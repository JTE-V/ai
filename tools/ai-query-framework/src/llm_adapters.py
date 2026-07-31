"""
LLM 适配器层 — Large Language Model Adapters
==============================================
提供多种大语言模型后端的统一适配接口。
所有适配器继承自 BaseAdapter，遵循相同的生命周期：
  initialize() → execute() → health_check() → shutdown()

适配器列表：
  1. BaseAdapter       — 抽象基类，定义统一接口契约
  2. OpenAIAdapter     — 适配 OpenAI GPT-4 / GPT-4o
  3. LocalLLMAdapter   — 适配本地模型（llama.cpp / Ollama / vLLM）
  4. ClaudeAdapter     — 适配 Anthropic Claude 系列
  5. MockAdapter       — 模拟适配器，用于测试和降级
  6. HarmonyAdapter    — 适配鸿蒙端侧 AI 模型（待实现）

类比：
  - Go 的 io.Reader / io.Writer 接口：统一抽象，多种实现
  - JDBC Driver：同一套接口，切换不同的数据库驱动
  - Node.js 的 Passport.js 认证策略：Strategy 模式
  - Python 的 logging.Handler：统一接口，不同后端（文件 / syslog / HTTP）

设计原则：
  - 依赖倒置（DIP）：上层依赖 BaseAdapter 抽象，不依赖具体实现
  - 开闭原则（OCP）：新增适配器无需修改已有代码
  - 单一职责（SRP）：每个适配器只负责与一种 LLM 后端交互
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import platform
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# 可选依赖：openai / anthropic SDK（若未安装则标记不可用并降级）
# ---------------------------------------------------------------------------
try:
    import openai  # type: ignore[import-untyped]
    _HAS_OPENAI = True
except ImportError:  # pragma: no cover
    openai = None  # type: ignore[assignment]
    _HAS_OPENAI = False

try:
    import anthropic  # type: ignore[import-untyped]
    _HAS_ANTHROPIC = True
except ImportError:  # pragma: no cover
    anthropic = None  # type: ignore[assignment]
    _HAS_ANTHROPIC = False

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ============================================================================
# 1. 适配器状态枚举
# ============================================================================

class AdapterState(Enum):
    """
    适配器生命周期状态。

    状态转换图：
      UNINITIALIZED ──initialize()──▶ INITIALIZED ──execute()──▶ RUNNING
           ▲                              │                        │
           │                              ▼                        ▼
           ◀──────── shutdown() ──── STOPPED ◀─── health_check() ──┘
           ◀──────── on_error() ──── ERROR
    """
    UNINITIALIZED = "uninitialized"   # 尚未初始化
    INITIALIZED = "initialized"       # 已初始化，等待执行
    RUNNING = "running"               # 正在执行查询
    STOPPED = "stopped"               # 已停止（正常关闭）
    ERROR = "error"                   # 错误状态


# ============================================================================
# 2. 适配器配置与响应数据类
# ============================================================================

@dataclass
class AdapterConfig:
    """
    适配器通用配置。

    字段说明：
      adapter_id   : 适配器唯一标识（用于日志和监控）
      timeout      : 请求超时时间（秒），默认 30
      max_retries  : 最大重试次数
      stream       : 是否启用流式输出
      extra        : 扩展配置（传递给具体适配器的额外参数）

    JS 类比：
      interface AdapterConfig {
        adapterId: string;
        timeout: number;
        maxRetries: number;
        stream: boolean;
        extra: Record<string, any>;
      }
    """
    adapter_id: str = ""
    timeout: float = 30.0
    max_retries: int = 3
    stream: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AdapterResponse:
    """
    适配器统一响应格式 — 所有适配器的 execute() 都返回此结构。

    字段说明：
      content    : LLM 返回的文本内容
      model      : 实际使用的模型名称
      usage      : token 用量统计（prompt_tokens, completion_tokens, total_tokens）
      latency_ms : 端到端耗时（毫秒）
      finish_reason : 完成原因（stop / length / content_filter / error）
      metadata   : 扩展元数据（如 API 请求 ID、缓存命中标记等）

    JS 类比：
      type AdapterResponse = {
        content: string;
        model: string;
        usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
        latencyMs: number;
        finishReason: 'stop' | 'length' | 'content_filter' | 'error';
        metadata: Record<string, any>;
      };
    """
    content: str = ""
    model: str = ""
    usage: Dict[str, int] = field(default_factory=lambda: {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
    })
    latency_ms: float = 0.0
    finish_reason: str = "stop"
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# 3. BaseAdapter — 抽象基类
# ============================================================================

class BaseAdapter(ABC):
    """
    所有适配器的抽象基类 — 定义统一的接口契约。

    子类必须实现：
      - _do_initialize()      : 实际的初始化逻辑
      - _do_execute()         : 实际的执行逻辑
      - _do_health_check()    : 实际的健康检查逻辑
      - _do_shutdown()        : 实际的关闭逻辑

    框架方法（已实现，子类不应覆盖）：
      - initialize()  → 记录状态 + 调用 _do_initialize()
      - execute()     → 计时 + 调用 _do_execute() + 统一响应
      - health_check()→ 调用 _do_health_check() + 状态更新
      - shutdown()    → 调用 _do_shutdown() + 状态更新

    类比：
      - Python 的 collections.abc.MutableMapping 作为 dict 的抽象基类
      - Go 的 io.ReadWriteCloser 组合接口
      - Java 的 java.sql.Connection 接口
    """

    def __init__(self, config: Optional[AdapterConfig] = None):
        """
        初始化适配器实例。

        参数：
          config : 适配器配置；若未提供则使用默认配置
        """
        self.config = config or AdapterConfig()
        self._state = AdapterState.UNINITIALIZED
        self._state_lock = threading.Lock()  # 状态变更锁，保证线程安全
        self._init_time: Optional[float] = None

    # ------------------------------------------------------------------
    # 状态属性（只读）
    # ------------------------------------------------------------------

    @property
    def state(self) -> AdapterState:
        """当前适配器状态（线程安全）"""
        with self._state_lock:
            return self._state

    @state.setter
    def state(self, new_state: AdapterState) -> None:
        """设置状态并记录日志（线程安全）"""
        with self._state_lock:
            old_state = self._state
            self._state = new_state
            logger.info(
                "[%s] 状态变更: %s → %s",
                self.config.adapter_id or self.__class__.__name__,
                old_state.value,
                new_state.value,
            )

    # ------------------------------------------------------------------
    # 生命周期方法（框架方法 — 子类不应覆盖）
    # ------------------------------------------------------------------

    def initialize(self) -> bool:
        """
        初始化适配器。设置初始状态，执行连接/鉴权/资源分配等。

        返回：
          True 表示初始化成功，False 表示失败

        调用约定：
          - 只能从 UNINITIALIZED 或 ERROR 状态调用
          - 成功后状态变为 INITIALIZED
          - 失败后状态变为 ERROR

        类比：
          - AWS SDK 的 client.init() / boto3.client()
          - Django 的 AppConfig.ready()
          - React 的 componentDidMount()
        """
        if self.state not in (AdapterState.UNINITIALIZED, AdapterState.ERROR):
            logger.warning(
                "[%s] 适配器已初始化，跳过重复初始化 (当前状态: %s)",
                self.config.adapter_id or self.__class__.__name__,
                self.state.value,
            )
            return True

        logger.info(
            "[%s] 开始初始化适配器...",
            self.config.adapter_id or self.__class__.__name__,
        )
        self._init_time = time.time()

        try:
            success = self._do_initialize()
            if success:
                self.state = AdapterState.INITIALIZED
                elapsed = (time.time() - self._init_time) * 1000
                logger.info(
                    "[%s] 初始化完成 (耗时 %.1f ms)",
                    self.config.adapter_id or self.__class__.__name__,
                    elapsed,
                )
            else:
                self.state = AdapterState.ERROR
                logger.error(
                    "[%s] 初始化失败",
                    self.config.adapter_id or self.__class__.__name__,
                )
            return success
        except Exception as exc:
            self.state = AdapterState.ERROR
            logger.exception(
                "[%s] 初始化异常: %s",
                self.config.adapter_id or self.__class__.__name__,
                exc,
            )
            return False

    def execute(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        messages: Optional[List[Dict[str, str]]] = None,
        **kwargs: Any,
    ) -> AdapterResponse:
        """
        执行一次 LLM 查询。

        参数：
          prompt        : 用户提示词（必需）
          system_prompt : 系统提示词（可选，用于设定 AI 角色/行为）
          messages      : 完整对话历史（可选，格式: [{"role":"user","content":"..."}]）
          **kwargs      : 传递给具体适配器的额外参数（如 temperature, max_tokens 等）

        返回：
          AdapterResponse 统一响应对象

        调用约定：
          - 只能从 INITIALIZED 或 RUNNING 状态调用
          - 执行期间状态变为 RUNNING
          - 执行完毕后状态回到 INITIALIZED（正常）或 ERROR（异常）

        类比：
          - OpenAI Python SDK 的 client.chat.completions.create()
          - LangChain 的 llm.invoke()
          - Express.js 的 res.send() — 统一出口
        """
        if self.state not in (AdapterState.INITIALIZED, AdapterState.RUNNING):
            raise RuntimeError(
                f"[{self.config.adapter_id}] 适配器未初始化，"
                f"无法执行 (当前状态: {self.state.value})"
            )

        self.state = AdapterState.RUNNING
        start_time = time.time()

        # 如果未传入 messages，则用 prompt 构建默认的 messages 列表
        if messages is None:
            messages = self._build_messages(prompt, system_prompt)

        for attempt in range(1, self.config.max_retries + 1):
            try:
                response = self._do_execute(messages, **kwargs)
                response.latency_ms = (time.time() - start_time) * 1000
                self.state = AdapterState.INITIALIZED
                logger.info(
                    "[%s] 查询完成 (耗时 %.1f ms, tokens: %s)",
                    self.config.adapter_id or self.__class__.__name__,
                    response.latency_ms,
                    response.usage.get("total_tokens", "N/A"),
                )
                return response
            except Exception as exc:
                logger.warning(
                    "[%s] 第 %d/%d 次尝试失败: %s",
                    self.config.adapter_id or self.__class__.__name__,
                    attempt,
                    self.config.max_retries,
                    exc,
                )
                if attempt == self.config.max_retries:
                    self.state = AdapterState.ERROR
                    return AdapterResponse(
                        content=f"执行失败（已重试 {self.config.max_retries} 次）: {exc}",
                        finish_reason="error",
                        latency_ms=(time.time() - start_time) * 1000,
                        metadata={"error": str(exc), "attempts": attempt},
                    )
                # 指数退避重试
                time.sleep(min(2 ** attempt, self.config.timeout / 2))

        # 逻辑上不可达（作为安全兜底）
        self.state = AdapterState.ERROR
        return AdapterResponse(
            content="未知错误",
            finish_reason="error",
            latency_ms=(time.time() - start_time) * 1000,
        )

    def health_check(self) -> bool:
        """
        执行健康检查。

        返回：
          True 表示健康，False 表示不健康

        类比：
          - Kubernetes 的 livenessProbe / readinessProbe
          - Spring Boot Actuator 的 /health 端点
          - AWS ELB 的 health check
        """
        try:
            healthy = self._do_health_check()
            if not healthy:
                logger.warning(
                    "[%s] 健康检查未通过",
                    self.config.adapter_id or self.__class__.__name__,
                )
            return healthy
        except Exception as exc:
            logger.exception(
                "[%s] 健康检查异常: %s",
                self.config.adapter_id or self.__class__.__name__,
                exc,
            )
            return False

    def shutdown(self) -> bool:
        """
        关闭适配器，释放所有资源（连接、显存、文件句柄等）。

        返回：
          True 表示关闭成功

        类比：
          - Python 的 contextlib.closing() / __exit__()
          - Go 的 defer conn.Close()
          - Node.js 的 server.close()
        """
        logger.info(
            "[%s] 开始关闭适配器...",
            self.config.adapter_id or self.__class__.__name__,
        )
        try:
            self._do_shutdown()
            self.state = AdapterState.STOPPED
            logger.info(
                "[%s] 已关闭",
                self.config.adapter_id or self.__class__.__name__,
            )
            return True
        except Exception as exc:
            self.state = AdapterState.ERROR
            logger.exception(
                "[%s] 关闭时发生异常: %s",
                self.config.adapter_id or self.__class__.__name__,
                exc,
            )
            return False

    # ------------------------------------------------------------------
    # 抽象方法（子类必须实现）
    # ------------------------------------------------------------------

    @abstractmethod
    def _do_initialize(self) -> bool:
        """执行实际的初始化逻辑。子类必须实现。"""
        ...

    @abstractmethod
    def _do_execute(self, messages: List[Dict[str, str]], **kwargs: Any) -> AdapterResponse:
        """执行实际的查询逻辑。子类必须实现。"""
        ...

    @abstractmethod
    def _do_health_check(self) -> bool:
        """执行实际的健康检查逻辑。子类必须实现。"""
        ...

    @abstractmethod
    def _do_shutdown(self) -> None:
        """执行实际的关闭/清理逻辑。子类必须实现。"""
        ...

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    @staticmethod
    def _build_messages(
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """
        根据 prompt 和 system_prompt 构建标准 messages 列表。

        参数：
          prompt        : 用户提示词
          system_prompt : 系统提示词（可选）

        返回：
          [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}]
        """
        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return messages


# ============================================================================
# 4. OpenAIAdapter — 适配 OpenAI GPT-4 / GPT-4o
# ============================================================================

class OpenAIAdapter(BaseAdapter):
    """
    适配 OpenAI GPT-4 / GPT-4o 系列模型。

    特性：
      - 支持 API Key / Azure AD 鉴权
      - 支持流式输出（SSE）和非流式输出
      - 支持 temperature / top_p / max_tokens 等标准参数
      - 支持自定义 API Base URL（适用于代理或 Azure OpenAI）

    配置项（通过 AdapterConfig.extra 传递）：
      api_key        : OpenAI API Key（优先使用环境变量 OPENAI_API_KEY）
      api_base       : 自定义 API 基础 URL
      model          : 模型名称（默认 gpt-4o）
      organization   : OpenAI 组织 ID（可选）

    类比：
      - OpenAI Python SDK 的 openai.OpenAI()
      - LangChain 的 ChatOpenAI
      - Azure OpenAI Service 的 Endpoint
    """

    # 已知的有效模型前缀（用于健康检查时验证连通性）
    _KNOWN_MODEL_PREFIXES = ("gpt-", "o1-", "o3-", "o4-")

    def __init__(self, config: Optional[AdapterConfig] = None):
        """初始化 OpenAI 适配器。"""
        super().__init__(config)
        self._client: Optional[Any] = None  # openai.OpenAI 客户端实例
        self._model_name: str = ""

    # ------------------------------------------------------------------
    # _do_initialize
    # ------------------------------------------------------------------

    def _do_initialize(self) -> bool:
        """
        初始化 OpenAI 客户端。

        步骤：
          1. 读取 API Key（优先 AdapterConfig.extra，其次环境变量 OPENAI_API_KEY）
          2. 构建 openai.OpenAI 客户端
          3. 验证模型名称

        返回：
          True 表示初始化成功
        """
        if not _HAS_OPENAI:
            logger.error("OpenAI SDK 未安装，请执行: pip install openai")
            return False

        # 1) 读取 API Key
        api_key = (
            self.config.extra.get("api_key")
            or os.environ.get("OPENAI_API_KEY")
            or ""
        )
        if not api_key:
            logger.error(
                "[%s] 未提供 API Key。"
                "请在 AdapterConfig.extra['api_key'] 或环境变量 OPENAI_API_KEY 中设置",
                self.config.adapter_id,
            )
            return False

        # 2) 读取可选配置
        api_base = self.config.extra.get("api_base", None)
        organization = self.config.extra.get("organization", None)
        self._model_name = self.config.extra.get("model", "gpt-4o")

        # 3) 构建客户端
        client_kwargs: Dict[str, Any] = {"api_key": api_key}
        if api_base:
            client_kwargs["base_url"] = api_base
        if organization:
            client_kwargs["organization"] = organization

        try:
            self._client = openai.OpenAI(**client_kwargs)  # type: ignore[union-attr]
            logger.info(
                "[%s] OpenAI 客户端已创建 (model=%s, base_url=%s)",
                self.config.adapter_id,
                self._model_name,
                api_base or "https://api.openai.com/v1",
            )
            return True
        except Exception as exc:
            logger.exception("[%s] 创建 OpenAI 客户端失败: %s", self.config.adapter_id, exc)
            return False

    # ------------------------------------------------------------------
    # _do_execute
    # ------------------------------------------------------------------

    def _do_execute(self, messages: List[Dict[str, str]], **kwargs: Any) -> AdapterResponse:
        """
        调用 OpenAI Chat Completions API。

        参数：
          messages : 标准对话消息列表
          **kwargs : 传递给 API 的额外参数（temperature, max_tokens, top_p 等）

        返回：
          AdapterResponse

        流式模式处理：
          当 self.config.stream=True 时，收集所有流式 chunk 拼接为完整响应。
        """
        if self._client is None:
            return AdapterResponse(
                content="OpenAI 客户端未初始化",
                finish_reason="error",
                metadata={"error": "client_not_initialized"},
            )

        # 合并默认参数
        request_kwargs: Dict[str, Any] = {
            "model": self._model_name,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 4096),
            "top_p": kwargs.get("top_p", 1.0),
            "stream": self.config.stream,
        }
        # 允许调用方覆盖任何参数
        request_kwargs.update({k: v for k, v in kwargs.items() if k not in ("temperature", "max_tokens", "top_p")})

        try:
            if self.config.stream:
                # === 流式模式 ===
                # 汇总所有 SSE chunk，拼接成完整响应
                stream = self._client.chat.completions.create(**request_kwargs)  # type: ignore[union-attr]
                collected_content: List[str] = []
                usage_dict: Dict[str, int] = {}
                finish = "stop"

                for chunk in stream:
                    if chunk.choices and len(chunk.choices) > 0:
                        delta = chunk.choices[0].delta
                        if delta and delta.content:
                            collected_content.append(delta.content)
                        if chunk.choices[0].finish_reason:
                            finish = chunk.choices[0].finish_reason
                    # 某些流式实现在最后一条 chunk 中携带 usage
                    if hasattr(chunk, "usage") and chunk.usage:
                        usage_dict = {
                            "prompt_tokens": chunk.usage.prompt_tokens or 0,
                            "completion_tokens": chunk.usage.completion_tokens or 0,
                            "total_tokens": chunk.usage.total_tokens or 0,
                        }

                return AdapterResponse(
                    content="".join(collected_content),
                    model=self._model_name,
                    usage=usage_dict,
                    finish_reason=finish or "stop",
                )
            else:
                # === 非流式模式 ===
                completion = self._client.chat.completions.create(**request_kwargs)  # type: ignore[union-attr]
                choice = completion.choices[0]
                return AdapterResponse(
                    content=choice.message.content or "",
                    model=completion.model or self._model_name,
                    usage={
                        "prompt_tokens": completion.usage.prompt_tokens if completion.usage else 0,
                        "completion_tokens": completion.usage.completion_tokens if completion.usage else 0,
                        "total_tokens": completion.usage.total_tokens if completion.usage else 0,
                    },
                    finish_reason=choice.finish_reason or "stop",
                    metadata={
                        "id": completion.id if hasattr(completion, "id") else "",
                        "created": completion.created if hasattr(completion, "created") else 0,
                    },
                )
        except openai.APIError as exc:  # type: ignore[union-attr]
            logger.error("[%s] OpenAI API 错误: %s", self.config.adapter_id, exc)
            raise
        except Exception as exc:
            logger.exception("[%s] 执行查询异常: %s", self.config.adapter_id, exc)
            raise

    # ------------------------------------------------------------------
    # _do_health_check
    # ------------------------------------------------------------------

    def _do_health_check(self) -> bool:
        """
        健康检查：发送一条极简请求验证 API 连通性。

        检查策略：
          1. 验证客户端是否已创建
          2. 验证模型名称是否有有效前缀
          3. 发送一条 max_tokens=1 的最小化请求测试连通性

        返回：
          True 表示 API 可达且模型可用
        """
        if self._client is None:
            logger.warning("[%s] 健康检查失败: 客户端未创建", self.config.adapter_id)
            return False

        if not any(self._model_name.startswith(p) for p in self._KNOWN_MODEL_PREFIXES):
            logger.warning(
                "[%s] 健康检查警告: 模型名称 %s 不是已知的 OpenAI 前缀",
                self.config.adapter_id,
                self._model_name,
            )

        try:
            # 发送最小化请求（1 token），仅验证连通性
            test_messages = [{"role": "user", "content": "hi"}]
            completion = self._client.chat.completions.create(  # type: ignore[union-attr]
                model=self._model_name,
                messages=test_messages,
                max_tokens=1,
                temperature=0,
            )
            # 只要能返回 choice 就认为健康
            if completion.choices and len(completion.choices) > 0:
                logger.info(
                    "[%s] 健康检查通过 (model=%s)",
                    self.config.adapter_id,
                    self._model_name,
                )
                return True
            return False
        except openai.APIError as exc:  # type: ignore[union-attr]
            logger.warning(
                "[%s] 健康检查失败 (API 错误): %s",
                self.config.adapter_id,
                exc,
            )
            return False
        except Exception as exc:
            logger.warning(
                "[%s] 健康检查失败 (网络/其他): %s",
                self.config.adapter_id,
                exc,
            )
            return False

    # ------------------------------------------------------------------
    # _do_shutdown
    # ------------------------------------------------------------------

    def _do_shutdown(self) -> None:
        """
        关闭 OpenAI 客户端连接。

        OpenAI SDK 使用 httpx，默认连接池会在对象析构时自动关闭。
        这里显式调用 close() 确保资源立即释放。
        """
        if self._client is not None:
            try:
                self._client.close()  # type: ignore[union-attr]
                logger.info("[%s] OpenAI 客户端已关闭", self.config.adapter_id)
            except Exception as exc:
                logger.warning("[%s] 关闭 OpenAI 客户端时出错: %s", self.config.adapter_id, exc)
            finally:
                self._client = None


# ============================================================================
# 5. LocalLLMAdapter — 适配本地模型
# ============================================================================

class LocalLLMAdapter(BaseAdapter):
    """
    适配本地部署的大语言模型。

    支持后端：
      - llama.cpp   : 通过 llama-cpp-python 绑定
      - Ollama      : 通过 Ollama REST API（默认 http://localhost:11434）
      - vLLM        : 通过 vLLM OpenAI 兼容 API

    配置项（通过 AdapterConfig.extra 传递）：
      backend      : 后端类型 — "llama_cpp" | "ollama" | "vllm"（默认 "ollama"）
      model_path   : 模型文件路径（llama_cpp 必需）
      model_name   : 模型名称（ollama / vLLM 使用）
      api_base     : API 基础 URL（ollama 默认 http://localhost:11434；vLLM 默认 http://localhost:8000/v1）
      n_gpu_layers : GPU 加速层数（llama_cpp 使用，-1 表示全部 GPU）
      n_ctx        : 上下文窗口大小（默认 4096）
      use_gpu      : 是否使用 GPU（仅 ollama / vLLM 判断用）

    类比：
      - Ollama 的 `ollama run`
      - llama-cpp-python 的 `Llama(model_path)`
      - vLLM 的 OpenAI-compatible server
    """

    _VALID_BACKENDS = ("llama_cpp", "ollama", "vllm")

    def __init__(self, config: Optional[AdapterConfig] = None):
        """初始化本地 LLM 适配器。"""
        super().__init__(config)
        self._client: Optional[Any] = None       # llama-cpp Llama 实例 或 ollama Client
        self._backend: str = ""                   # 当前后端类型
        self._model_loaded: bool = False          # 模型是否已加载到内存/显存
        self._use_gpu: bool = False               # 是否使用 GPU

    # ------------------------------------------------------------------
    # _do_initialize
    # ------------------------------------------------------------------

    def _do_initialize(self) -> bool:
        """
        初始化本地 LLM 后端。

        步骤：
          1. 确定后端类型
          2. 根据后端类型加载模型或建立连接
          3. 记录设备信息（GPU/CPU）

        返回：
          True 表示初始化成功
        """
        self._backend = self.config.extra.get("backend", "ollama")
        self._use_gpu = self.config.extra.get("use_gpu", False)

        if self._backend not in self._VALID_BACKENDS:
            logger.error(
                "[%s] 无效的后端类型: %s。支持: %s",
                self.config.adapter_id,
                self._backend,
                self._VALID_BACKENDS,
            )
            return False

        logger.info(
            "[%s] 初始化本地 LLM (backend=%s, use_gpu=%s)",
            self.config.adapter_id,
            self._backend,
            self._use_gpu,
        )

        # 根据后端类型分支处理
        if self._backend == "llama_cpp":
            return self._init_llama_cpp()
        elif self._backend == "ollama":
            return self._init_ollama()
        elif self._backend == "vllm":
            return self._init_vllm()
        else:
            return False  # 理论不可达

    def _init_llama_cpp(self) -> bool:
        """
        初始化 llama.cpp 后端。

        需要安装: pip install llama-cpp-python
        GPU 加速需编译时指定 CUDA/Metal 支持。
        """
        model_path = self.config.extra.get("model_path", "")
        if not model_path or not os.path.isfile(model_path):
            logger.error(
                "[%s] 模型文件不存在: %s",
                self.config.adapter_id,
                model_path,
            )
            return False

        n_gpu_layers = self.config.extra.get("n_gpu_layers", 0)
        if self._use_gpu:
            n_gpu_layers = self.config.extra.get("n_gpu_layers", -1)  # -1 = 全部 GPU

        n_ctx = self.config.extra.get("n_ctx", 4096)

        try:
            # 动态导入 llama-cpp-python（避免硬依赖）
            from llama_cpp import Llama  # type: ignore[import-untyped]

            self._client = Llama(
                model_path=model_path,
                n_ctx=n_ctx,
                n_gpu_layers=n_gpu_layers,
                verbose=False,
            )
            self._model_loaded = True
            logger.info(
                "[%s] llama.cpp 模型已加载 (path=%s, n_gpu_layers=%d, n_ctx=%d)",
                self.config.adapter_id,
                model_path,
                n_gpu_layers,
                n_ctx,
            )
            return True
        except ImportError:
            logger.error(
                "[%s] llama-cpp-python 未安装。请执行: pip install llama-cpp-python",
                self.config.adapter_id,
            )
            return False
        except Exception as exc:
            logger.exception("[%s] 加载 llama.cpp 模型失败: %s", self.config.adapter_id, exc)
            return False

    def _init_ollama(self) -> bool:
        """
        初始化 Ollama 后端。

        Ollama 默认在 http://localhost:11434 提供 REST API。
        通过 OpenAI 兼容的 /v1 端点访问。
        """
        api_base = self.config.extra.get("api_base", "http://localhost:11434/v1")
        model_name = self.config.extra.get("model_name", "llama3")

        if not _HAS_OPENAI:
            logger.error(
                "[%s] Ollama 后端依赖 openai SDK（兼容接口），但 openai 未安装。"
                "请执行: pip install openai",
                self.config.adapter_id,
            )
            return False

        try:
            self._client = openai.OpenAI(  # type: ignore[union-attr]
                base_url=api_base,
                api_key="ollama",  # Ollama 不需要真实 key，但不能为空
            )
            self._model_loaded = True  # Ollama 按需拉取模型，此处标记为就绪
            logger.info(
                "[%s] Ollama 客户端已创建 (api_base=%s, model=%s)",
                self.config.adapter_id,
                api_base,
                model_name,
            )
            return True
        except Exception as exc:
            logger.exception("[%s] 创建 Ollama 客户端失败: %s", self.config.adapter_id, exc)
            return False

    def _init_vllm(self) -> bool:
        """
        初始化 vLLM 后端。

        vLLM 提供 OpenAI 兼容 API，默认 http://localhost:8000/v1。
        """
        api_base = self.config.extra.get("api_base", "http://localhost:8000/v1")
        model_name = self.config.extra.get("model_name", "")

        if not _HAS_OPENAI:
            logger.error(
                "[%s] vLLM 后端依赖 openai SDK（兼容接口），但 openai 未安装。"
                "请执行: pip install openai",
                self.config.adapter_id,
            )
            return False

        try:
            self._client = openai.OpenAI(  # type: ignore[union-attr]
                base_url=api_base,
                api_key="vllm",  # vLLM 默认不需要认证
            )
            # 如果未指定 model_name，尝试列出可用模型
            if not model_name:
                try:
                    models = self._client.models.list()  # type: ignore[union-attr]
                    if models.data:
                        model_name = models.data[0].id
                        self.config.extra["model_name"] = model_name
                        logger.info(
                            "[%s] 自动选择 vLLM 模型: %s",
                            self.config.adapter_id,
                            model_name,
                        )
                except Exception:
                    logger.warning(
                        "[%s] 无法列出 vLLM 模型，将使用配置中的 model_name",
                        self.config.adapter_id,
                    )

            self._model_loaded = True
            logger.info(
                "[%s] vLLM 客户端已创建 (api_base=%s, model=%s)",
                self.config.adapter_id,
                api_base,
                model_name or "(待定)",
            )
            return True
        except Exception as exc:
            logger.exception("[%s] 创建 vLLM 客户端失败: %s", self.config.adapter_id, exc)
            return False

    # ------------------------------------------------------------------
    # _do_execute
    # ------------------------------------------------------------------

    def _do_execute(self, messages: List[Dict[str, str]], **kwargs: Any) -> AdapterResponse:
        """
        调用本地 LLM 执行推理。

        根据 self._backend 分支到不同的实现。
        """
        if self._backend == "llama_cpp":
            return self._execute_llama_cpp(messages, **kwargs)
        elif self._backend in ("ollama", "vllm"):
            return self._execute_openai_compat(messages, **kwargs)
        else:
            return AdapterResponse(
                content=f"不支持的后端类型: {self._backend}",
                finish_reason="error",
            )

    def _execute_llama_cpp(self, messages: List[Dict[str, str]], **kwargs: Any) -> AdapterResponse:
        """
        使用 llama-cpp-python 执行推理。

        注意：llama.cpp 的 Python 绑定使用原始 create_completion 接口。
        将 messages 展平为单个 prompt 字符串。
        """
        if self._client is None:
            return AdapterResponse(
                content="llama.cpp 模型未加载",
                finish_reason="error",
                metadata={"error": "model_not_loaded"},
            )

        # 将对话消息拼接为一个 prompt 字符串
        prompt = self._messages_to_prompt(messages)

        try:
            result = self._client(
                prompt,
                max_tokens=kwargs.get("max_tokens", 512),
                temperature=kwargs.get("temperature", 0.7),
                top_p=kwargs.get("top_p", 1.0),
                stop=kwargs.get("stop", None),
                echo=False,
            )
            content = ""
            usage: Dict[str, int] = {}
            if isinstance(result, dict):
                content = result.get("choices", [{}])[0].get("text", "")
                usage = {
                    "prompt_tokens": result.get("usage", {}).get("prompt_tokens", 0),
                    "completion_tokens": result.get("usage", {}).get("completion_tokens", 0),
                    "total_tokens": result.get("usage", {}).get("total_tokens", 0),
                }
            return AdapterResponse(
                content=content.strip(),
                model=os.path.basename(self.config.extra.get("model_path", "local")),
                usage=usage,
                finish_reason="stop",
            )
        except Exception as exc:
            logger.exception("[%s] llama.cpp 推理失败: %s", self.config.adapter_id, exc)
            raise

    def _execute_openai_compat(self, messages: List[Dict[str, str]], **kwargs: Any) -> AdapterResponse:
        """
        使用 OpenAI 兼容接口执行推理（Ollama / vLLM）。
        """
        if self._client is None:
            return AdapterResponse(
                content=f"{self._backend} 客户端未初始化",
                finish_reason="error",
                metadata={"error": "client_not_initialized"},
            )

        model_name = self.config.extra.get("model_name", "")

        try:
            completion = self._client.chat.completions.create(  # type: ignore[union-attr]
                model=model_name,
                messages=messages,
                temperature=kwargs.get("temperature", 0.7),
                max_tokens=kwargs.get("max_tokens", 512),
            )
            choice = completion.choices[0]
            return AdapterResponse(
                content=choice.message.content or "",
                model=completion.model or model_name,
                usage={
                    "prompt_tokens": completion.usage.prompt_tokens if completion.usage else 0,
                    "completion_tokens": completion.usage.completion_tokens if completion.usage else 0,
                    "total_tokens": completion.usage.total_tokens if completion.usage else 0,
                },
                finish_reason=choice.finish_reason or "stop",
            )
        except Exception as exc:
            logger.exception("[%s] %s 推理失败: %s", self.config.adapter_id, self._backend, exc)
            raise

    # ------------------------------------------------------------------
    # _do_health_check
    # ------------------------------------------------------------------

    def _do_health_check(self) -> bool:
        """
        健康检查本地 LLM。

        检查策略：
          - llama_cpp: 检查模型是否已加载，并发送一条最小请求
          - ollama:    通过 /api/tags 端点检查服务是否可达
          - vLLM:      通过 /v1/models 端点检查服务是否可达
        """
        if self._backend == "llama_cpp":
            if self._client is None:
                logger.warning("[%s] 健康检查失败: llama.cpp 模型未加载", self.config.adapter_id)
                return False
            try:
                # 发送一条极短 prompt 测试
                test_result = self._client("Hello", max_tokens=1)
                if isinstance(test_result, dict) and "choices" in test_result:
                    logger.info("[%s] llama.cpp 健康检查通过", self.config.adapter_id)
                    return True
                return False
            except Exception as exc:
                logger.warning("[%s] llama.cpp 健康检查失败: %s", self.config.adapter_id, exc)
                return False

        elif self._backend in ("ollama", "vllm"):
            if self._client is None:
                logger.warning("[%s] 健康检查失败: 客户端未创建", self.config.adapter_id)
                return False
            try:
                # 通过列出模型来验证连通性
                models = self._client.models.list()  # type: ignore[union-attr]
                if models.data:
                    logger.info(
                        "[%s] %s 健康检查通过 (可用模型: %d)",
                        self.config.adapter_id,
                        self._backend,
                        len(models.data),
                    )
                    return True
                return False
            except Exception as exc:
                logger.warning(
                    "[%s] %s 健康检查失败: %s",
                    self.config.adapter_id,
                    self._backend,
                    exc,
                )
                return False

        return False

    # ------------------------------------------------------------------
    # _do_shutdown
    # ------------------------------------------------------------------

    def _do_shutdown(self) -> None:
        """
        关闭本地 LLM 并释放资源。

        llama.cpp 需要显式释放模型占用的显存/内存。
        Ollama / vLLM 客户端关闭 HTTP 连接池即可。
        """
        if self._backend == "llama_cpp":
            if self._client is not None:
                try:
                    # llama-cpp-python 的 Llama 对象支持 close() 或上下文管理器
                    if hasattr(self._client, "close"):
                        self._client.close()
                    elif hasattr(self._client, "__del__"):
                        del self._client
                    logger.info("[%s] llama.cpp 模型已卸载", self.config.adapter_id)
                except Exception as exc:
                    logger.warning(
                        "[%s] 卸载 llama.cpp 模型时出错: %s",
                        self.config.adapter_id,
                        exc,
                    )
                finally:
                    self._client = None
                    self._model_loaded = False
        else:
            # Ollama / vLLM 基于 OpenAI SDK，调用 close 即可
            if self._client is not None:
                try:
                    self._client.close()  # type: ignore[union-attr]
                    logger.info(
                        "[%s] %s 客户端已关闭",
                        self.config.adapter_id,
                        self._backend,
                    )
                except Exception as exc:
                    logger.warning(
                        "[%s] 关闭 %s 客户端时出错: %s",
                        self.config.adapter_id,
                        self._backend,
                        exc,
                    )
                finally:
                    self._client = None
                    self._model_loaded = False

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    @staticmethod
    def _messages_to_prompt(messages: List[Dict[str, str]]) -> str:
        """
        将对话 messages 列表转换为单个 prompt 字符串（for llama.cpp）。

        转换规则：
          system 消息用 [INST]<<SYS>>...<</SYS>> 包裹
          user 消息用 [INST]...[/INST] 包裹
          assistant 消息直接拼接

        返回：
          格式化后的 prompt 字符串
        """
        parts: List[str] = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                parts.append(f"<<SYS>>\n{content}\n<</SYS>>")
            elif role == "user":
                parts.append(f"[INST] {content} [/INST]")
            elif role == "assistant":
                parts.append(content)
            else:
                parts.append(content)
        return "\n".join(parts)


# ============================================================================
# 6. ClaudeAdapter — 适配 Anthropic Claude
# ============================================================================

class ClaudeAdapter(BaseAdapter):
    """
    适配 Anthropic Claude 系列模型（Claude 3 / 3.5 / 4）。

    特性：
      - 支持 Anthropic API Key 鉴权
      - 支持流式输出（SSE）
      - 支持 system prompt 独立字段（Anthropic 特有）
      - 支持扩展思考（extended thinking，Claude 3.5+特性）

    配置项（通过 AdapterConfig.extra 传递）：
      api_key    : Anthropic API Key（优先使用环境变量 ANTHROPIC_API_KEY）
      model      : 模型名称（默认 claude-sonnet-4-20250514）
      max_tokens : 最大输出 token 数（默认 4096，Anthropic 必需参数）

    类比：
      - Anthropic Python SDK 的 anthropic.Anthropic()
      - Anthropic Messages API
      - AWS Bedrock 上的 Claude（通过不同 endpoint）
    """

    def __init__(self, config: Optional[AdapterConfig] = None):
        """初始化 Claude 适配器。"""
        super().__init__(config)
        self._client: Optional[Any] = None  # anthropic.Anthropic 客户端实例
        self._model_name: str = ""

    # ------------------------------------------------------------------
    # _do_initialize
    # ------------------------------------------------------------------

    def _do_initialize(self) -> bool:
        """
        初始化 Anthropic Claude 客户端。

        步骤：
          1. 读取 API Key
          2. 构建 anthropic.Anthropic 客户端
          3. 验证模型名称

        返回：
          True 表示初始化成功
        """
        if not _HAS_ANTHROPIC:
            logger.error("Anthropic SDK 未安装，请执行: pip install anthropic")
            return False

        api_key = (
            self.config.extra.get("api_key")
            or os.environ.get("ANTHROPIC_API_KEY")
            or ""
        )
        if not api_key:
            logger.error(
                "[%s] 未提供 Anthropic API Key。"
                "请在 AdapterConfig.extra['api_key'] 或环境变量 ANTHROPIC_API_KEY 中设置",
                self.config.adapter_id,
            )
            return False

        self._model_name = self.config.extra.get("model", "claude-sonnet-4-20250514")

        try:
            self._client = anthropic.Anthropic(api_key=api_key)  # type: ignore[union-attr]
            logger.info(
                "[%s] Anthropic 客户端已创建 (model=%s)",
                self.config.adapter_id,
                self._model_name,
            )
            return True
        except Exception as exc:
            logger.exception("[%s] 创建 Anthropic 客户端失败: %s", self.config.adapter_id, exc)
            return False

    # ------------------------------------------------------------------
    # _do_execute
    # ------------------------------------------------------------------

    def _do_execute(self, messages: List[Dict[str, str]], **kwargs: Any) -> AdapterResponse:
        """
        调用 Anthropic Messages API。

        Anthropic API 与 OpenAI 的差异：
          - system prompt 是独立参数，不是 messages 中的一条
          - max_tokens 是必需参数
          - 角色使用 "user" / "assistant"（不支持 "system" 角色在 messages 中）
        """
        if self._client is None:
            return AdapterResponse(
                content="Anthropic 客户端未初始化",
                finish_reason="error",
                metadata={"error": "client_not_initialized"},
            )

        # 分离 system prompt
        system_prompt: Optional[str] = None
        api_messages: List[Dict[str, Any]] = []
        for msg in messages:
            if msg.get("role") == "system":
                system_prompt = msg.get("content", "")
            else:
                api_messages.append(msg)

        # 构建请求参数
        request_kwargs: Dict[str, Any] = {
            "model": self._model_name,
            "messages": api_messages,
            "max_tokens": kwargs.get("max_tokens", 4096),
            "temperature": kwargs.get("temperature", 0.7),
            "stream": self.config.stream,
        }
        if system_prompt:
            request_kwargs["system"] = system_prompt
        # 支持 top_p / top_k / stop_sequences 等 Anthropic 特有参数
        for key in ("top_p", "top_k", "stop_sequences", "thinking", "tool_choice", "tools"):
            if key in kwargs:
                request_kwargs[key] = kwargs[key]

        try:
            if self.config.stream:
                # === 流式模式 ===
                with self._client.messages.stream(**request_kwargs) as stream:  # type: ignore[union-attr]
                    collected_text = stream.get_final_text()
                    final_message = stream.get_final_message()
                    return AdapterResponse(
                        content=collected_text,
                        model=final_message.model,
                        usage={
                            "prompt_tokens": final_message.usage.input_tokens if final_message.usage else 0,
                            "completion_tokens": final_message.usage.output_tokens if final_message.usage else 0,
                            "total_tokens": (
                                final_message.usage.input_tokens + final_message.usage.output_tokens
                                if final_message.usage else 0
                            ),
                        },
                        finish_reason=final_message.stop_reason or "stop",
                        metadata={
                            "id": final_message.id if hasattr(final_message, "id") else "",
                        },
                    )
            else:
                # === 非流式模式 ===
                message = self._client.messages.create(**request_kwargs)  # type: ignore[union-attr]
                # Anthropic 返回的 content 是 list，通常第一个是 text block
                content = ""
                if message.content and len(message.content) > 0:
                    first_block = message.content[0]
                    if hasattr(first_block, "text"):
                        content = first_block.text
                    elif isinstance(first_block, dict):
                        content = first_block.get("text", "")
                return AdapterResponse(
                    content=content,
                    model=message.model,
                    usage={
                        "prompt_tokens": message.usage.input_tokens if message.usage else 0,
                        "completion_tokens": message.usage.output_tokens if message.usage else 0,
                        "total_tokens": (
                            message.usage.input_tokens + message.usage.output_tokens
                            if message.usage else 0
                        ),
                    },
                    finish_reason=message.stop_reason or "stop",
                    metadata={
                        "id": message.id if hasattr(message, "id") else "",
                    },
                )
        except anthropic.APIError as exc:  # type: ignore[union-attr]
            logger.error("[%s] Anthropic API 错误: %s", self.config.adapter_id, exc)
            raise
        except Exception as exc:
            logger.exception("[%s] 执行查询异常: %s", self.config.adapter_id, exc)
            raise

    # ------------------------------------------------------------------
    # _do_health_check
    # ------------------------------------------------------------------

    def _do_health_check(self) -> bool:
        """
        健康检查：发送一条极简请求验证 Anthropic API 连通性。

        返回：
          True 表示 API 可达
        """
        if self._client is None:
            logger.warning("[%s] 健康检查失败: 客户端未创建", self.config.adapter_id)
            return False

        try:
            # 发送 1 token 最小请求
            message = self._client.messages.create(  # type: ignore[union-attr]
                model=self._model_name,
                messages=[{"role": "user", "content": "Hi"}],
                max_tokens=1,
            )
            if message.content:
                logger.info(
                    "[%s] 健康检查通过 (model=%s)",
                    self.config.adapter_id,
                    self._model_name,
                )
                return True
            return False
        except anthropic.APIError as exc:  # type: ignore[union-attr]
            logger.warning(
                "[%s] 健康检查失败 (API 错误): %s",
                self.config.adapter_id,
                exc,
            )
            return False
        except Exception as exc:
            logger.warning(
                "[%s] 健康检查失败 (网络/其他): %s",
                self.config.adapter_id,
                exc,
            )
            return False

    # ------------------------------------------------------------------
    # _do_shutdown
    # ------------------------------------------------------------------

    def _do_shutdown(self) -> None:
        """关闭 Anthropic 客户端连接。"""
        if self._client is not None:
            try:
                self._client.close()  # type: ignore[union-attr]
                logger.info("[%s] Anthropic 客户端已关闭", self.config.adapter_id)
            except Exception as exc:
                logger.warning(
                    "[%s] 关闭 Anthropic 客户端时出错: %s",
                    self.config.adapter_id,
                    exc,
                )
            finally:
                self._client = None


# ============================================================================
# 7. MockAdapter — 模拟适配器（测试和降级）
# ============================================================================

class MockAdapter(BaseAdapter):
    """
    模拟适配器 — 用于单元测试、集成测试和生产降级。

    特性：
      - 返回预置回答（可配置映射表）
      - 支持模拟延迟（测试超时逻辑）
      - 支持模拟失败（测试重试逻辑）
      - 支持记录调用历史（测试断言用）

    配置项（通过 AdapterConfig.extra 传递）：
      responses       : Dict[str, str] — prompt 到回答的映射表
      default_response: str           — 默认回答（未命中映射表时使用）
      simulate_delay_ms: float        — 模拟的 API 延迟（毫秒）
      simulate_failure: bool          — 是否模拟失败
      failure_rate    : float         — 失败概率（0.0 ~ 1.0），用于模拟间歇性故障

    类比：
      - Python 的 unittest.mock.Mock
      - JavaScript 的 MSW (Mock Service Worker)
      - WireMock / Mockoon
    """

    def __init__(self, config: Optional[AdapterConfig] = None):
        """初始化模拟适配器。"""
        super().__init__(config)
        # 调用历史（用于测试断言）
        self.call_history: List[Dict[str, Any]] = []
        # 预置回答映射表
        self._responses: Dict[str, str] = {}
        self._default_response: str = ""
        self._simulate_delay_ms: float = 0.0
        self._simulate_failure: bool = False
        self._failure_rate: float = 0.0
        self._random = __import__("random")

    # ------------------------------------------------------------------
    # _do_initialize
    # ------------------------------------------------------------------

    def _do_initialize(self) -> bool:
        """
        初始化模拟适配器 — 加载配置中的预置回答。

        始终成功，因为不需要任何外部依赖。
        """
        self._responses = self.config.extra.get("responses", {})
        self._default_response = self.config.extra.get(
            "default_response",
            "这是模拟适配器的默认回答。查询已正常处理。",
        )
        self._simulate_delay_ms = float(self.config.extra.get("simulate_delay_ms", 50))
        self._simulate_failure = bool(self.config.extra.get("simulate_failure", False))
        self._failure_rate = float(self.config.extra.get("failure_rate", 0.0))
        self.call_history.clear()

        logger.info(
            "[%s] 模拟适配器已初始化 (预置回答数: %d, 模拟延迟: %.0f ms, 模拟失败: %s)",
            self.config.adapter_id,
            len(self._responses),
            self._simulate_delay_ms,
            self._simulate_failure,
        )
        return True

    # ------------------------------------------------------------------
    # _do_execute
    # ------------------------------------------------------------------

    def _do_execute(self, messages: List[Dict[str, str]], **kwargs: Any) -> AdapterResponse:
        """
        返回模拟的 LLM 回答。

        匹配逻辑（按优先级）：
          1. 精确匹配：responses 中有与最后一条 user 消息 content 完全相同的 key
          2. 子串匹配：responses 的 key 是 user 消息的子串
          3. 默认回答：未命中任何映射

        模拟特性：
          - 延迟：simulate_delay_ms 毫秒后返回（测试超时）
          - 失败：simulate_failure=True 时抛出异常（测试重试）
          - 概率失败：failure_rate 决定本次是否失败
        """
        # 提取最后一条 user 消息的内容作为匹配 key
        user_content = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                user_content = msg.get("content", "")
                break

        # 记录调用历史
        record = {
            "timestamp": time.time(),
            "messages": messages,
            "kwargs": kwargs,
        }
        self.call_history.append(record)

        # 模拟延迟
        if self._simulate_delay_ms > 0:
            time.sleep(self._simulate_delay_ms / 1000.0)

        # 模拟概率失败
        if self._simulate_failure:
            raise RuntimeError(f"[{self.config.adapter_id}] 模拟的适配器失败（配置开启 simulate_failure）")

        if self._failure_rate > 0 and self._random.random() < self._failure_rate:
            raise RuntimeError(
                f"[{self.config.adapter_id}] 模拟的间歇性故障"
                f"（failure_rate={self._failure_rate}）"
            )

        # 匹配回答
        response_content = self._match_response(user_content)

        return AdapterResponse(
            content=response_content,
            model="mock-model-v1",
            usage={
                "prompt_tokens": len(user_content) // 4,      # 粗略估算
                "completion_tokens": len(response_content) // 4,
                "total_tokens": (len(user_content) + len(response_content)) // 4,
            },
            finish_reason="stop",
            metadata={
                "adapter_type": "mock",
                "matched_key": self._get_match_key(user_content),
            },
        )

    # ------------------------------------------------------------------
    # _do_health_check
    # ------------------------------------------------------------------

    def _do_health_check(self) -> bool:
        """
        健康检查：模拟适配器始终健康（无外部依赖）。

        返回：
          始终 True
        """
        logger.info("[%s] 模拟适配器健康检查: 始终通过", self.config.adapter_id)
        return True

    # ------------------------------------------------------------------
    # _do_shutdown
    # ------------------------------------------------------------------

    def _do_shutdown(self) -> None:
        """关闭模拟适配器 — 清理调用历史。"""
        count = len(self.call_history)
        self.call_history.clear()
        logger.info(
            "[%s] 模拟适配器已关闭 (清除了 %d 条调用历史)",
            self.config.adapter_id,
            count,
        )

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _match_response(self, user_content: str) -> str:
        """
        根据用户输入匹配预置回答。

        匹配优先级：
          1. 空输入 → 默认回答
          2. 精确匹配
          3. 子串匹配

        参数：
          user_content : 用户输入文本

        返回：
          匹配到的回答文本
        """
        if not user_content:
            return self._default_response

        # 1) 精确匹配
        if user_content in self._responses:
            return self._responses[user_content]

        # 2) 子串匹配（key 出现在 user_content 中）
        for key, value in self._responses.items():
            if key and key in user_content:
                return value

        # 3) 默认回答
        return self._default_response

    def _get_match_key(self, user_content: str) -> Optional[str]:
        """返回匹配到的 key（用于 metadata），未匹配返回 None。"""
        if user_content in self._responses:
            return user_content
        for key in self._responses:
            if key and key in user_content:
                return key
        return None

    # ------------------------------------------------------------------
    # 测试辅助方法
    # ------------------------------------------------------------------

    def add_response(self, prompt_pattern: str, response: str) -> None:
        """
        动态添加预置回答（方便测试中增量配置）。

        参数：
          prompt_pattern : 匹配的 prompt 模式（精确或子串）
          response       : 对应的模拟回答
        """
        self._responses[prompt_pattern] = response

    def get_call_count(self) -> int:
        """返回历史调用次数（测试断言用）。"""
        return len(self.call_history)

    def get_last_call(self) -> Optional[Dict[str, Any]]:
        """返回最近一次调用记录（测试断言用）。"""
        return self.call_history[-1] if self.call_history else None


# ============================================================================
# 8. HarmonyAdapter — 鸿蒙端侧 AI 模型适配器（待实现）
# ============================================================================

class HarmonyAdapter(BaseAdapter):
    """
    适配鸿蒙（HarmonyOS）端侧 AI 模型。

    目标：
      在 OpenHarmony 设备上直接运行轻量级 AI 推理，无需云端往返。

    计划支持的能力：
      - 通过 NAPI（Native API）调用 HarmonyOS 内置的 MindSpore Lite 推理引擎
      - 对接 HiAI Foundation SDK 的 NPU 加速能力
      - 支持 .ms（MindSpore）和 .om（Ascend）模型格式
      - 端侧模型热加载和热替换
      - 与 ArkTS 层通过 IPC 传递推理结果

    当前状态：**待实现（Pseudo-code only）**

    伪代码标注说明：
      - @PSEUDO     : 接口签名已确定，实现留空
      - @TODO       : 待后续完成的具体任务
      - @DEPENDS_ON : 依赖的鸿蒙 SDK / 能力

    类比：
      - Apple 的 Core ML
      - Google 的 TensorFlow Lite (Android)
      - 华为 HiAI Engine

    参考文档：
      docs/harmony_adaptation.md
    """

    def __init__(self, config: Optional[AdapterConfig] = None):
        """初始化鸿蒙端侧适配器。"""
        super().__init__(config)
        # @PSEUDO: 鸿蒙端侧推理引擎实例（MindSpore Lite Runtime）
        self._runtime: Optional[Any] = None  # 实际为 mindspore.lite.Model 或 HiAI Session
        # @PSEUDO: 当前加载的模型信息
        self._model_info: Dict[str, Any] = {}
        # @PSEUDO: NPU 是否可用
        self._npu_available: bool = False
        # @PSEUDO: 设备信息（芯片型号、内存等）
        self._device_info: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # _do_initialize — 伪代码
    # ------------------------------------------------------------------

    def _do_initialize(self) -> bool:
        """
        @PSEUDO 初始化鸿蒙端侧 AI 推理引擎。

        @TODO 实际实现步骤：
          1. 检测 HarmonyOS 版本（≥ 4.0 才支持 MindSpore Lite 完整特性）
          2. 检测 NPU 是否可用（通过 HiAI Foundation API）
          3. 加载 .ms 模型文件到内存
          4. 构建推理会话（MindSpore Lite Session）
          5. 预热：发送一条空输入完成首次推理（消除冷启动延迟）

        @DEPENDS_ON:
          - HarmonyOS NAPI (Native API) 的 mindspore_lite 模块
          - HiAI Foundation SDK（需要华为开发者账号和签名）
        """
        # @PSEUDO: 检测 HarmonyOS 版本
        # harmony_version = get_harmony_os_version()  # e.g. "4.0.0"
        # if not _check_version(harmony_version, "4.0.0"):
        #     logger.error("需要 HarmonyOS >= 4.0")
        #     return False

        # @PSEUDO: 初始化 MindSpore Lite 上下文
        # context = mindspore.lite.Context()
        # context.target = ["npu"] if self._npu_available else ["cpu"]
        # context.npu.frequency = 3  # NPU 频率等级

        # @PSEUDO: 加载模型
        # model_path = self.config.extra.get("model_path", "/data/models/query_assistant.ms")
        # self._runtime = mindspore.lite.Model()
        # self._runtime.build_from_file(model_path, mindspore.lite.ModelType.MINDIR, context)

        # @PSEUDO: 预热
        # dummy_input = mindspore.Tensor(np.zeros((1, 512), dtype=np.int32), mindspore.int32)
        # self._runtime.predict([dummy_input])

        logger.warning(
            "[%s] HarmonyAdapter 尚未实现 — 仅提供接口定义和伪代码",
            self.config.adapter_id,
        )
        # @PSEUDO: 当前返回 False 表示不可用；实现后改为 True
        return False

    # ------------------------------------------------------------------
    # _do_execute — 伪代码
    # ------------------------------------------------------------------

    def _do_execute(self, messages: List[Dict[str, str]], **kwargs: Any) -> AdapterResponse:
        """
        @PSEUDO 在鸿蒙设备上执行端侧推理。

        @TODO 实际实现步骤：
          1. 将 messages 转换/分词为模型输入 tensor
          2. 调用 self._runtime.predict()
          3. 将输出 tensor 解码为文本
          4. 返回 AdapterResponse

        预计延迟：
          - CPU 推理: 500-2000 ms（视模型大小）
          - NPU 推理: 100-500 ms

        @DEPENDS_ON:
          - Tokenizer（与模型配套的分词器，可能是 SentencePiece 或 BPE）
          - MindSpore Tensor 操作
        """
        # @PSEUDO: 分词
        # tokenizer = _get_tokenizer()
        # input_ids = tokenizer.encode(messages)
        # input_tensor = mindspore.Tensor(np.array([input_ids]), mindspore.int32)

        # @PSEUDO: 推理
        # outputs = self._runtime.predict([input_tensor])

        # @PSEUDO: 解码
        # output_text = tokenizer.decode(outputs[0])

        # @PSEUDO: 暂返回错误，待实现后改为真实结果
        return AdapterResponse(
            content="[HarmonyAdapter] 鸿蒙端侧推理尚未实现。"
                   "请等待 MindSpore Lite 集成完成。",
            model=self.config.extra.get("model_name", "harmony-local"),
            finish_reason="error",
            metadata={
                "status": "not_implemented",
                "device": "HarmonyOS",
            },
        )

    # ------------------------------------------------------------------
    # _do_health_check — 伪代码
    # ------------------------------------------------------------------

    def _do_health_check(self) -> bool:
        """
        @PSEUDO 检查鸿蒙端侧推理引擎是否健康。

        @TODO 实际检查项：
          1. NPU 驱动是否正常
          2. 模型是否仍在内存中（未被系统回收）
          3. 推理延迟是否在可接受范围内
        """
        # @PSEUDO: 检查 NPU 状态
        # if self._npu_available:
        #     npu_status = check_npu_status()
        #     if npu_status.temperature > 80:
        #         logger.warning("NPU 过热，降级到 CPU 推理")
        #         return True  # 降级而非失败

        # @PSEUDO: 检查模型是否已加载
        # if self._runtime is None:
        #     return False

        logger.info(
            "[%s] HarmonyAdapter 健康检查: 当前不可用（尚未实现）",
            self.config.adapter_id,
        )
        return False

    # ------------------------------------------------------------------
    # _do_shutdown — 伪代码
    # ------------------------------------------------------------------

    def _do_shutdown(self) -> None:
        """
        @PSEUDO 释放鸿蒙端侧推理资源。

        @TODO 实际清理：
          1. 释放 MindSpore Lite 会话
          2. 卸载模型（释放内存/显存）
          3. 通知 NPU 驱动释放资源
        """
        # @PSEUDO: 释放推理会话
        # if self._runtime is not None:
        #     self._runtime.free()
        #     self._runtime = None

        logger.info(
            "[%s] HarmonyAdapter 已关闭（当前无实际资源需释放）",
            self.config.adapter_id,
        )


# ============================================================================
# 9. 适配器工厂函数
# ============================================================================

def create_adapter(adapter_type: str, config: Optional[AdapterConfig] = None) -> BaseAdapter:
    """
    适配器工厂 — 根据类型字符串创建对应的适配器实例。

    参数：
      adapter_type : 适配器类型标识
                     "openai" | "local" | "claude" | "mock" | "harmony"
      config       : 适配器配置（可选）

    返回：
      对应的 BaseAdapter 子类实例

    引发：
      ValueError — 当 adapter_type 无效时

    类比：
      - Python 的 logging.getLogger(name) — 工厂方法
      - Java 的 DriverManager.getConnection(url)
      - Node.js 的 require('express') — 模块工厂

    使用示例：
      >>> adapter = create_adapter("mock")
      >>> adapter.initialize()
      >>> resp = adapter.execute("你好")
      >>> print(resp.content)
    """
    registry: Dict[str, type] = {
        "openai": OpenAIAdapter,
        "local": LocalLLMAdapter,
        "claude": ClaudeAdapter,
        "mock": MockAdapter,
        "harmony": HarmonyAdapter,
    }

    adapter_cls = registry.get(adapter_type.lower())
    if adapter_cls is None:
        raise ValueError(
            f"未知的适配器类型: '{adapter_type}'。"
            f"支持的类型: {list(registry.keys())}"
        )

    logger.info("创建适配器: type=%s", adapter_type)
    return adapter_cls(config)
