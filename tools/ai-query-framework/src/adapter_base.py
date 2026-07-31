"""
ai-query-framework/src/adapter_base.py

适配器抽象基类模块
====================
定义所有适配器的基础抽象，提供统一的适配器生命周期管理接口。

类比说明：
- Python abc.ABC ≈ TypeScript abstract class：定义契约但不提供完整实现
- 适配器模式 ≈ Docker 的 driver 插件机制：通过统一接口支持多种后端实现
- AdapterStatus 枚举类似于 Kubernetes 的 Pod Condition（健康/降级/故障）

设计原则：
1. 所有适配器必须实现 initialize / execute / health_check / shutdown 四个核心方法
2. 适配器状态机：HEALTHY ↔ DEGRADED ↔ FAULT，MAINTENANCE 为特殊维护状态
3. 每个适配器通过 AdapterEvent 上报生命周期事件，便于监控和审计
4. 事件处理器采用观察者模式，外部可注册回调监听适配器事件
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional
import time


# ============================================================================
# 适配器状态枚举
# ============================================================================

class AdapterStatus(Enum):
    """适配器健康状态枚举

    定义适配器在其生命周期中可能处于的四种状态。

    状态流转规则：
        HEALTHY ──(部分功能异常)──→ DEGRADED
        HEALTHY ──(故障)────────→ FAULT
        DEGRADED ──(恢复)───────→ HEALTHY
        DEGRADED ──(恶化)───────→ FAULT
        FAULT ──(恢复)─────────→ HEALTHY
        任意状态 ──(手动维护)───→ MAINTENANCE
        MAINTENANCE ──(维护完成)→ HEALTHY

    取值：
        HEALTHY: 适配器正常运行，所有功能可用
        DEGRADED: 适配器部分功能受限，仍可提供降级服务
        FAULT: 适配器发生故障，无法正常提供服务
        MAINTENANCE: 适配器处于维护模式，暂时不可用
    """
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAULT = "fault"
    MAINTENANCE = "maintenance"


# ============================================================================
# 适配器事件数据类
# ============================================================================

@dataclass
class AdapterEvent:
    """适配器生命周期事件数据类

    用于记录适配器在运行过程中产生的各类事件。事件通过观察者模式
    分发给所有已注册的事件处理器。

    支持的事件类型：
        - status_change: 适配器状态发生变更时触发
        - execution: 适配器执行任务时触发（用于记录执行日志）
        - error: 适配器发生异常时触发（用于告警）
        - heartbeat: 适配器定期心跳上报（用于存活检测）

    Attributes:
        event_type: 事件类型字符串，取值为上述四种之一
        adapter_id: 产生该事件的适配器唯一标识
        timestamp: 事件发生的 Unix 时间戳（秒），默认使用当前时间
        data: 事件携带的附加数据字典，具体结构由事件类型决定
              示例（status_change）: {"old_status": "healthy", "new_status": "degraded", "reason": "..."}
              示例（execution）: {"task": "translate", "elapsed_ms": 230, "tokens_used": 450}
              示例（error）: {"error_type": "TimeoutError", "message": "..."}
              示例（heartbeat）: {"uptime_seconds": 3600, "memory_mb": 128}
    """
    event_type: str
    adapter_id: str
    timestamp: float = field(default_factory=time.time)
    data: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# 适配器抽象基类
# ============================================================================

class BaseAdapter(ABC):
    """适配器抽象基类

    所有适配器（LLM 适配器、采集器适配器、数据源适配器、算法适配器）
    都必须继承此类并实现全部抽象方法。

    生命周期（标准调用顺序）：
        1. 实例化 → __init__() 设置基本属性（ID、类型、元数据）
        2. 初始化 → initialize() 建立连接、加载配置、分配资源
        3. 执行   → execute() 反复调用，执行核心业务逻辑
        4. 检查   → health_check() 定期调用，更新健康状态
        5. 关闭   → shutdown() 释放所有资源，优雅退出

    子类示例：
        class GPT4Adapter(BaseAdapter):
            def __init__(self):
                super().__init__(
                    adapter_id="gpt4_primary",
                    adapter_type="llm",
                    metadata={"model": "gpt-4", "version": "turbo-2024"}
                )

            def initialize(self) -> bool:
                # 建立 OpenAI 连接...
                return True

            def execute(self, input_data):
                # 调用 OpenAI API...
                return {"success": True, "data": {...}}

            def health_check(self):
                # 检查 API 连通性...
                return AdapterStatus.HEALTHY

            def shutdown(self):
                # 关闭 HTTP 会话...
                pass

    类比：
        - 相当于 Docker 的 driver 插件接口：统一抽象，多种具体实现
        - 相当于 TypeScript 的 abstract class：定义契约，子类强制实现
        - 相当于 Java 的 Interface + abstract class 结合体
    """

    def __init__(
        self,
        adapter_id: str,
        adapter_type: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """初始化适配器基础属性

        子类应在 __init__ 中调用 super().__init__() 并传入必要参数。
        子类可在此基础上添加自己的实例属性（如连接池、配置对象等）。

        Args:
            adapter_id: 适配器唯一标识符，建议使用语义化命名
                        命名规范：{provider}_{capability}_{version}
                        例如 "gpt4_primary_v2"、"web_collector_stable"、"bloomberg_terminal"
            adapter_type: 适配器类型，必须是以下四种之一：
                          - "llm": 大语言模型适配器（GPT-4、Claude、文心一言等）
                          - "collector": 数据采集器适配器（网络爬虫、API 采集等）
                          - "source": 数据源适配器（数据库、文件系统、Bloomberg 终端等）
                          - "algorithm": 算法适配器（NL2SQL、语义路由、RAG 等）
            metadata: 适配器元数据字典，用于描述适配器的详细能力信息
                      推荐字段：
                      - model: 模型名称（LLM 适配器）
                      - version: 适配器版本号
                      - capabilities: 能力列表，如 ["translate", "summarize"]
                      - provider: 服务提供方
                      - max_tokens: 最大 Token 数（LLM 适配器）
                      - endpoint: 服务端点 URL
        """
        self.adapter_id = adapter_id
        self.adapter_type = adapter_type
        self.status = AdapterStatus.HEALTHY
        self.metadata = metadata or {}

        # 内部事件处理器注册表：{event_type: [handler1, handler2, ...]}
        # 通过 on_event() 注册，通过 _emit_event() 触发
        self._event_handlers: Dict[str, list] = {}

    # ==================== 抽象方法（子类必须实现） ====================

    @abstractmethod
    def initialize(self) -> bool:
        """初始化适配器

        子类在此方法中完成一次性初始化工作：
        - 资源分配：建立数据库/缓存连接、创建 HTTP 客户端会话
        - 配置加载：读取配置文件、验证必需参数
        - 依赖检查：确认下游服务可用、SDK 版本兼容
        - 预热操作：加载模型、填充缓存等

        此方法在适配器注册后由注册中心或编排器调用一次。

        Returns:
            bool: 初始化成功返回 True，失败返回 False。
                  失败时调用方不应继续使用该适配器。

        Raises:
            子类可按需抛出具体异常（ConnectionError、ConfigError 等），
            调用方应捕获并处理。推荐在方法内部尽量自行处理可恢复错误。
        """
        ...

    @abstractmethod
    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """执行适配器核心功能

        这是适配器的主要工作入口，所有业务逻辑通过此方法调用。
        此方法在适配器生命周期中可被反复调用。

        Args:
            input_data: 输入数据字典，具体结构由适配器类型和子类定义。

                        LLM 适配器示例：
                            {"prompt": "翻译以下文本...", "max_tokens": 1024, "temperature": 0.7}

                        采集器适配器示例：
                            {"query": "贵州茅台 2024年报", "sources": ["web", "pdf"], "max_results": 10}

                        数据源适配器示例：
                            {"table": "financial_reports", "filters": {"year": 2024, "company": "600519"}}

                        算法适配器示例：
                            {"nl": "查询茅台最新财报", "schema": {...}, "dialect": "mysql"}

        Returns:
            Dict[str, Any]: 执行结果字典，必须包含至少以下字段：
                - success (bool): 执行是否成功
                - data (Any): 执行结果数据，成功时包含具体结果
                - error (str, 可选): 错误描述，失败时提供
                - elapsed_ms (float, 可选): 执行耗时（毫秒）

        Raises:
            执行失败时子类可抛出异常。推荐在方法内部尽量捕获并返回
            包含 error 字段的结果字典，而非直接抛出异常。
        """
        ...

    @abstractmethod
    def health_check(self) -> AdapterStatus:
        """执行适配器健康检查

        检查适配器及其下游依赖的当前健康状态。此方法应尽量轻量，
        不应执行重量级操作（如完整的查询请求）。

        推荐检查项：
        - 后端服务连通性：ping / 简单探活请求
        - 资源使用率：连接池可用连接数、内存占用
        - 响应延迟：最近的请求延迟是否在阈值内
        - 凭证有效性：API Key / Token 是否过期

        Returns:
            AdapterStatus: 当前健康状态枚举值。
                           同时必须更新 self.status 属性。

        Note:
            此方法会被监控系统定期调用（如每 30 秒），
            因此必须保证快速返回（建议 < 5 秒）。
        """
        ...

    @abstractmethod
    def shutdown(self) -> None:
        """优雅关闭适配器

        释放适配器占用的所有资源，确保无资源泄漏。
        此方法在适配器注销或系统关闭时调用。

        应释放的资源包括：
        - 网络连接：关闭 HTTP 会话、WebSocket 连接
        - 文件句柄：关闭日志文件、临时文件
        - 数据库连接：归还连接池、关闭游标
        - 线程/进程：停止后台线程、清理进程池
        - 缓存数据：持久化内存缓存、清理临时目录

        Note:
            此方法必须保证幂等性——多次调用不应产生副作用或抛出异常。
            推荐使用标志位记录是否已关闭，重复调用时直接返回。
        """
        ...

    # ==================== 具体方法（子类可直接使用） ====================

    def get_info(self) -> Dict[str, Any]:
        """获取适配器完整信息

        返回适配器的标识、类型、当前状态和元数据的汇总字典。
        常用于：
        - 管理面板展示适配器列表
        - 调试时快速了解适配器配置
        - 监控系统采集适配器元数据

        Returns:
            Dict[str, Any]: 包含以下键的字典：
                - adapter_id (str): 适配器唯一标识
                - adapter_type (str): 适配器类型
                - status (str): 当前状态字符串值（如 "healthy"）
                - metadata (dict): 元数据字典的浅拷贝
                - available (bool): 适配器当前是否可用
        """
        return {
            "adapter_id": self.adapter_id,
            "adapter_type": self.adapter_type,
            "status": self.status.value,
            "metadata": dict(self.metadata),  # 浅拷贝，避免外部修改
            "available": self.is_available(),
        }

    def is_available(self) -> bool:
        """判断适配器当前是否可用

        只有状态为 HEALTHY 或 DEGRADED 时视为可用。
        FAULT 和 MAINTENANCE 状态均视为不可用。

        调用方在执行适配器前应检查此方法，避免向故障适配器发送请求。

        Returns:
            bool: 适配器可用返回 True，否则返回 False
        """
        return self.status in (AdapterStatus.HEALTHY, AdapterStatus.DEGRADED)

    # ==================== 事件处理机制（观察者模式） ====================

    def on_event(self, event_type: str, handler) -> None:
        """注册事件处理器（观察者模式）

        为指定事件类型注册一个回调函数。当该类型事件发生时，
        所有已注册的回调函数会按注册顺序依次调用。

        Args:
            event_type: 事件类型字符串，如 "status_change"、"error"、"execution"、"heartbeat"
            handler: 回调函数，签名为 handler(event: AdapterEvent) -> None
                     回调函数中的异常会被静默捕获，不会影响其他处理器

        使用示例：
            def on_status_change(event: AdapterEvent):
                print(f"适配器 {event.adapter_id} 状态变更: {event.data}")

            adapter.on_event("status_change", on_status_change)
        """
        if event_type not in self._event_handlers:
            self._event_handlers[event_type] = []
        self._event_handlers[event_type].append(handler)

    def _emit_event(self, event_type: str, data: Optional[Dict[str, Any]] = None) -> None:
        """触发事件并通知所有已注册的处理器

        内部方法，子类在状态变更、执行完成、发生错误时调用此方法
        通知外部监听者。

        Args:
            event_type: 事件类型字符串
            data: 事件附加数据字典，可选

        Note:
            事件处理器的异常会被静默捕获并记录，不会中断主流程。
            这是刻意设计——事件通知是"尽力而为"的，不应影响核心业务。
        """
        event = AdapterEvent(
            event_type=event_type,
            adapter_id=self.adapter_id,
            data=data or {}
        )
        handlers = self._event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                # 事件处理器异常不应中断主流程
                # 生产环境中可替换为 logger.exception(...)
                pass

    def __repr__(self) -> str:
        """适配器的可读字符串表示"""
        return (
            f"<{self.__class__.__name__}("
            f"id={self.adapter_id!r}, "
            f"type={self.adapter_type!r}, "
            f"status={self.status.value!r})>"
        )
