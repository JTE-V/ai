"""
查询编排器 — Query Orchestrator
================================
将 AI 查询模板 + 用户输入编排为完整的查询流水线，
每一步都有错误处理和降级策略。

流水线架构：
  用户输入 + AITemplate
    │
    ▼
  [1. 权限校验]  AuthProxy.check_permission()
    │  ├── 通过 → 继续
    │  └── 拒绝 → 返回 403 错误
    ▼
  [2. 渐进查询]  ProgressiveQueryEngine.execute()
    │  ├── CACHE → COARSE_FILTER → FINE_RERANK → GENERATE
    │  └── 失败 → 降级到缓存或空结果
    ▼
  [3. 精准采集]  PrecisionCollector
    │  ├── HTML / JSON / API → 结构化字段
    │  └── 失败 → 跳过，保留原始结果
    ▼
  [4. 算法房间]  AlgorithmRoom 步骤流水线
    │  ├── merge → rank → filter → transform → aggregate → llm_summarize
    │  └── 失败 → 跳过该步骤，保留上一步结果
    ▼
  [5. 格式化输出] → 结构化 Dict
    └── 对齐模板的 output_schema

全程由 QueryGuardian 监控（背压、超时、降级、GC）

类比：
  - Express.js 的 middleware chain：
    app.use(authMiddleware)
       .use(queryMiddleware)
       .use(collectMiddleware)
       .use(algorithmMiddleware)
       .use(formatMiddleware)
  - Nginx 的请求处理阶段链（11 个阶段）
  - AWS Step Functions 的状态机（State Machine）
  - Next.js 的 Middleware → API Route → Response 流水线

核心设计原则：
  - 每一步独立、可替换、可测试
  - 错误不传播——降级而非中断
  - QueryContext 在管道各阶段间传递，类似 HTTP Request 对象
"""

import json
import logging
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

# ---------------------------------------------------------------------------
# 可选依赖：对话管理和查询日志（若模块缺失则降级为空操作）
# ---------------------------------------------------------------------------
try:
    from conversation_manager import (
        ConversationManager,
        ConversationListener,
    )
    _HAS_CONVERSATION_MANAGER = True
except ImportError:  # pragma: no cover
    ConversationManager = None  # type: ignore[assignment,misc]
    ConversationListener = None  # type: ignore[assignment,misc]
    _HAS_CONVERSATION_MANAGER = False

try:
    from query_logger import QueryLogger
    _HAS_QUERY_LOGGER = True
except ImportError:  # pragma: no cover
    QueryLogger = None  # type: ignore[assignment,misc]
    _HAS_QUERY_LOGGER = False

# ---------------------------------------------------------------------------
# 导入各子系统的核心类
# ---------------------------------------------------------------------------
from template_engine import (
    AITemplate,
    AlgorithmRoom,
    AlgorithmStep,
    AlgorithmType,
    QuerySource,
    OutputField,
)
from query_guardian import (
    ProgressiveQueryEngine,
    QueryGuardian,
    QueryContext as GuardianQueryContext,  # 别名避免与本模块的 QueryContext 混淆
    QueryLayer,
    DegradationLevel,
    DegradedResponse,
)
from precision_collector import (
    PrecisionCollector,
    FieldType,
    FieldSchema,
    quick_collect,
)
from auth_proxy import (
    AuthProxy,
    Permission,
    AuditEntry,
    AuditEvent,
)

# ---------------------------------------------------------------------------
# 可选依赖：适配器子系统（若模块缺失则降级为空操作）
# ---------------------------------------------------------------------------
try:
    from adapter_registry import AdapterRegistry
    _HAS_ADAPTER_REGISTRY = True
except ImportError:  # pragma: no cover
    AdapterRegistry = None  # type: ignore[assignment,misc]
    _HAS_ADAPTER_REGISTRY = False

try:
    from adapter_base import AbstractAdapter
    _HAS_ABSTRACT_ADAPTER = True
except ImportError:  # pragma: no cover
    AbstractAdapter = None  # type: ignore[assignment,misc]
    _HAS_ABSTRACT_ADAPTER = False

try:
    from unified_monitor import UnifiedMonitor, AdapterEvent, HealthStatus
    _HAS_UNIFIED_MONITOR = True
except ImportError:  # pragma: no cover
    UnifiedMonitor = None  # type: ignore[assignment,misc]
    AdapterEvent = None  # type: ignore[assignment,misc]
    HealthStatus = None  # type: ignore[assignment,misc]
    _HAS_UNIFIED_MONITOR = False

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ============================================================================
# 1. 流水线阶段枚举
# ============================================================================

class PipelineStage(Enum):
    """
    流水线阶段枚举 — 每个阶段对应管道中的一个处理节点。

    类比：
      - Express.js middleware 的挂载路径
      - Nginx 的 NGX_HTTP_POST_READ_PHASE 等阶段常量
      - Promise 链中的 .then() 节点
    """
    AUTH = "auth"                       # 权限校验
    PROGRESSIVE_QUERY = "progressive_query"  # 渐进式查询
    PRECISION_COLLECT = "precision_collect"  # 精准采集
    ALGORITHM_ROOM = "algorithm_room"        # 算法房间
    FORMAT_OUTPUT = "format_output"          # 格式化输出


# ============================================================================
# 2. QueryContext — 在管道各阶段间传递的上下文对象
# ============================================================================

@dataclass
class QueryContext:
    """
    查询上下文——在编排器管道的各阶段间传递，类似 HTTP Request 对象。

    类比：
      - Express.js 的 `req` 对象：
        req.body    = user_input      （请求体）
        req.params  = template        （路由参数）
        req.locals  = metadata        （中间件间传递的本地变量）
      - Node.js 的 async_hooks 的 executionAsyncId()
      - Python 的 contextvars.ContextVar

    字段说明：
      template         : AITemplate              — 当前查询使用的 AI 模板
      user_input       : Dict[str, Any]          — 用户原始输入（key-value）
      query_results    : Optional[Any]           — 渐进查询产出的中间结果
      collected_data   : Optional[Dict]          — 精准采集产出的结构化数据
      algorithm_output : Optional[Any]           — 算法房间产出的处理后数据
      formatted_output : Optional[Dict]          — 格式化后的最终输出
      errors           : List[Dict]              — 各阶段错误记录（不中断流水线）
      metadata         : Dict[str, Any]          — 扩展元数据（计时、来源等）
      started_at       : float                   — 管道开始时间戳
      pipeline_id      : str                     — 全局唯一管道 ID

    JS 类比：
      interface QueryContext {
        template: AITemplate;
        userInput: Record<string, any>;
        queryResults?: any;
        collectedData?: Record<string, any>;
        algorithmOutput?: any;
        formattedOutput?: Record<string, any>;
        errors: Array<{ stage: string; message: string; timestamp: number }>;
        metadata: Record<string, any>;
        startedAt: number;
        pipelineId: string;
      }
    """
    template: "AITemplate"
    user_input: Dict[str, Any]
    query_results: Optional[Any] = None
    collected_data: Optional[Dict[str, Any]] = None
    algorithm_output: Optional[Any] = None
    formatted_output: Optional[Dict[str, Any]] = None
    errors: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    pipeline_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    # ------------------------------------------------------------------
    # 便捷方法
    # ------------------------------------------------------------------

    def record_error(self, stage: PipelineStage, message: str,
                     exception: Optional[Exception] = None) -> None:
        """
        记录一个非致命错误——不中断流水线，只记录。

        类比：
          - Express.js 的 next(err) 但选择记录而非跳过
          - Sentry / DataDog 的错误捕获
          - console.error() 但不 throw

        参数：
          stage     : PipelineStage — 发生错误的阶段
          message   : str           — 人类可读的错误描述
          exception : Exception     — 原始异常（可选）
        """
        error_entry = {
            "stage": stage.value,
            "message": message,
            "timestamp": time.time(),
            "exception_type": type(exception).__name__ if exception else None,
            "exception_message": str(exception) if exception else None,
        }
        self.errors.append(error_entry)
        logger.warning(
            f"[Pipeline:{self.pipeline_id}] [{stage.value}] {message}"
            + (f" | {type(exception).__name__}: {exception}" if exception else "")
        )

    def has_errors(self) -> bool:
        """是否有任何阶段记录了错误。类比：Express.js 的 res.locals.hasErrors。"""
        return len(self.errors) > 0

    def elapsed_seconds(self) -> float:
        """从管道启动到现在的耗时（秒）。类比：performance.now() - startTime。"""
        return time.time() - self.started_at

    def to_summary(self) -> Dict[str, Any]:
        """
        生成上下文的摘要（用于日志 / 调试）。

        类比：Express.js 的 morgan 日志中间件输出的请求摘要
        """
        return {
            "pipeline_id": self.pipeline_id,
            "template_name": self.template.name,
            "elapsed_seconds": round(self.elapsed_seconds(), 3),
            "error_count": len(self.errors),
            "has_query_results": self.query_results is not None,
            "has_collected_data": self.collected_data is not None,
            "has_algorithm_output": self.algorithm_output is not None,
            "has_formatted_output": self.formatted_output is not None,
            "stages_with_errors": [e["stage"] for e in self.errors],
        }


# ============================================================================
# 3. 管道步骤签名 — 统一的可调用协议
# ============================================================================

# 每个管道步骤都是一个 Callable，签名为：
#   (QueryContext, **deps) -> QueryContext
# 返回修改后的 QueryContext（或原样返回以表示跳过）
PipelineStep = Callable[["QueryContext"], "QueryContext"]


# ============================================================================
# 4. QueryOrchestrator — 查询编排器主体
# ============================================================================

class QueryOrchestrator:
    """
    查询编排器——将 AI 模板 + 用户输入编排为完整的查询流水线。

    核心职责：
      1. 接收 AITemplate + 用户输入 → 编排查询路径
      2. 调用 AuthProxy 做权限校验
      3. 调用 ProgressiveQueryEngine 做渐进式查询
      4. 调用 PrecisionCollector 做精准采集
      5. 调用 AlgorithmRoom 做算法计算
      6. 全程由 QueryGuardian 监控（背压、超时、降级、GC）

    使用方式：
      orchestrator = QueryOrchestrator(
          auth_proxy=auth_proxy,
          guardian=guardian,
          collector=PrecisionCollector(),
      )

      template = AITemplate.from_file("product_search.yaml")
      result = orchestrator.execute(template, {"query": "机械键盘"})

    类比：
      - Express.js 的 app 对象——注册中间件、处理请求
      - Next.js 的 App Router——路由 + 中间件 + 渲染
      - AWS Step Functions——定义状态机、执行工作流
      - Python 的 asyncio.gather()——编排多个协程
    """

    def __init__(
        self,
        *,
        auth_proxy: Optional[AuthProxy] = None,
        guardian: Optional[QueryGuardian] = None,
        collector: Optional[PrecisionCollector] = None,
        # 可选：自定义中间件步骤（在标准流水线之外插入）
        pre_steps: Optional[List[PipelineStep]] = None,
        post_steps: Optional[List[PipelineStep]] = None,
        # 降级策略配置
        degrade_on_auth_failure: bool = True,
        degrade_on_query_failure: bool = True,
        degrade_on_collect_failure: bool = True,
    ):
        """
        初始化查询编排器。

        参数：
          auth_proxy    : AuthProxy            — 权限代理实例；None 则跳过权限校验
          guardian      : QueryGuardian        — 查询卫士实例；None 则创建默认实例
          collector     : PrecisionCollector   — 精准采集器实例；None 则创建默认实例
          pre_steps     : List[PipelineStep]   — 标准流水线之前插入的额外步骤
          post_steps    : List[PipelineStep]   — 标准流水线之后插入的额外步骤
          degrade_on_auth_failure    : bool    — 权限失败时是否降级（vs 直接抛异常）
          degrade_on_query_failure   : bool    — 查询失败时是否降级
          degrade_on_collect_failure : bool    — 采集失败时是否降级

        类比：
          Express.js 的 app.use() 注册中间件
          ——顺序敏感，先注册的先执行
        """
        # 核心组件
        self.auth_proxy = auth_proxy
        self.guardian = guardian or QueryGuardian()
        self.collector = collector or PrecisionCollector()

        # 降级配置
        self.degrade_on_auth_failure = degrade_on_auth_failure
        self.degrade_on_query_failure = degrade_on_query_failure
        self.degrade_on_collect_failure = degrade_on_collect_failure

        # 自定义中间件步骤
        self._pre_steps: List[PipelineStep] = pre_steps or []
        self._post_steps: List[PipelineStep] = post_steps or []

        # ------------------------------------------------------------------
        # 对话管理与查询日志（类比：Express.js 的 session + morgan 日志）
        # ------------------------------------------------------------------
        if _HAS_CONVERSATION_MANAGER and ConversationManager is not None:
            self.conversation_manager = ConversationManager()
            self.conversation_listener = ConversationListener()
            # 注册回调：当对话切换/创建时通知监听器
            self.conversation_listener.register(self.conversation_manager)
        else:
            self.conversation_manager = None
            self.conversation_listener = None
            logger.debug("[QueryOrchestrator] ConversationManager 未安装，对话管理功能禁用")

        if _HAS_QUERY_LOGGER and QueryLogger is not None:
            self.query_logger = QueryLogger()
        else:
            self.query_logger = None
            logger.debug("[QueryOrchestrator] QueryLogger 未安装，查询日志功能禁用")

        # 每个阶段的处理器（可被外部替换）
        self._stage_handlers: Dict[PipelineStage, PipelineStep] = {
            PipelineStage.AUTH: self._step_auth,
            PipelineStage.PROGRESSIVE_QUERY: self._step_progressive_query,
            PipelineStage.PRECISION_COLLECT: self._step_precision_collect,
            PipelineStage.ALGORITHM_ROOM: self._step_algorithm_room,
            PipelineStage.FORMAT_OUTPUT: self._step_format_output,
        }

        # 运行状态
        self._running = False
        self._execution_count: int = 0  # 已执行管道数（监控用）

        # ------------------------------------------------------------------
        # 适配器子系统（类比：Kubernetes 的多种 CNI 插件共存）
        # ------------------------------------------------------------------
        # 适配器注册表 —— 管理所有 LLM/数据源适配器
        if _HAS_ADAPTER_REGISTRY and AdapterRegistry is not None:
            self._adapter_registry = AdapterRegistry()
            # 注册默认适配器（MockAdapter + APIAdapter）
            self._register_default_adapters()
        else:
            self._adapter_registry = None
            logger.debug("[QueryOrchestrator] AdapterRegistry 未安装，适配器功能禁用")

        # 当前活跃的适配器 ID（用于 execute 中的算法房间 LLM 调用）
        self._active_llm_adapter_id: Optional[str] = None

        # 统一监听器 —— 持续监控适配器健康 + 自动故障切换
        if _HAS_UNIFIED_MONITOR and UnifiedMonitor is not None:
            self._monitor = UnifiedMonitor(
                registry=self._adapter_registry,
                heartbeat_interval=10.0,
                fault_threshold=3,
                auto_switch=True,
            )
            # 注册故障回调：适配器故障时打印告警
            self._monitor.on_adapter_fault(self._on_adapter_fault_handler)
            # 启动后台心跳监控
            self._monitor.watch_all()
        else:
            self._monitor = None
            logger.debug("[QueryOrchestrator] UnifiedMonitor 未安装，适配器监控功能禁用")

        logger.info("[QueryOrchestrator] 初始化完成，已注册 %d 个标准阶段",
                    len(self._stage_handlers))

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        启动编排器及其依赖的子组件。

        类比：
          - Express 的 app.listen() —— 启动 HTTP 服务器
          - Kubernetes Pod 的 init container —— 初始化依赖
        """
        if self._running:
            return
        self._running = True
        self.guardian.start()
        logger.info("[QueryOrchestrator] 编排器已启动")

    def stop(self) -> None:
        """
        优雅停止编排器。

        类比：
          - Express 的 server.close() —— 优雅关闭
          - Kubernetes 的 SIGTERM → graceful shutdown
        """
        self._running = False
        self.guardian.stop()
        # 停止适配器监控
        if self._monitor is not None:
            try:
                self._monitor.stop()
            except Exception as e:
                logger.warning("[QueryOrchestrator] 停止监控器异常: %s", e)
        logger.info("[QueryOrchestrator] 编排器已停止，共执行 %d 次管道",
                    self._execution_count)

    # ------------------------------------------------------------------
    # 核心方法: execute() —— 执行完整的查询管道
    # ------------------------------------------------------------------

    def execute(
        self,
        template: AITemplate,
        user_input: Dict[str, Any],
        *,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        执行完整的查询管道，返回结构化输出。

        这是编排器的主入口——类似于 Express.js 处理一个 HTTP 请求。

        参数：
          template   : AITemplate      — AI 查询模板（声明式定义）
          user_input : Dict[str, Any]  — 用户输入键值对，如 {"query": "蓝牙耳机"}
          metadata   : Dict[str, Any]  — 额外元数据（来源、追踪 ID 等）

        返回：
          Dict[str, Any]：
            {
              "success": True / False,
              "data": { ... },               # 格式化后的结构化输出
              "pipeline_id": "abc123",
              "template_name": "product_search",
              "elapsed_seconds": 0.523,
              "degraded": False,
              "degradation_reason": None,
              "errors": [ ... ],             # 非致命错误列表
              "metadata": { ... },
            }

        流水线执行顺序：
          pre_steps → auth → progressive_query → precision_collect
          → algorithm_room → format_output → post_steps

        类比：
          Express.js 的 app.handle(req, res, callback)
            ——请求进入中间件链，逐层处理，最终返回响应
        """
        start_time = time.time()
        self._execution_count += 1

        # ---- 创建管道上下文 ----
        ctx = QueryContext(
            template=template,
            user_input=user_input,
            metadata=metadata or {},
        )
        ctx.metadata["execution_index"] = self._execution_count

        logger.info(
            "[Pipeline:%s] 开始执行模板 '%s'，用户输入键: %s",
            ctx.pipeline_id, template.name, list(user_input.keys())
        )

        # ---- 对话管理：创建/获取会话，记录查询开始 ----
        session_id = None
        if self.conversation_manager is not None:
            try:
                session_id = (
                    metadata or {}
                ).get("session_id") or self.conversation_manager.current_session_id
                if not session_id:
                    session_id = self.conversation_manager.create_session(
                        template_name=template.name,
                        metadata={"pipeline_id": ctx.pipeline_id},
                    )
                ctx.metadata["session_id"] = session_id
                logger.debug("[Pipeline:%s] 会话 ID: %s", ctx.pipeline_id, session_id)
            except Exception as e:
                logger.warning("[Pipeline:%s] 创建会话失败: %s", ctx.pipeline_id, e)

        if self.query_logger is not None:
            try:
                self.query_logger.start_query(
                    pipeline_id=ctx.pipeline_id,
                    template_name=template.name,
                    user_input=user_input,
                    session_id=session_id,
                )
            except Exception as e:
                logger.warning("[Pipeline:%s] 记录查询开始失败: %s", ctx.pipeline_id, e)

        # ---- 标准流水线阶段（按序执行） ----
        pipeline_order: List[PipelineStage] = [
            PipelineStage.AUTH,
            PipelineStage.PROGRESSIVE_QUERY,
            PipelineStage.PRECISION_COLLECT,
            PipelineStage.ALGORITHM_ROOM,
            PipelineStage.FORMAT_OUTPUT,
        ]

        try:
            # 执行前置步骤（用户自定义中间件）
            ctx = self._execute_steps(ctx, self._pre_steps, label="pre")

            # 执行标准流水线
            for stage in pipeline_order:
                handler = self._stage_handlers.get(stage)
                if handler is None:
                    continue  # 未注册的阶段跳过
                try:
                    ctx = handler(ctx)
                except Exception as e:
                    # 标准阶段的意外异常——记录但不中断
                    ctx.record_error(stage, f"阶段执行异常: {e}", exception=e)
                    logger.error(
                        "[Pipeline:%s] [%s] 未捕获异常: %s",
                        ctx.pipeline_id, stage.value, e, exc_info=True
                    )

            # 执行后置步骤（用户自定义中间件）
            ctx = self._execute_steps(ctx, self._post_steps, label="post")

        except Exception as e:
            # 最外层兜底——确保始终返回有意义的结构
            logger.critical(
                "[Pipeline:%s] 致命异常: %s", ctx.pipeline_id, e, exc_info=True
            )
            ctx.record_error(PipelineStage.FORMAT_OUTPUT, f"管道致命异常: {e}", exception=e)

        # ---- 组装最终输出 ----
        elapsed = time.time() - start_time
        degraded = ctx.has_errors()
        # 确定降级原因
        degradation_reason = None
        if degraded:
            # 收集所有阶段的错误信息
            error_stages = [e["stage"] for e in ctx.errors]
            degradation_reason = f"阶段错误: {', '.join(error_stages)}"

        result = {
            "success": not degraded,
            "data": ctx.formatted_output if ctx.formatted_output is not None else {},
            "pipeline_id": ctx.pipeline_id,
            "template_name": template.name,
            "template_version": template.version,
            "elapsed_seconds": round(elapsed, 4),
            "degraded": degraded,
            "degradation_reason": degradation_reason,
            "errors": ctx.errors,
            "metadata": {
                **ctx.metadata,
                "query_results_available": ctx.query_results is not None,
                "collected_data_available": ctx.collected_data is not None,
                "algorithm_output_available": ctx.algorithm_output is not None,
            },
        }

        logger.info(
            "[Pipeline:%s] 完成，耗时 %.3fs，成功=%s，错误数=%d",
            ctx.pipeline_id, elapsed, not degraded, len(ctx.errors)
        )

        # ---- 执行后：记录完整查询日志 ----
        if self.query_logger is not None:
            try:
                self.query_logger.log(
                    pipeline_id=ctx.pipeline_id,
                    template_name=template.name,
                    user_input=user_input,
                    result=result,
                    session_id=session_id,
                    elapsed_seconds=round(elapsed, 4),
                )
            except Exception as e:
                logger.warning("[Pipeline:%s] 查询日志记录失败: %s", ctx.pipeline_id, e)

        # ---- 执行后：添加对话轮次 ----
        if self.conversation_manager is not None and session_id:
            try:
                self.conversation_manager.add_turn(
                    session_id=session_id,
                    user_message=user_input,
                    assistant_message=result,
                    metadata={
                        "pipeline_id": ctx.pipeline_id,
                        "template_name": template.name,
                        "elapsed_seconds": round(elapsed, 4),
                        "degraded": degraded,
                    },
                )
            except Exception as e:
                logger.warning("[Pipeline:%s] 添加对话轮次失败: %s", ctx.pipeline_id, e)

        return result

    # ------------------------------------------------------------------
    # execute_async() — 异步执行（兼容 async/await）
    # ------------------------------------------------------------------

    async def execute_async(
        self,
        template: AITemplate,
        user_input: Dict[str, Any],
        *,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        异步执行完整管道（与 execute() 相同逻辑，但在异步上下文中运行）。

        类比：
          - Express.js 5 的 async middleware
          - Python FastAPI 的 async def endpoint
          - Next.js App Router 的 async Server Component

        使用方式：
          result = await orchestrator.execute_async(template, user_input)
        """
        # 在默认线程池中运行同步 execute（避免阻塞事件循环）
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self.execute(template, user_input, metadata=metadata)
        )

    # ------------------------------------------------------------------
    # 5a. 阶段处理器: 权限校验
    # ------------------------------------------------------------------

    def _step_auth(self, ctx: QueryContext) -> QueryContext:
        """
        阶段 1: 权限校验 — 验证用户/请求是否有权执行此查询。

        校验内容：
          1. 检查请求域名是否在白名单
          2. 检查操作类型（READ / WRITE / ADMIN）
          3. 检查 scope（如 "read:products"）
          4. 记录审计日志

        类比：
          - Express.js 的 auth middleware（passport.js / JWT 验证）
          - AWS IAM 的 policy evaluation
          - Kubernetes RBAC 的 SubjectAccessReview

        降级策略：
          如果 auth_proxy 未配置 → 跳过校验（开发模式）
          如果权限被拒绝 → 根据 degrade_on_auth_failure 决定是否降级
        """
        # 如果未配置 auth_proxy，跳过权限校验（开发/测试模式）
        if self.auth_proxy is None:
            ctx.metadata["auth_skipped"] = True
            ctx.metadata["auth_reason"] = "no_auth_proxy_configured"
            logger.debug("[Pipeline:%s] [auth] 未配置 AuthProxy，跳过权限校验",
                         ctx.pipeline_id)
            return ctx

        # 从模板和用户输入构建权限检查上下文
        auth_context = self._build_auth_context(ctx)

        try:
            allowed, reason = self.auth_proxy.check_permission(
                auth_context,
                required_permission=Permission.READ,
            )

            ctx.metadata["auth_allowed"] = allowed
            ctx.metadata["auth_reason"] = reason

            if allowed:
                # 记录审计日志：允许
                self.auth_proxy.audit_log(AuditEntry(
                    event=AuditEvent.PERMISSION_CHECK,
                    subject=auth_context.get("subject", "unknown"),
                    action=auth_context.get("action", "query"),
                    resource=ctx.template.name,
                    result="allowed",
                    detail=f"权限校验通过: {reason}",
                ))
                logger.info("[Pipeline:%s] [auth] ✅ 权限校验通过: %s",
                            ctx.pipeline_id, reason)
            else:
                # 记录审计日志：拒绝
                self.auth_proxy.audit_log(AuditEntry(
                    event=AuditEvent.PERMISSION_CHECK,
                    subject=auth_context.get("subject", "unknown"),
                    action=auth_context.get("action", "query"),
                    resource=ctx.template.name,
                    result="denied",
                    detail=f"权限被拒绝: {reason}",
                ))
                logger.warning("[Pipeline:%s] [auth] ❌ 权限被拒绝: %s",
                               ctx.pipeline_id, reason)
                ctx.record_error(PipelineStage.AUTH, f"权限校验失败: {reason}")

                # 根据降级策略决定行为
                if not self.degrade_on_auth_failure:
                    # 严格模式：直接抛出异常
                    raise PermissionError(f"权限校验失败: {reason}")

        except PermissionError:
            # 严格模式下的拒绝 → 向上传播
            raise
        except Exception as e:
            # auth_proxy 内部异常 → 记录并降级
            ctx.record_error(PipelineStage.AUTH,
                             f"权限校验组件异常: {e}", exception=e)
            logger.error("[Pipeline:%s] [auth] AuthProxy 异常: %s",
                         ctx.pipeline_id, e)

        return ctx

    # ------------------------------------------------------------------
    # 5b. 阶段处理器: 渐进式查询
    # ------------------------------------------------------------------

    def _step_progressive_query(self, ctx: QueryContext) -> QueryContext:
        """
        阶段 2: 渐进式查询 — 通过四层漏斗获取查询结果。

        流程：
          CACHE（命中→直接返回）→ COARSE_FILTER（粗筛 1000 条）
          → FINE_RERANK（精排 50 条）→ GENERATE（LLM 生成 Top-5）

        降级策略：
          如果查询失败 → 根据 degrade_on_query_failure 决定行为
          如果返回缓存结果 → 标记 cache_hit=True

        类比：
          - Elasticsearch 的 Query → Recall → Rescore → Response 流程
          - CDN 的 Edge Cache → Origin Fetch 策略
        """
        # 从用户输入构建查询文本
        query_text = self._build_query_text(ctx)

        if not query_text:
            ctx.record_error(PipelineStage.PROGRESSIVE_QUERY,
                             "无法从用户输入构建查询文本，用户输入为空")
            return ctx

        try:
            # 使用 QueryGuardian 的 ask() 方法——它会自动应用五层防护
            response: DegradedResponse = self.guardian.ask(
                query_text=query_text,
                source=ctx.template.name,
                metadata={"pipeline_id": ctx.pipeline_id},
            )

            # 将查询结果存入上下文
            ctx.query_results = {
                "answer": response.answer,
                "is_degraded": response.is_degraded,
                "degradation_level": response.level.name if response.level else None,
                "partial_results": response.partial_results,
                "original_query": response.original_query,
            }

            ctx.metadata["query_degraded"] = response.is_degraded
            ctx.metadata["query_level"] = response.level.name if response.level else "UNKNOWN"

            if response.is_degraded:
                logger.warning(
                    "[Pipeline:%s] [query] ⚠️ 查询降级 (级别=%s): %s",
                    ctx.pipeline_id, response.level.name, response.degrade_reason
                )
                if not self.degrade_on_query_failure:
                    ctx.record_error(PipelineStage.PROGRESSIVE_QUERY,
                                     f"查询结果降级: {response.degrade_reason}")
            else:
                logger.info("[Pipeline:%s] [query] ✅ 查询成功，回答长度=%d 字符",
                            ctx.pipeline_id, len(response.answer))

        except Exception as e:
            ctx.record_error(PipelineStage.PROGRESSIVE_QUERY,
                             f"渐进查询异常: {e}", exception=e)
            logger.error("[Pipeline:%s] [query] 异常: %s",
                         ctx.pipeline_id, e, exc_info=True)
            # 查询失败不中断管道——后续阶段使用空结果继续

        return ctx

    # ------------------------------------------------------------------
    # 5c. 阶段处理器: 精准采集
    # ------------------------------------------------------------------

    def _step_precision_collect(self, ctx: QueryContext) -> QueryContext:
        """
        阶段 3: 精准采集 — 从查询结果中抽取结构化字段。

        流程：
          1. 从模板的 query_sources 中提取采集规则
          2. 遍历每个 QuerySource，对原始查询结果施加 schema 抽取
          3. 合并多个数据源的采集结果

        降级策略：
          如果采集失败 → 根据 degrade_on_collect_failure 决定行为
          如果无查询结果 → 跳过采集阶段

        类比：
          - ETL 流程中的 Extract 阶段
          - Scrapy 的 Item Pipeline——从 HTML 中抽取结构化字段
          - GraphQL 的 resolver——从数据源中按 schema 拾取字段
        """
        # 如果没有查询结果，跳过采集
        if ctx.query_results is None:
            ctx.metadata["collect_skipped"] = True
            ctx.metadata["collect_skip_reason"] = "no_query_results"
            logger.debug("[Pipeline:%s] [collect] 无查询结果，跳过精准采集",
                         ctx.pipeline_id)
            return ctx

        # 从模板和查询结果中获取待采集的数据源
        collected: Dict[str, Any] = {}
        collect_sources = self._prepare_collect_sources(ctx)

        if not collect_sources:
            ctx.metadata["collect_skipped"] = True
            ctx.metadata["collect_skip_reason"] = "no_collect_sources"
            logger.debug("[Pipeline:%s] [collect] 无采集数据源，跳过精准采集",
                         ctx.pipeline_id)
            return ctx

        for source_name, source_info in collect_sources.items():
            try:
                source_data = source_info.get("data")
                source_type = source_info.get("type", "auto")
                fields_def = source_info.get("fields", [])

                if source_data is None or not fields_def:
                    continue

                # 使用 PrecisionCollector 的 quick_collect 进行快速采集
                result = quick_collect(
                    source=source_data,
                    fields=fields_def,
                    source_type=source_type,
                )
                collected[source_name] = result
                logger.debug("[Pipeline:%s] [collect] 数据源 '%s' 采集成功，字段数=%d",
                             ctx.pipeline_id, source_name, len(result))

            except Exception as e:
                ctx.record_error(
                    PipelineStage.PRECISION_COLLECT,
                    f"数据源 '{source_name}' 采集失败: {e}",
                    exception=e,
                )
                logger.warning("[Pipeline:%s] [collect] 数据源 '%s' 采集异常: %s",
                               ctx.pipeline_id, source_name, e)
                if not self.degrade_on_collect_failure:
                    # 严格模式：标记但继续
                    pass
                # 继续处理下一个数据源
                continue

        ctx.collected_data = collected if collected else None
        ctx.metadata["collect_source_count"] = len(collect_sources)
        ctx.metadata["collect_success_count"] = len(collected)

        if collected:
            logger.info("[Pipeline:%s] [collect] ✅ 采集完成，成功 %d/%d 个数据源",
                        ctx.pipeline_id, len(collected), len(collect_sources))
        else:
            logger.warning("[Pipeline:%s] [collect] ⚠️ 所有数据源采集均失败",
                           ctx.pipeline_id)

        return ctx

    # ------------------------------------------------------------------
    # 5d. 阶段处理器: 算法房间
    # ------------------------------------------------------------------

    def _step_algorithm_room(self, ctx: QueryContext) -> QueryContext:
        """
        阶段 4: 算法房间 — 执行模板中定义的算法步骤流水线。

        流程：
          1. 获取算法房间配置（来自模板）
          2. 将查询结果 + 采集数据合并为输入
          3. 逐步骤执行：merge → rank → filter → transform → aggregate → llm_summarize
          4. 每步的输出是下一步的输入（Unix pipe 模型）

        降级策略：
          单步骤失败 → 跳过该步骤，保留上一步结果继续
          所有步骤失败 → algorithm_output = 原始输入

        类比：
          - Unix pipe: cat data | grep ... | sort | uniq -c | head
          - scikit-learn Pipeline: [StandardScaler(), PCA(), LogisticRegression()]
          - RxJS pipe: of(data).pipe(map(...), filter(...), reduce(...))
          - Airflow DAG 的任务链
        """
        # 获取算法房间配置
        algorithm_room: AlgorithmRoom = ctx.template.algorithm_room

        if not algorithm_room.steps:
            ctx.metadata["algorithm_skipped"] = True
            ctx.metadata["algorithm_skip_reason"] = "no_steps_configured"
            logger.debug("[Pipeline:%s] [algorithm] 模板未配置算法步骤，跳过算法房间",
                         ctx.pipeline_id)
            # 无算法步骤时，直接将采集数据作为算法输出
            ctx.algorithm_output = ctx.collected_data or ctx.query_results
            return ctx

        # 准备算法房间的输入数据（合并查询结果 + 采集数据）
        algo_input = self._prepare_algorithm_input(ctx)

        current_data = algo_input
        executed_steps = 0
        failed_steps = 0

        for i, step in enumerate(algorithm_room.steps):
            try:
                logger.debug("[Pipeline:%s] [algorithm] 执行步骤 %d/%d: %s",
                             ctx.pipeline_id, i + 1, len(algorithm_room.steps),
                             step.type.value)
                current_data = self._execute_algorithm_step(
                    step=step,
                    data=current_data,
                    ctx=ctx,
                    step_index=i,
                )
                executed_steps += 1
            except Exception as e:
                failed_steps += 1
                ctx.record_error(
                    PipelineStage.ALGORITHM_ROOM,
                    f"算法步骤 {i+1} '{step.type.value}' 执行失败: {e}",
                    exception=e,
                )
                logger.warning(
                    "[Pipeline:%s] [algorithm] 步骤 %d '%s' 失败，跳过: %s",
                    ctx.pipeline_id, i + 1, step.type.value, e
                )
                # 继续执行下一步——当前数据不变

        ctx.algorithm_output = current_data
        ctx.metadata["algorithm_steps_total"] = len(algorithm_room.steps)
        ctx.metadata["algorithm_steps_executed"] = executed_steps
        ctx.metadata["algorithm_steps_failed"] = failed_steps

        logger.info(
            "[Pipeline:%s] [algorithm] ✅ 算法房间完成: %d/%d 步骤成功",
            ctx.pipeline_id, executed_steps, len(algorithm_room.steps)
        )

        return ctx

    # ------------------------------------------------------------------
    # 5e. 阶段处理器: 格式化输出
    # ------------------------------------------------------------------

    def _step_format_output(self, ctx: QueryContext) -> QueryContext:
        """
        阶段 5: 格式化输出 — 将流水线结果对齐模板的 output_schema。

        流程：
          1. 获取模板定义的 output_schema（字段列表）
          2. 从算法输出 / 采集数据 / 查询结果中按 source 路径取值
          3. 对于无法取值的字段，使用 fallback 值
          4. 构建最终的结构化 Dict

        降级策略：
          格式化失败 → 返回原始数据的 JSON 序列化

        类比：
          - GraphQL 的 response shaping——只返回请求的字段
          - SQL 的 SELECT a, b, c FROM ...（列投影）
          - TypeScript 的类型断言: as OutputType
          - Express.js 的 res.json({ ... })——最后的响应序列化
        """
        output_schema: List[OutputField] = ctx.template.output_schema
        formatted: Dict[str, Any] = {}

        if not output_schema:
            # 无 schema → 返回算法输出的原样（或空对象）
            ctx.formatted_output = (
                ctx.algorithm_output
                if isinstance(ctx.algorithm_output, dict)
                else {"result": ctx.algorithm_output}
            )
            ctx.metadata["format_used_schema"] = False
            logger.debug("[Pipeline:%s] [format] 无 output_schema，返回原始输出",
                         ctx.pipeline_id)
            return ctx

        # 构建取值源：算法输出 > 采集数据 > 查询结果
        value_source = ctx.algorithm_output or ctx.collected_data or {}
        if isinstance(value_source, dict):
            # 将查询结果也合并进去作为后备
            if isinstance(ctx.query_results, dict):
                value_source = {**ctx.query_results, **value_source}
        else:
            value_source = {"_raw": value_source}

        try:
            for field in output_schema:
                value = self._resolve_field_value(field, value_source)
                formatted[field.name] = value

            ctx.formatted_output = formatted
            ctx.metadata["format_used_schema"] = True
            ctx.metadata["format_field_count"] = len(output_schema)
            logger.info("[Pipeline:%s] [format] ✅ 格式化完成，输出 %d 个字段",
                        ctx.pipeline_id, len(formatted))

        except Exception as e:
            ctx.record_error(PipelineStage.FORMAT_OUTPUT,
                             f"格式化输出异常: {e}", exception=e)
            logger.error("[Pipeline:%s] [format] 异常: %s",
                         ctx.pipeline_id, e, exc_info=True)
            # 降级：返回原始数据
            ctx.formatted_output = {
                "_degraded": True,
                "_raw": str(value_source)[:2000],
            }

        return ctx

    # ------------------------------------------------------------------
    # 辅助方法: 构建权限校验上下文
    # ------------------------------------------------------------------

    def _build_auth_context(self, ctx: QueryContext) -> Dict[str, Any]:
        """
        从模板和用户输入构建 AuthProxy 所需的权限检查上下文。

        模板的 query_sources 中可能包含 domain / api_endpoint 等信息，
        这些信息被提取出来构成权限检查的依据。

        类比：
          - Express.js 从 req 中提取 JWT token、API key
          - AWS SigV4 从请求中提取 Host、X-Amz-Target 等签名要素
        """
        auth_ctx: Dict[str, Any] = {
            "action": "query_execute",
            "subject": ctx.user_input.get("subject",
                        ctx.metadata.get("subject", "anonymous")),
            "scope": f"execute:{ctx.template.name}",
        }

        # 从第一个 query_source 推断 domain / endpoint
        if ctx.template.query_sources:
            first_source = ctx.template.query_sources[0]
            if first_source.endpoint:
                auth_ctx["domain"] = first_source.endpoint
                auth_ctx["api_endpoint"] = first_source.endpoint
            if hasattr(first_source, "params") and isinstance(first_source.params, dict):
                if "table" in first_source.params:
                    auth_ctx["table"] = first_source.params["table"]

        # 合并用户输入中的认证字段
        for key in ("api_key", "token", "subject", "scope"):
            if key in ctx.user_input:
                auth_ctx[key] = ctx.user_input[key]

        return auth_ctx

    # ------------------------------------------------------------------
    # 辅助方法: 构建查询文本
    # ------------------------------------------------------------------

    def _build_query_text(self, ctx: QueryContext) -> str:
        """
        从用户输入中提取/构建查询文本。

        优先级：
          1. user_input["query"]    — 显式的查询字段
          2. user_input["question"] — 备选键名
          3. 所有输入值的拼接      — 兜底

        类比：
          - Express.js 的 req.body 解析
          - GraphQL 的 query 参数提取
        """
        # 优先使用显式的 query 字段
        if "query" in ctx.user_input and ctx.user_input["query"]:
            return str(ctx.user_input["query"])

        if "question" in ctx.user_input and ctx.user_input["question"]:
            return str(ctx.user_input["question"])

        # 兜底：拼接所有非空字符串输入
        parts = []
        for key, value in ctx.user_input.items():
            if isinstance(value, str) and value.strip():
                parts.append(f"{key}: {value}")
        return " | ".join(parts) if parts else ""

    # ------------------------------------------------------------------
    # 辅助方法: 准备采集数据源
    # ------------------------------------------------------------------

    def _prepare_collect_sources(self, ctx: QueryContext) -> Dict[str, Dict[str, Any]]:
        """
        从查询结果和模板中提取待采集的数据源。

        返回格式：
          {
            "source_name": {
              "data": <原始数据>,
              "type": "json" | "html" | "api" | "auto",
              "fields": [ { "field_name": "...", "selector": "...", "type": "..." } ]
            }
          }

        类比：
          - ETL 工具的 source configuration
          - Scrapy Spider 的 start_requests()
        """
        sources: Dict[str, Dict[str, Any]] = {}

        # 从查询结果中提取可采集的数据
        if isinstance(ctx.query_results, dict):
            # 将 partial_results 作为采集目标（如果有的话）
            partial = ctx.query_results.get("partial_results")
            if partial is not None:
                sources["query_results"] = {
                    "data": partial,
                    "type": "json",
                    "fields": self._extract_fields_from_output_schema(ctx),
                }

            # 将完整 answer 也作为一个采集源
            answer = ctx.query_results.get("answer")
            if answer is not None and answer:
                sources["answer_text"] = {
                    "data": answer,
                    "type": "auto",
                    "fields": [
                        {"field_name": "answer", "selector": "answer", "type": "str"}
                    ],
                }

        # 如果查询结果非 dict（如列表），直接作为采集源
        elif ctx.query_results is not None:
            sources["query_results_raw"] = {
                "data": ctx.query_results,
                "type": "auto",
                "fields": self._extract_fields_from_output_schema(ctx),
            }

        return sources

    # ------------------------------------------------------------------
    # 辅助方法: 从 output_schema 提取字段定义（供精准采集使用）
    # ------------------------------------------------------------------

    def _extract_fields_from_output_schema(self, ctx: QueryContext) -> List[Dict[str, Any]]:
        """
        将模板的 output_schema 转为 PrecisionCollector 兼容的字段定义。

        类比：
          - GraphQL schema → SQL SELECT columns 的转换
          - OpenAPI schema → form field 的转换
        """
        fields = []
        for field in ctx.template.output_schema:
            fields.append({
                "field_name": field.name,
                "selector": field.source.split(".")[-1] if field.source else field.name,
                "type": field.type,
                "default": field.fallback,
                "description": field.description,
            })
        return fields

    # ------------------------------------------------------------------
    # 辅助方法: 准备算法房间输入
    # ------------------------------------------------------------------

    def _prepare_algorithm_input(self, ctx: QueryContext) -> Any:
        """
        合并查询结果和采集数据，作为算法房间的输入。

        策略：
          - 优先使用采集数据（更结构化）
          - 其次使用查询结果
          - 两者都有时合并

        类比：
          - SQL 的 JOIN / UNION 操作前的数据准备
          - Python 的 {**dict1, **dict2} 合并
        """
        # 采集数据优先（更结构化）
        if ctx.collected_data is not None:
            return ctx.collected_data

        # 其次使用查询结果
        if ctx.query_results is not None:
            return ctx.query_results

        # 都没有 → 使用用户输入
        return ctx.user_input

    # ------------------------------------------------------------------
    # 辅助方法: 执行单个算法步骤
    # ------------------------------------------------------------------

    def _execute_algorithm_step(
        self,
        step: AlgorithmStep,
        data: Any,
        ctx: QueryContext,
        step_index: int,
    ) -> Any:
        """
        执行算法房间中的单个步骤。

        每个步骤类型对应一种数据操作：

          MERGE        — 多源结果合并（类似 SQL JOIN / UNION）
          RANK         — 结果排序/重排序
          FILTER       — 后置过滤
          TRANSFORM    — 格式转换
          AGGREGATE    — 聚合（计数、求和、平均）
          LLM_SUMMARIZE — LLM 总结

        类比：
          - RxJS operators: mergeMap, filter, map, reduce
          - Python itertools: chain, filter, map
          - SQL: JOIN, WHERE, ORDER BY, GROUP BY
        """
        algo_type = step.type
        config = step.config

        if algo_type == AlgorithmType.MERGE:
            return self._algo_merge(data, config)

        elif algo_type == AlgorithmType.RANK:
            return self._algo_rank(data, config)

        elif algo_type == AlgorithmType.FILTER:
            return self._algo_filter(data, config)

        elif algo_type == AlgorithmType.TRANSFORM:
            return self._algo_transform(data, config)

        elif algo_type == AlgorithmType.AGGREGATE:
            return self._algo_aggregate(data, config)

        elif algo_type == AlgorithmType.LLM_SUMMARIZE:
            return self._algo_llm_summarize(data, config, ctx)

        else:
            logger.warning("[Pipeline:%s] [algorithm] 未知算法类型: %s，跳过",
                           ctx.pipeline_id, algo_type)
            return data

    # ---- 各算法实现 ----

    def _algo_merge(self, data: Any, config: Dict[str, Any]) -> Any:
        """
        MERGE 步骤：合并多个来源的数据。

        config 键：
          strategy : str — "concat" / "extend" / "zip"
          sources  : List[str] — 待合并的源键名（可选）

        类比：Python 的 list.extend() 或 dict.update()
        """
        strategy = config.get("strategy", "concat")

        if not isinstance(data, dict):
            return data

        if strategy == "extend":
            # 将所有子 dict 合并为一个 dict
            merged: Dict[str, Any] = {}
            for key, value in data.items():
                if isinstance(value, dict):
                    merged.update(value)
                else:
                    merged[key] = value
            return merged

        elif strategy == "zip":
            # 将并列的列表 zip 在一起
            lists = [v for v in data.values() if isinstance(v, list)]
            if not lists:
                return data
            min_len = min(len(lst) for lst in lists)
            return [dict(zip(data.keys(), items)) for items in zip(*[lst[:min_len] for lst in lists])]

        else:  # concat（默认）
            return data

    def _algo_rank(self, data: Any, config: Dict[str, Any]) -> Any:
        """
        RANK 步骤：对结果排序。

        config 键：
          by       : str   — 排序字段
          order    : str   — "asc" / "desc"（默认 "desc"）
          limit    : int   — 保留 Top-K（可选）

        类比：SQL 的 ORDER BY ... DESC LIMIT K
        """
        sort_by = config.get("by", "")
        reverse = config.get("order", "desc") == "desc"
        limit = config.get("limit")

        # 尝试从 data 中提取可排序的列表
        items = self._extract_sortable_list(data)

        if not items or not sort_by:
            return data

        try:
            sorted_items = sorted(
                items,
                key=lambda x: (x.get(sort_by, 0) if isinstance(x, dict) else 0),
                reverse=reverse,
            )
            if limit and isinstance(limit, int) and limit > 0:
                sorted_items = sorted_items[:limit]
            return self._replace_sortable_list(data, sorted_items)
        except Exception:
            return data

    def _algo_filter(self, data: Any, config: Dict[str, Any]) -> Any:
        """
        FILTER 步骤：后置过滤。

        config 键：
          field    : str   — 过滤字段
          operator : str   — "eq" / "ne" / "gt" / "gte" / "lt" / "lte" / "contains"
          value    : Any   — 比较值

        类比：SQL 的 WHERE score >= 0.8
        """
        field = config.get("field", "")
        operator = config.get("operator", "eq")
        target_value = config.get("value")

        items = self._extract_sortable_list(data)
        if not items or not field:
            return data

        filtered = []
        for item in items:
            if not isinstance(item, dict):
                continue
            item_value = item.get(field)
            if self._compare(item_value, operator, target_value):
                filtered.append(item)

        return self._replace_sortable_list(data, filtered)

    def _algo_transform(self, data: Any, config: Dict[str, Any]) -> Any:
        """
        TRANSFORM 步骤：格式转换。

        config 键：
          format : str — "dict_to_list" / "list_to_dict" / "extract_keys"
          keys   : List[str] — 提取的键（extract_keys 时使用）

        类比：Python 的 dict.values() 或 list comprehension
        """
        fmt = config.get("format", "")
        keys = config.get("keys", [])

        if fmt == "dict_to_list" and isinstance(data, dict):
            return list(data.values())

        elif fmt == "list_to_dict" and isinstance(data, list):
            return {str(i): item for i, item in enumerate(data)}

        elif fmt == "extract_keys" and isinstance(data, dict) and keys:
            return {k: data.get(k) for k in keys if k in data}

        return data

    def _algo_aggregate(self, data: Any, config: Dict[str, Any]) -> Any:
        """
        AGGREGATE 步骤：聚合计算。

        config 键：
          func   : str — "count" / "sum" / "avg" / "min" / "max"
          field  : str — 聚合字段

        类比：SQL 的 SELECT COUNT(*), AVG(score) FROM ...
        """
        func_name = config.get("func", "count")
        field = config.get("field", "")

        items = self._extract_sortable_list(data)
        if not items:
            return {"count": 0, "result": None}

        values = []
        for item in items:
            if isinstance(item, dict) and field:
                v = item.get(field)
                if v is not None:
                    try:
                        values.append(float(v))
                    except (ValueError, TypeError):
                        pass

        if func_name == "count":
            return {"count": len(items), "field": field}
        elif func_name == "sum":
            return {"sum": sum(values), "count": len(values), "field": field}
        elif func_name == "avg":
            return {"avg": sum(values) / max(len(values), 1), "count": len(values), "field": field}
        elif func_name == "min":
            return {"min": min(values) if values else None, "count": len(values), "field": field}
        elif func_name == "max":
            return {"max": max(values) if values else None, "count": len(values), "field": field}
        else:
            return data

    def _algo_llm_summarize(self, data: Any, config: Dict[str, Any],
                            ctx: QueryContext) -> Any:
        """
        LLM_SUMMARIZE 步骤：使用 LLM 总结——通过适配器组执行。

        config 键：
          prompt_template : str — 提示词模板
          max_tokens      : int — 最大 token 数

        执行策略：
          1. 优先通过适配器组（AdapterRegistry）调用真实 LLM
          2. 适配器不可用时降级为 Mock 实现
          3. 适配器故障时自动切换到备用适配器（由 UnifiedMonitor 处理）

        类比：LangChain 的 summarize_chain.run()
        """
        # 构建 prompt
        prompt_template = config.get("prompt_template",
                                     "请总结以下内容：\n{data}")
        max_tokens = config.get("max_tokens", 200)

        # 将数据转为字符串
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data, ensure_ascii=False, indent=2)
        else:
            data_str = str(data)

        prompt = prompt_template.replace("{data}", data_str[:4000])

        # ---- 尝试通过适配器组调用 LLM ----
        llm_adapter = self._get_active_llm_adapter()
        if llm_adapter is not None and hasattr(llm_adapter, 'generate'):
            try:
                logger.info(
                    "[Pipeline:%s] [algorithm] 通过适配器 %s 调用 LLM (max_tokens=%d)",
                    ctx.pipeline_id,
                    getattr(llm_adapter, 'adapter_id', 'unknown'),
                    max_tokens,
                )
                response = llm_adapter.generate(
                    prompt=prompt,
                    max_tokens=max_tokens,
                )
                # 适配器返回的可能是一个对象或字符串
                if isinstance(response, dict) and 'text' in response:
                    summary = response['text']
                elif isinstance(response, str):
                    summary = response
                else:
                    summary = str(response)

                return {
                    "summary": summary,
                    "original_length": len(data_str),
                    "is_mock": False,
                    "adapter_id": getattr(llm_adapter, 'adapter_id', 'unknown'),
                }
            except Exception as e:
                logger.warning(
                    "[Pipeline:%s] [algorithm] 适配器 LLM 调用失败: %s，降级为 mock",
                    ctx.pipeline_id, e,
                )
                # 适配器调用失败 → 降级为 mock 实现
                # 如果是适配器本身的故障，UnifiedMonitor 会在心跳中检测到

        # ---- 降级：Mock 实现（适配器不可用或调用失败时） ----
        logger.info("[Pipeline:%s] [algorithm] LLM summarize (mock, max_tokens=%d)",
                    ctx.pipeline_id, max_tokens)
        summary = (
            f"[LLM 总结 - mock] 输入长度: {len(data_str)} 字符. "
            f"提示词前 100 字: {prompt[:100]}..."
        )

        return {
            "summary": summary,
            "original_length": len(data_str),
            "is_mock": True,
        }

    # ------------------------------------------------------------------
    # 辅助方法: 从数据结构中提取可排序的列表
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_sortable_list(data: Any) -> Optional[List[Any]]:
        """
        从各种数据结构中提取一个可排序/过滤的列表。

        支持：
          - 直接是 list → 返回
          - dict 中有 "items" / "results" / "data" 键 → 返回对应列表
          - dict 的 values 全是 list → 拼接返回

        类比：ORM 的 QuerySet——不管底层是什么，对外暴露统一的列表接口
        """
        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            # 尝试常见键名
            for key in ("items", "results", "data", "records", "rows"):
                val = data.get(key)
                if isinstance(val, list):
                    return val

            # 如果所有 values 都是 list，拼接它们
            lists = [v for v in data.values() if isinstance(v, list)]
            if lists:
                result = []
                for lst in lists:
                    result.extend(lst)
                return result

        return None

    @staticmethod
    def _replace_sortable_list(data: Any, new_list: List[Any]) -> Any:
        """
        将处理后的列表放回原数据结构。

        类比：不可变数据的更新——返回新对象，不修改原数据
        """
        if isinstance(data, list):
            return new_list

        if isinstance(data, dict):
            for key in ("items", "results", "data", "records", "rows"):
                if key in data and isinstance(data[key], list):
                    result = dict(data)
                    result[key] = new_list
                    return result

        # 无法放回 → 直接返回新列表
        return new_list

    @staticmethod
    def _compare(item_value: Any, operator: str, target: Any) -> bool:
        """
        执行比较操作。

        类比：Python 的 operator 模块（operator.eq, operator.gt 等）
        """
        try:
            if operator == "eq":
                return item_value == target
            elif operator == "ne":
                return item_value != target
            elif operator == "gt":
                return float(item_value) > float(target)  # type: ignore[arg-type]
            elif operator == "gte":
                return float(item_value) >= float(target)  # type: ignore[arg-type]
            elif operator == "lt":
                return float(item_value) < float(target)  # type: ignore[arg-type]
            elif operator == "lte":
                return float(item_value) <= float(target)  # type: ignore[arg-type]
            elif operator == "contains":
                return str(target).lower() in str(item_value).lower()
            elif operator == "in":
                if isinstance(target, list):
                    return item_value in target
                return False
            else:
                return item_value == target  # 默认 eq
        except (ValueError, TypeError):
            return False

    # ------------------------------------------------------------------
    # 辅助方法: 字段值解析（对齐 output_schema）
    # ------------------------------------------------------------------

    def _resolve_field_value(self, field: OutputField,
                             source: Dict[str, Any]) -> Any:
        """
        从数据源中按 source 路径解析字段值。

        source 格式："{source_name}.{field_path}"
          例: "query_results.answer" → source["query_results"]["answer"]

        如果解析失败，使用 field.fallback 作为回退值。

        类比：
          - GraphQL resolver 的 parent[fieldName]
          - JSONPath / jq 的字段提取
          - JavaScript 的 lodash.get(obj, path, defaultValue)
        """
        if not field.source:
            return field.fallback

        # 按 "." 分割路径
        parts = field.source.split(".")
        current: Any = source

        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
                if current is None:
                    return field.fallback
            elif isinstance(current, list):
                # 尝试按索引访问
                try:
                    idx = int(part)
                    current = current[idx]
                except (ValueError, IndexError):
                    return field.fallback
            else:
                return field.fallback

        return current if current is not None else field.fallback

    # ------------------------------------------------------------------
    # 辅助方法: 执行自定义步骤
    # ------------------------------------------------------------------

    @staticmethod
    def _execute_steps(ctx: QueryContext, steps: List[PipelineStep],
                       label: str = "") -> QueryContext:
        """
        执行一组自定义中间件步骤。

        类比：
          - Express.js 依次调用 app.use() 注册的中间件
          - Python 的 reduce(lambda ctx, fn: fn(ctx), steps, ctx)
        """
        for i, step in enumerate(steps):
            try:
                ctx = step(ctx)
            except Exception as e:
                ctx.record_error(
                    PipelineStage.FORMAT_OUTPUT,  # 自定义步骤归于 FORMAT 阶段
                    f"自定义{label}步骤 {i+1} 异常: {e}",
                    exception=e,
                )
                logger.warning("[Pipeline:%s] 自定义%s步骤 %d 异常: %s",
                               ctx.pipeline_id, label, i + 1, e)
        return ctx

    # ------------------------------------------------------------------
    # 对话管理便捷方法
    # ------------------------------------------------------------------

    def search_history(self, keyword: str) -> List[Dict[str, Any]]:
        """
        搜索历史对话。

        参数：
          keyword : str — 搜索关键词

        返回：
          List[Dict[str, Any]] — 匹配的对话记录列表

        类比：
          - Slack / Discord 的消息搜索
          - Chrome 浏览历史搜索 (Ctrl+H → 输入关键词)
        """
        if self.conversation_manager is None:
            logger.warning("[QueryOrchestrator] ConversationManager 未安装，无法搜索历史")
            return []
        try:
            return self.conversation_manager.search(keyword)
        except Exception as e:
            logger.error("[QueryOrchestrator] 搜索历史对话失败: %s", e)
            return []

    def list_conversations(self) -> List[Dict[str, Any]]:
        """
        列出所有对话会话。

        返回：
          List[Dict[str, Any]] — 每个 dict 包含 session_id、title、created_at 等

        类比：
          - ChatGPT 的对话列表侧边栏
          - Slack 的频道列表
        """
        if self.conversation_manager is None:
            logger.warning("[QueryOrchestrator] ConversationManager 未安装，无法列出对话")
            return []
        try:
            return self.conversation_manager.list_sessions()
        except Exception as e:
            logger.error("[QueryOrchestrator] 列出对话失败: %s", e)
            return []

    def switch_conversation(self, session_id: str) -> bool:
        """
        切换到指定的对话会话。

        参数：
          session_id : str — 目标会话 ID

        返回：
          bool — 是否切换成功

        类比：
          - ChatGPT 点击对话列表中的某个对话
          - tmux 的 switch-client -t <session>
        """
        if self.conversation_manager is None:
            logger.warning("[QueryOrchestrator] ConversationManager 未安装，无法切换对话")
            return False
        try:
            success = self.conversation_manager.switch_session(session_id)
            if success and self.conversation_listener is not None:
                self.conversation_listener.notify("session_switched", {
                    "session_id": session_id,
                })
            return success
        except Exception as e:
            logger.error("[QueryOrchestrator] 切换对话失败: %s", e)
            return False

    # ==================================================================
    # 适配器管理方法（类比：Kubernetes 的 CSI driver 注册与管理）
    # ==================================================================

    def register_adapter(self, adapter: Any) -> Optional[str]:
        """
        注册新适配器到适配器注册表。

        参数：
          adapter : Any — 适配器实例（需实现 AbstractAdapter 接口）

        返回：
          Optional[str] — 注册成功返回 adapter_id，失败返回 None

        类比：
          - Kubernetes 的 `kubectl apply -f deployment.yaml` → 注册新资源
          - Express.js 的 `app.use()` → 注册中间件
          - Docker 的 `docker plugin install` → 安装新插件
        """
        if self._adapter_registry is None:
            logger.warning("[QueryOrchestrator] AdapterRegistry 未安装，无法注册适配器")
            return None

        try:
            adapter_id = self._adapter_registry.register(adapter)
            logger.info("[QueryOrchestrator] ✅ 适配器已注册: %s", adapter_id)

            # 如果这是第一个 LLM 适配器，自动设为活跃
            if self._active_llm_adapter_id is None and hasattr(adapter, 'adapter_type'):
                adapter_type = getattr(adapter, 'adapter_type', '')
                if 'llm' in str(adapter_type).lower():
                    self._active_llm_adapter_id = adapter_id
                    logger.info("[QueryOrchestrator] 自动设置活跃 LLM 适配器: %s", adapter_id)

            return adapter_id
        except Exception as e:
            logger.error("[QueryOrchestrator] 注册适配器失败: %s", e)
            return None

    def get_active_adapters(self) -> Dict[str, Any]:
        """
        获取当前活跃适配器组（所有已注册的适配器）。

        返回：
          Dict[str, Any] — {adapter_id: adapter_instance}

        类比：
          - Kubernetes 的 `kubectl get pods --all-namespaces`
          - Docker 的 `docker ps` 列出所有运行容器
        """
        if self._adapter_registry is None:
            logger.warning("[QueryOrchestrator] AdapterRegistry 未安装，无活跃适配器")
            return {}

        try:
            return self._adapter_registry.list_all()
        except Exception as e:
            logger.error("[QueryOrchestrator] 获取活跃适配器失败: %s", e)
            return {}

    def switch_llm(self, adapter_id: str) -> bool:
        """
        切换 LLM 适配器——将指定适配器设为当前活跃的 LLM 适配器。

        参数：
          adapter_id : str — 目标适配器 ID

        返回：
          bool — 切换是否成功

        类比：
          - Kubernetes 的 `kubectl set image deployment/xxx` → 滚动更新
          - AWS Route 53 的 DNS failover → 切换流量到备用端点
          - Nginx 的 upstream server 切换
        """
        if self._adapter_registry is None:
            logger.warning("[QueryOrchestrator] AdapterRegistry 未安装，无法切换 LLM 适配器")
            return False

        try:
            # 检查目标适配器是否存在
            all_adapters = self._adapter_registry.list_all()
            if adapter_id not in all_adapters:
                logger.error("[QueryOrchestrator] 适配器 %s 不存在，无法切换", adapter_id)
                return False

            # 检查目标适配器的健康状态
            if self._monitor is not None:
                report = self._monitor.get_health_report()
                adapter_health = report.get("adapters", {}).get(adapter_id, {})
                status = adapter_health.get("status", "unknown")
                if status == "fault":
                    logger.warning(
                        "[QueryOrchestrator] 适配器 %s 处于 FAULT 状态，切换有风险",
                        adapter_id,
                    )

            prev = self._active_llm_adapter_id
            self._active_llm_adapter_id = adapter_id
            logger.info(
                "[QueryOrchestrator] 🔄 LLM 适配器切换: %s → %s",
                prev or "(none)", adapter_id,
            )
            return True
        except Exception as e:
            logger.error("[QueryOrchestrator] 切换 LLM 适配器失败: %s", e)
            return False

    def get_adapter_health(self) -> Dict[str, Any]:
        """
        获取适配器健康报告（委托给 UnifiedMonitor）。

        返回：
          Dict[str, Any] — 与 UnifiedMonitor.get_health_report() 相同结构

        类比：
          - Kubernetes 的 `kubectl top nodes` → 节点资源使用
          - AWS CloudWatch 的 health dashboard
          - Datadog 的 Service Health 视图
        """
        if self._monitor is not None:
            try:
                return self._monitor.get_health_report()
            except Exception as e:
                logger.error("[QueryOrchestrator] 获取适配器健康报告失败: %s", e)
                return {"error": str(e), "total_adapters": 0}

        # 降级：返回空报告
        return {
            "timestamp": "",
            "total_adapters": 0,
            "healthy_count": 0,
            "degraded_count": 0,
            "fault_count": 0,
            "unknown_count": 0,
            "adapters": {},
            "recent_events_count": 0,
            "_note": "UnifiedMonitor 未安装",
        }

    # ------------------------------------------------------------------
    # 适配器内部方法
    # ------------------------------------------------------------------

    def _register_default_adapters(self) -> None:
        """
        注册默认适配器（MockAdapter + APIAdapter）。

        在 __init__ 中调用，仅在 AdapterRegistry 可用时执行。

        类比：
          - Kubernetes 内置的默认 admission controllers
          - Express.js 内置的 body-parser 中间件
          - AWS 默认 VPC 的默认安全组
        """
        if self._adapter_registry is None:
            return

        # 尝试注册 MockAdapter（测试/降级用）
        try:
            from adapter_mock import MockAdapter
            mock = MockAdapter()
            self._adapter_registry.register(mock)
            logger.debug("[QueryOrchestrator] 默认适配器已注册: MockAdapter")
        except ImportError:
            logger.debug("[QueryOrchestrator] MockAdapter 未安装，跳过")
        except Exception as e:
            logger.warning("[QueryOrchestrator] MockAdapter 注册失败: %s", e)

        # 尝试注册 APIAdapter（通用 API 调用适配器）
        try:
            from adapter_api import APIAdapter
            api = APIAdapter()
            self._adapter_registry.register(api)
            logger.debug("[QueryOrchestrator] 默认适配器已注册: APIAdapter")
        except ImportError:
            logger.debug("[QueryOrchestrator] APIAdapter 未安装，跳过")
        except Exception as e:
            logger.warning("[QueryOrchestrator] APIAdapter 注册失败: %s", e)

    def _on_adapter_fault_handler(self, event: Any) -> None:
        """
        适配器故障回调——当 UnifiedMonitor 检测到适配器进入 FAULT 状态时调用。

        行为：
          1. 打印告警日志
          2. 如果故障适配器是当前活跃的 LLM 适配器，自动触发切换

        参数：
          event : AdapterEvent — 故障事件

        类比：
          - Kubernetes 的 Event 处理：NodeUnreachable → 驱逐 Pod
          - AWS Auto Scaling 的 lifecycle hook
        """
        adapter_id = getattr(event, 'adapter_id', 'unknown')
        message = getattr(event, 'message', '')
        logger.warning(
            "[QueryOrchestrator] 🔔 适配器故障告警: %s — %s", adapter_id, message
        )

        # 如果故障适配器正是当前活跃的 LLM 适配器，尝试切换到备用
        if adapter_id == self._active_llm_adapter_id:
            logger.warning(
                "[QueryOrchestrator] 活跃 LLM 适配器 %s 故障，尝试自动切换...",
                adapter_id,
            )
            # UnifiedMonitor 的 auto_switch_on_fault() 已处理切换
            # 这里仅做额外清理：清除活跃适配器引用
            self._active_llm_adapter_id = None
            # 尝试从健康适配器中选一个作为新活跃
            healthy = self._adapter_registry.list_all() if self._adapter_registry else {}
            for aid in healthy:
                if aid != adapter_id:
                    self._active_llm_adapter_id = aid
                    logger.info(
                        "[QueryOrchestrator] ✅ 自动切换到备用 LLM 适配器: %s", aid
                    )
                    break

    def _get_active_llm_adapter(self) -> Optional[Any]:
        """
        获取当前活跃的 LLM 适配器实例。

        返回：
          Optional[Any] — 适配器实例，无可用适配器时返回 None

        类比：
          - Kubernetes Service 的 endpoint 选择——选一个健康的后端
        """
        if self._adapter_registry is None:
            return None

        # 如果有明确设置的活跃适配器，使用它
        if self._active_llm_adapter_id:
            try:
                all_adapters = self._adapter_registry.list_all()
                adapter = all_adapters.get(self._active_llm_adapter_id)
                if adapter is not None:
                    return adapter
            except Exception:
                pass

        # 否则返回第一个可用的适配器
        try:
            all_adapters = self._adapter_registry.list_all()
            for aid, adapter in all_adapters.items():
                if hasattr(adapter, 'adapter_type'):
                    atype = str(getattr(adapter, 'adapter_type', ''))
                    if 'llm' in atype.lower():
                        self._active_llm_adapter_id = aid
                        return adapter
            # 没有 LLM 类型的适配器，返回第一个
            if all_adapters:
                first_id = next(iter(all_adapters))
                self._active_llm_adapter_id = first_id
                return all_adapters[first_id]
        except Exception as e:
            logger.warning("[QueryOrchestrator] 查找 LLM 适配器失败: %s", e)

        return None


# ============================================================================
# 6. 便捷函数 — 快速使用编排器
# ============================================================================

def quick_execute(
    template: AITemplate,
    user_input: Dict[str, Any],
    *,
    auth_proxy: Optional[AuthProxy] = None,
) -> Dict[str, Any]:
    """
    一行代码执行查询管道（不持久化编排器实例）。

    参数：
      template   : AITemplate      — AI 查询模板
      user_input : Dict[str, Any]  — 用户输入
      auth_proxy : AuthProxy       — 权限代理（可选）

    返回：
      Dict[str, Any] — 结构化输出（与 QueryOrchestrator.execute() 相同）

    使用方式：
      result = quick_execute(template, {"query": "蓝牙耳机降噪推荐"})
      print(result["data"])

    类比：
      - Express.js 的单个路由处理: app.post("/search", handler)
      - Python requests 库的 requests.get()——无需手动管理 Session
    """
    orchestrator = QueryOrchestrator(auth_proxy=auth_proxy)
    orchestrator.start()
    try:
        return orchestrator.execute(template, user_input)
    finally:
        orchestrator.stop()


def quick_execute_sync(
    template: AITemplate,
    user_input: Dict[str, Any],
    *,
    auth_proxy: Optional[AuthProxy] = None,
) -> Dict[str, Any]:
    """
    quick_execute 的别名（语义更明确）。

    类比：requests.get() ≈ quick_execute_sync()
    """
    return quick_execute(template, user_input, auth_proxy=auth_proxy)


# ============================================================================
# 7. 自测
# ============================================================================

if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print("=" * 60)
    print("Query Orchestrator — 查询编排器自测")
    print("=" * 60)

    # ---- 构建测试模板 ----
    from template_engine import (
        AITemplate, InputField, InputType,
        QuerySource, QuerySourceType,
        OutputField, AlgorithmRoom, AlgorithmStep, AlgorithmType,
    )

    test_template = AITemplate(
        name="test_search",
        version="1.0.0",
        description="测试用搜索引擎模板",
        inputs=[
            InputField(
                name="query",
                type=InputType.STRING,
                required=True,
                description="搜索关键词",
                examples=["蓝牙耳机", "机械键盘"],
            ),
        ],
        query_sources=[
            QuerySource(
                name="vector_search",
                type=QuerySourceType.VECTOR_DB,
                endpoint="localhost:19530",
                params={"top_k": 10, "metric": "cosine"},
            ),
        ],
        output_schema=[
            OutputField(
                name="title",
                type="string",
                source="query_results.title",
                description="结果标题",
                fallback="未知标题",
            ),
            OutputField(
                name="score",
                type="number",
                source="query_results.score",
                description="相关性分数",
                fallback=0.0,
            ),
        ],
        algorithm_room=AlgorithmRoom(
            steps=[
                AlgorithmStep(
                    type=AlgorithmType.FILTER,
                    config={"field": "score", "operator": "gte", "value": 0.5},
                    description="过滤低分结果",
                ),
                AlgorithmStep(
                    type=AlgorithmType.RANK,
                    config={"by": "score", "order": "desc", "limit": 5},
                    description="按分数降序排列取 Top-5",
                ),
            ],
            merge_strategy="concat",
        ),
    )

    # ---- 创建编排器 ----
    orchestrator = QueryOrchestrator()
    orchestrator.start()

    print("\n📋 模板:", test_template.name, "v" + test_template.version)
    print("📥 输入:", {"query": "蓝牙耳机降噪推荐"})

    # ---- 执行 ----
    result = orchestrator.execute(
        test_template,
        {"query": "蓝牙耳机降噪推荐"},
    )

    print("\n📤 输出:")
    print(json.dumps(result, ensure_ascii=False, indent=2))

    orchestrator.stop()
    print("\n✅ 自测完成")
