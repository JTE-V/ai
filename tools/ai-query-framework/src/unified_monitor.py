"""
统一监听器 — Unified Monitor
=============================
持续监控所有已注册适配器的健康状态，自动感知适配器增删，
在故障时触发自动切换，提供统一的事件流和健康报告。

核心职责：
  1. 关联 AdapterRegistry，自动感知适配器的注册/注销
  2. watch_all() — 开始监控所有已注册适配器（心跳检测）
  3. get_health_report() — 汇总所有适配器健康状态（结构化 Dict）
  4. get_event_stream() — 获取最近 N 条事件
  5. on_adapter_fault(callback) — 注册故障回调
  6. auto_switch_on_fault() — 适配器故障时自动切换到备用适配器

监控指标：
  - 每个适配器的健康状态（healthy / degraded / fault）
  - 故障次数和恢复次数
  - 平均响应时间
  - 最后心跳时间

类比：
  - Kubernetes 的 controller manager — 持续监控 + 自动修复
  - AWS Auto Scaling Group 的健康检查（Health Check）
  - Prometheus 的 alertmanager — 规则评估 + 告警触发
  - Docker Swarm 的 healthcheck — 周期性探测容器状态
  - Nginx 的 upstream health checks — 后端节点健康监控

设计原则：
  - 非侵入式：心跳检测在后台线程运行，不阻塞主流程
  - 容错：即使 AdapterRegistry 不可用，监控器仍能降级运行
  - 事件驱动：状态变更即时记录为 AdapterEvent
"""

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# 可选依赖：AdapterRegistry（若模块缺失则降级为空操作）
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

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ============================================================================
# 1. 健康状态枚举
# ============================================================================

class HealthStatus(Enum):
    """
    适配器健康状态枚举。

    状态转换图：
      HEALTHY ──(连续故障)──▶ DEGRADED ──(持续故障)──▶ FAULT
        ▲                        │                        │
        └────(恢复)──────────────└────(恢复)──────────────┘

    类比：
      - Kubernetes Pod 的 Ready / NotReady / CrashLoopBackOff
      - AWS ELB 健康检查的 healthy / unhealthy / draining
      - Datadog 监控的 OK / WARN / CRITICAL
    """
    HEALTHY = "healthy"          # 健康：响应正常
    DEGRADED = "degraded"        # 降级：偶发故障，仍可工作
    FAULT = "fault"              # 故障：连续失败，需要切换
    UNKNOWN = "unknown"          # 未知：尚未进行首次心跳检测


# ============================================================================
# 2. AdapterEvent — 适配器事件
# ============================================================================

@dataclass
class AdapterEvent:
    """
    适配器运行时事件——一次状态变化或操作记录。

    字段说明：
      event_id     : str          — 全局唯一事件 ID
      adapter_id   : str          — 关联的适配器 ID
      event_type   : str          — 事件类型（见 AdapterEventType）
      timestamp    : datetime     — 事件发生时间（UTC）
      old_status   : HealthStatus — 变化前的健康状态（可选）
      new_status   : HealthStatus — 变化后的健康状态
      message      : str          — 人类可读的描述
      metadata     : Dict         — 扩展元数据（响应时间、错误详情等）

    类比：
      - Kubernetes Event：{ reason: "Started", message: "Started container" }
      - AWS CloudTrail 事件：记录了 "谁在何时做了什么"
      - GitHub Webhook 的 event payload
    """
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    adapter_id: str = ""
    event_type: str = "status_change"  # status_change / fault / recovery / heartbeat
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    old_status: Optional["HealthStatus"] = None
    new_status: Optional["HealthStatus"] = None
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转为可序列化的字典。类比：JSON.stringify(event)。"""
        return {
            "event_id": self.event_id,
            "adapter_id": self.adapter_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "old_status": self.old_status.value if self.old_status else None,
            "new_status": self.new_status.value if self.new_status else None,
            "message": self.message,
            "metadata": self.metadata,
        }


# ============================================================================
# 3. AdapterHealth — 单个适配器的健康快照
# ============================================================================

@dataclass
class AdapterHealth:
    """
    单个适配器的健康快照——在健康报告中每个适配器一条。

    类比：
      - Kubernetes Pod status 字段
      - AWS EC2 实例的 status check（2/2 checks passed）
      - Docker 容器的 Health Status（healthy 3 minutes ago）
    """
    adapter_id: str = ""
    status: HealthStatus = HealthStatus.UNKNOWN
    fault_count: int = 0              # 累计故障次数
    recovery_count: int = 0           # 累计恢复次数
    avg_response_time_ms: float = 0.0 # 平均响应时间（毫秒）
    last_heartbeat: Optional[datetime] = None  # 最后心跳时间
    last_error: Optional[str] = None  # 最后一次错误信息
    consecutive_failures: int = 0     # 连续故障次数（恢复后归零）

    def to_dict(self) -> Dict[str, Any]:
        """转为可序列化的字典。"""
        return {
            "adapter_id": self.adapter_id,
            "status": self.status.value,
            "fault_count": self.fault_count,
            "recovery_count": self.recovery_count,
            "avg_response_time_ms": round(self.avg_response_time_ms, 2),
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "last_error": self.last_error,
            "consecutive_failures": self.consecutive_failures,
        }


# ============================================================================
# 4. UnifiedMonitor — 统一监听器主体
# ============================================================================

class UnifiedMonitor:
    """
    统一监听器——持续监控所有已注册适配器的健康状态。

    核心职责：
      1. 关联 AdapterRegistry，自动感知适配器的注册/注销
      2. 周期性心跳检测（默认 10 秒）
      3. 状态变化时自动触发故障回调
      4. 适配器故障时自动切换到备用适配器
      5. 提供统一的事件流和健康报告

    使用方式：
      monitor = UnifiedMonitor(
          registry=adapter_registry,
          heartbeat_interval=10.0,
          fault_threshold=3,       # 连续 3 次失败→FAULT
          auto_switch=True,
      )
      monitor.watch_all()
      # ... 运行一段时间 ...
      report = monitor.get_health_report()
      events = monitor.get_event_stream(limit=50)

    类比：
      - Kubernetes 的 controller manager：
        * ReplicaSet controller → 确保 Pod 数量符合期望
        * Node controller → 监控节点状态，驱逐不健康节点
        * 本类 → 监控适配器状态，切换故障适配器
      - AWS Auto Scaling Group 的健康检查
      - Prometheus + AlertManager 的规则评估 + 告警
    """

    # ------------------------------------------------------------------
    # 初始化
    # ------------------------------------------------------------------

    def __init__(
        self,
        *,
        registry: Optional[Any] = None,  # AdapterRegistry 实例
        heartbeat_interval: float = 10.0,
        fault_threshold: int = 3,
        auto_switch: bool = True,
        event_max_size: int = 1000,
    ):
        """
        初始化统一监听器。

        参数：
          registry           : AdapterRegistry — 适配器注册表；None 则创建空注册表
          heartbeat_interval : float           — 心跳检测间隔（秒），默认 10 秒
          fault_threshold    : int             — 连续故障阈值：超过此次数标记为 FAULT
          auto_switch        : bool            — 是否在故障时自动切换到备用适配器
          event_max_size     : int             — 事件流最大保留条数（超出则截断旧事件）

        类比：
          Kubernetes controller 的 --sync-period 和 --concurrent-workers 参数
        """
        # 适配器注册表
        if registry is not None:
            self._registry = registry
        elif _HAS_ADAPTER_REGISTRY and AdapterRegistry is not None:
            self._registry = AdapterRegistry()
        else:
            self._registry = None
            logger.warning(
                "[UnifiedMonitor] AdapterRegistry 不可用，监控器将在无注册表模式运行"
            )

        # 心跳配置
        self._heartbeat_interval = heartbeat_interval
        self._fault_threshold = fault_threshold
        self._auto_switch = auto_switch

        # 事件流（环形缓冲区风格——超出 max_size 时截断旧事件）
        self._event_max_size = event_max_size
        self._events: List[AdapterEvent] = []

        # 每个适配器的健康快照（key = adapter_id）
        self._health_map: Dict[str, AdapterHealth] = {}

        # 故障回调列表：每个回调签名为 (AdapterEvent) -> None
        self._fault_callbacks: List[Callable[[AdapterEvent], None]] = []

        # 后台心跳线程
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._watch_lock = threading.RLock()  # 保护 _health_map 和 _events 的读写

        # 已知的适配器 ID 集合（用于自动感知增删）
        self._known_adapter_ids: Set[str] = set()

        logger.info(
            "[UnifiedMonitor] 初始化完成 | 心跳间隔=%.1fs | 故障阈值=%d | 自动切换=%s",
            heartbeat_interval, fault_threshold, auto_switch,
        )

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def watch_all(self) -> None:
        """
        启动后台心跳线程，开始监控所有已注册适配器。

        可以重复调用——如果已启动则忽略。

        类比：
          - Kubernetes controller 的 Run() 方法
          - ThreadPoolExecutor 的 submit() 后开始执行
          - setInterval() 开始周期性回调
        """
        if self._heartbeat_thread is not None and self._heartbeat_thread.is_alive():
            logger.debug("[UnifiedMonitor] 心跳线程已在运行，跳过重复启动")
            return

        self._stop_event.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name="unified-monitor-heartbeat",
        )
        self._heartbeat_thread.start()
        logger.info("[UnifiedMonitor] ✅ 心跳线程已启动（间隔=%.1fs）", self._heartbeat_interval)

    def stop(self) -> None:
        """
        停止心跳线程，优雅关闭监控器。

        类比：
          - Kubernetes controller 的 Shutdown() 方法
          - clearInterval() 停止周期性回调
          - SIGTERM 触发的 graceful shutdown
        """
        if self._heartbeat_thread is None:
            return
        self._stop_event.set()
        self._heartbeat_thread.join(timeout=5.0)
        self._heartbeat_thread = None
        logger.info("[UnifiedMonitor] 心跳线程已停止")

    # ------------------------------------------------------------------
    # 后台心跳循环
    # ------------------------------------------------------------------

    def _heartbeat_loop(self) -> None:
        """
        后台心跳循环——周期性检查所有适配器的健康状态。

        类比：
          Kubernetes controller 的 syncLoop 内部循环
        """
        logger.debug("[UnifiedMonitor] 心跳循环开始")
        while not self._stop_event.is_set():
            try:
                self._perform_heartbeat()
            except Exception as e:
                logger.error("[UnifiedMonitor] 心跳检测异常: %s", e, exc_info=True)
            # 等待下一次心跳（支持提前终止）
            self._stop_event.wait(timeout=self._heartbeat_interval)

    def _perform_heartbeat(self) -> None:
        """
        单次心跳检测：检查所有已注册适配器，更新健康状态，感知增删。

        类比：
          Kubernetes Node controller 的 monitorNodeHealth()——遍历所有节点
        """
        # 获取当前已注册的适配器列表
        current_adapters = self._get_registered_adapters()

        with self._watch_lock:
            current_ids = set(current_adapters.keys())

            # ---- 感知新增适配器 ----
            new_ids = current_ids - self._known_adapter_ids
            for adapter_id in new_ids:
                adapter = current_adapters.get(adapter_id)
                self._health_map[adapter_id] = AdapterHealth(
                    adapter_id=adapter_id,
                    status=HealthStatus.UNKNOWN,
                )
                self._known_adapter_ids.add(adapter_id)
                # 记录发现事件
                self._push_event(AdapterEvent(
                    adapter_id=adapter_id,
                    event_type="registered",
                    new_status=HealthStatus.UNKNOWN,
                    message=f"发现新适配器: {adapter_id}",
                    metadata={"adapter_type": type(adapter).__name__ if adapter is not None else "unknown"},
                ))
                logger.info("[UnifiedMonitor] 发现新适配器: %s", adapter_id)

            # ---- 感知移除的适配器 ----
            removed_ids = self._known_adapter_ids - current_ids
            for adapter_id in removed_ids:
                self._health_map.pop(adapter_id, None)
                self._known_adapter_ids.discard(adapter_id)
                self._push_event(AdapterEvent(
                    adapter_id=adapter_id,
                    event_type="deregistered",
                    message=f"适配器已移除: {adapter_id}",
                ))
                logger.info("[UnifiedMonitor] 适配器已移除: %s", adapter_id)

            # ---- 对每个现有适配器执行健康检查 ----
            for adapter_id, adapter in current_adapters.items():
                self._check_single_adapter(adapter_id, adapter)

    def _check_single_adapter(self, adapter_id: str, adapter: Any) -> None:
        """
        对单个适配器执行健康检查并更新状态。

        参数：
          adapter_id : str  — 适配器 ID
          adapter    : Any  — 适配器实例（应有 health_check() 方法）

        类比：
          Kubernetes 的 livenessProbe——探测单个 Pod 是否存活
        """
        health = self._health_map.get(adapter_id)
        if health is None:
            return  # 理论上不会发生，但防御性编程

        start_time = time.time()
        is_healthy = False
        error_msg: Optional[str] = None

        # 尝试调用适配器的健康检查方法
        try:
            if hasattr(adapter, 'health_check'):
                is_healthy = adapter.health_check()
            elif hasattr(adapter, 'ping'):
                is_healthy = adapter.ping()
            else:
                # 适配器无健康检查方法 → 假设可用（乐观策略）
                is_healthy = True
                logger.debug("[UnifiedMonitor] 适配器 %s 无 health_check/ping 方法，假定健康",
                             adapter_id)
        except Exception as e:
            is_healthy = False
            error_msg = f"{type(e).__name__}: {e}"
            logger.warning("[UnifiedMonitor] 适配器 %s 健康检查异常: %s", adapter_id, e)

        # 计算响应时间
        response_time_ms = (time.time() - start_time) * 1000.0

        # 更新平均响应时间（指数加权移动平均，EWMA）
        if health.avg_response_time_ms == 0.0:
            health.avg_response_time_ms = response_time_ms
        else:
            # EWMA 平滑因子 α = 0.3 —— 新值权重 30%
            alpha = 0.3
            health.avg_response_time_ms = (
                alpha * response_time_ms + (1 - alpha) * health.avg_response_time_ms
            )

        # 更新心跳时间
        health.last_heartbeat = datetime.now(timezone.utc)

        # ---- 状态转换逻辑 ----
        old_status = health.status

        if is_healthy:
            # 健康检查通过
            if health.consecutive_failures > 0:
                # 之前有故障 → 这次是恢复
                health.recovery_count += 1
                health.consecutive_failures = 0
                health.status = HealthStatus.HEALTHY
                self._push_event(AdapterEvent(
                    adapter_id=adapter_id,
                    event_type="recovery",
                    old_status=old_status,
                    new_status=HealthStatus.HEALTHY,
                    message=f"适配器已恢复 (响应时间={response_time_ms:.1f}ms)",
                    metadata={"response_time_ms": round(response_time_ms, 2)},
                ))
                logger.info("[UnifiedMonitor] 适配器 %s 已恢复 (响应时间=%.1fms)",
                            adapter_id, response_time_ms)
            else:
                # 持续健康
                health.status = HealthStatus.HEALTHY
                if old_status != HealthStatus.HEALTHY:
                    # 状态发生变化才记录事件
                    self._push_event(AdapterEvent(
                        adapter_id=adapter_id,
                        event_type="status_change",
                        old_status=old_status,
                        new_status=HealthStatus.HEALTHY,
                        message=f"适配器状态变为 HEALTHY",
                        metadata={"response_time_ms": round(response_time_ms, 2)},
                    ))
        else:
            # 健康检查失败
            health.consecutive_failures += 1
            health.fault_count += 1
            health.last_error = error_msg

            if health.consecutive_failures >= self._fault_threshold:
                # 连续故障超过阈值 → FAULT
                new_status = HealthStatus.FAULT
                health.status = new_status
                if old_status != HealthStatus.FAULT:
                    event = AdapterEvent(
                        adapter_id=adapter_id,
                        event_type="fault",
                        old_status=old_status,
                        new_status=HealthStatus.FAULT,
                        message=f"适配器故障 (连续 {health.consecutive_failures} 次失败): {error_msg}",
                        metadata={
                            "consecutive_failures": health.consecutive_failures,
                            "last_error": error_msg,
                        },
                    )
                    self._push_event(event)
                    logger.error(
                        "[UnifiedMonitor] ❌ 适配器 %s 故障 (连续 %d 次失败): %s",
                        adapter_id, health.consecutive_failures, error_msg,
                    )

                    # ---- 触发故障回调 ----
                    for callback in self._fault_callbacks:
                        try:
                            callback(event)
                        except Exception as cb_err:
                            logger.error(
                                "[UnifiedMonitor] 故障回调异常 (adapter=%s): %s",
                                adapter_id, cb_err,
                            )

                    # ---- 自动切换到备用适配器 ----
                    if self._auto_switch:
                        self._perform_auto_switch(adapter_id, event)
            else:
                # 尚未达到故障阈值 → DEGRADED
                health.status = HealthStatus.DEGRADED
                if old_status != HealthStatus.DEGRADED:
                    self._push_event(AdapterEvent(
                        adapter_id=adapter_id,
                        event_type="status_change",
                        old_status=old_status,
                        new_status=HealthStatus.DEGRADED,
                        message=f"适配器降级 (连续 {health.consecutive_failures} 次失败): {error_msg}",
                        metadata={
                            "consecutive_failures": health.consecutive_failures,
                            "last_error": error_msg,
                        },
                    ))
                    logger.warning(
                        "[UnifiedMonitor] ⚠️ 适配器 %s 降级 (连续 %d 次): %s",
                        adapter_id, health.consecutive_failures, error_msg,
                    )

    # ------------------------------------------------------------------
    # 自动切换
    # ------------------------------------------------------------------

    def _perform_auto_switch(self, fault_adapter_id: str,
                             fault_event: AdapterEvent) -> None:
        """
        适配器故障时自动切换到备用适配器。

        策略：
          1. 查找同一类型（如 LLM）的健康适配器
          2. 优先选择 response_time 最低的
          3. 如果没有健康适配器，保持现状并告警

        类比：
          - Kubernetes Service 的 failover：故障 Pod 被 endpoints 剔除
          - AWS RDS Multi-AZ 的自动故障切换
          - Nginx upstream 的 backup server
        """
        logger.info("[UnifiedMonitor] 尝试为故障适配器 %s 自动切换...", fault_adapter_id)

        # 尝试找到同类型的健康适配器
        candidates = self._find_fallback_adapters(fault_adapter_id)

        if not candidates:
            logger.warning(
                "[UnifiedMonitor] 适配器 %s 无可用的备用适配器，保持现状",
                fault_adapter_id,
            )
            self._push_event(AdapterEvent(
                adapter_id=fault_adapter_id,
                event_type="auto_switch_failed",
                new_status=HealthStatus.FAULT,
                message="自动切换失败：无可用的备用适配器",
            ))
            return

        # 选择响应时间最低的作为切换目标
        best_candidate_id = candidates[0][0]
        best_candidate_rt = candidates[0][1]

        # 记录切换事件
        switch_event = AdapterEvent(
            adapter_id=fault_adapter_id,
            event_type="auto_switch",
            new_status=HealthStatus.FAULT,
            message=f"自动切换: {fault_adapter_id} → {best_candidate_id}",
            metadata={
                "switched_to": best_candidate_id,
                "candidates": [c[0] for c in candidates],
                "best_response_time_ms": round(best_candidate_rt, 2),
                "fault_reason": fault_event.message,
            },
        )
        self._push_event(switch_event)
        logger.info(
            "[UnifiedMonitor] ✅ 自动切换: %s → %s (响应时间=%.1fms)",
            fault_adapter_id, best_candidate_id, best_candidate_rt,
        )

    def _find_fallback_adapters(self, fault_adapter_id: str) -> List[Tuple[str, float]]:
        """
        查找可用的备用适配器列表，按响应时间升序排列。

        返回：
          List[Tuple[str, float]] — [(adapter_id, avg_response_time_ms), ...]

        类比：
          Kubernetes 的 EndpointSlice——提供可用的后端列表，按就绪状态排序
        """
        candidates: List[Tuple[str, float]] = []

        # 推断故障适配器的类型（通过 ID 前缀，如 "llm/openai-gpt4"）
        if "/" in fault_adapter_id:
            adapter_type_prefix = fault_adapter_id.split("/")[0]
        else:
            adapter_type_prefix = ""

        with self._watch_lock:
            for aid, health in self._health_map.items():
                if aid == fault_adapter_id:
                    continue  # 跳过故障适配器本身
                if health.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED):
                    # 类型匹配或放宽条件：任意健康适配器都可以
                    if not adapter_type_prefix or aid.startswith(adapter_type_prefix + "/"):
                        candidates.append((aid, health.avg_response_time_ms))

        # 按响应时间升序排列
        candidates.sort(key=lambda x: x[1])
        return candidates

    # ------------------------------------------------------------------
    # 获取已注册适配器列表
    # ------------------------------------------------------------------

    def _get_registered_adapters(self) -> Dict[str, Any]:
        """
        从 AdapterRegistry 获取当前已注册的所有适配器。

        返回：
          Dict[str, Any] — {adapter_id: adapter_instance}

        类比：
          Kubernetes API Server 的 LIST pods 请求
        """
        if self._registry is not None and hasattr(self._registry, 'list_all'):
            try:
                return self._registry.list_all()
            except Exception as e:
                logger.error("[UnifiedMonitor] 获取适配器列表失败: %s", e)
        return {}

    # ------------------------------------------------------------------
    # 健康报告
    # ------------------------------------------------------------------

    def get_health_report(self) -> Dict[str, Any]:
        """
        汇总所有适配器的健康状态，返回结构化报告。

        返回格式：
          {
            "timestamp": "2026-01-15T12:00:00+00:00",
            "total_adapters": 5,
            "healthy_count": 3,
            "degraded_count": 1,
            "fault_count": 1,
            "unknown_count": 0,
            "adapters": {
              "adapter_id_1": { ... AdapterHealth.to_dict() ... },
              ...
            },
            "recent_events_count": 42,
          }

        类比：
          - Kubernetes 的 `kubectl get nodes` 输出
          - AWS 的 Systems Manager Fleet Manager 仪表盘
          - Docker 的 `docker ps` 状态总览
        """
        with self._watch_lock:
            adapters_detail = {
                aid: health.to_dict()
                for aid, health in self._health_map.items()
            }

            # 统计各状态的适配器数量
            status_counts = {
                HealthStatus.HEALTHY: 0,
                HealthStatus.DEGRADED: 0,
                HealthStatus.FAULT: 0,
                HealthStatus.UNKNOWN: 0,
            }
            for health in self._health_map.values():
                status_counts[health.status] += 1

            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_adapters": len(self._health_map),
                "healthy_count": status_counts[HealthStatus.HEALTHY],
                "degraded_count": status_counts[HealthStatus.DEGRADED],
                "fault_count": status_counts[HealthStatus.FAULT],
                "unknown_count": status_counts[HealthStatus.UNKNOWN],
                "adapters": adapters_detail,
                "recent_events_count": len(self._events),
            }

    # ------------------------------------------------------------------
    # 事件流
    # ------------------------------------------------------------------

    def get_event_stream(self, limit: int = 50) -> List[AdapterEvent]:
        """
        获取最近 N 条事件（按时间倒序——最新在前）。

        参数：
          limit : int — 返回的最大事件数，默认 50

        返回：
          List[AdapterEvent] — 事件列表（最新的在前）

        类比：
          - Kubernetes 的 `kubectl get events --sort-by='.lastTimestamp'`
          - AWS CloudTrail 的 "Event history"
          - systemd 的 `journalctl -n 50`
        """
        with self._watch_lock:
            # 返回最近 limit 条（事件按时间正序存储，取末尾再反转）
            recent = self._events[-limit:] if limit > 0 else list(self._events)
            return list(reversed(recent))

    def get_events_by_adapter(self, adapter_id: str,
                               limit: int = 50) -> List[AdapterEvent]:
        """
        获取特定适配器的最近 N 条事件。

        参数：
          adapter_id : str — 适配器 ID
          limit      : int — 最大事件数

        类比：
          - Kubernetes 的 `kubectl describe pod <name>` 中的 Events 字段
        """
        with self._watch_lock:
            matching = [e for e in self._events if e.adapter_id == adapter_id]
            recent = matching[-limit:] if limit > 0 else matching
            return list(reversed(recent))

    # ------------------------------------------------------------------
    # 故障回调注册
    # ------------------------------------------------------------------

    def on_adapter_fault(self, callback: Callable[[AdapterEvent], None]) -> None:
        """
        注册故障回调——当适配器进入 FAULT 状态时调用。

        参数：
          callback : (AdapterEvent) -> None — 回调函数，接收故障事件

        类比：
          - Express.js 的 app.on('error', handler)
          - Node.js EventEmitter 的 emitter.on('fault', callback)
          - Kubernetes 的 admission webhook——外部系统订阅内部事件
        """
        if callback not in self._fault_callbacks:
            self._fault_callbacks.append(callback)
            logger.debug("[UnifiedMonitor] 注册故障回调: %s", callback.__name__)

    def remove_fault_callback(self, callback: Callable[[AdapterEvent], None]) -> None:
        """
        移除之前注册的故障回调。

        类比：EventEmitter 的 removeListener()
        """
        if callback in self._fault_callbacks:
            self._fault_callbacks.remove(callback)
            logger.debug("[UnifiedMonitor] 移除故障回调: %s", callback.__name__)

    # ------------------------------------------------------------------
    # 自动切换开关
    # ------------------------------------------------------------------

    def auto_switch_on_fault(self, enabled: bool = True) -> None:
        """
        启用/禁用适配器故障时的自动切换。

        参数：
          enabled : bool — True 启用自动切换，False 仅记录不切换

        类比：
          - Kubernetes Deployment 的 `.spec.replicas` 自动修复开关
          - Feature Flag: ENABLE_AUTO_FAILOVER = true/false
        """
        prev = self._auto_switch
        self._auto_switch = enabled
        logger.info("[UnifiedMonitor] 自动切换: %s → %s", prev, enabled)

    # ------------------------------------------------------------------
    # 内部工具方法
    # ------------------------------------------------------------------

    def _push_event(self, event: AdapterEvent) -> None:
        """
        将事件推入事件流，并维护最大容量限制。

        类比：
          Redis Streams 的 XADD + MAXLEN 截断
        """
        self._events.append(event)
        # 超出容量时截断旧事件（保留最新的）
        if len(self._events) > self._event_max_size:
            overflow = len(self._events) - self._event_max_size
            self._events = self._events[overflow:]

    # ------------------------------------------------------------------
    # 上下文管理器协议（with 语句支持）
    # ------------------------------------------------------------------

    def __enter__(self) -> "UnifiedMonitor":
        """
        进入上下文管理器时自动开始监控。

        使用方式：
          with UnifiedMonitor(registry=reg) as monitor:
              # 监控自动运行
              report = monitor.get_health_report()
        """
        self.watch_all()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """退出上下文管理器时自动停止。"""
        self.stop()
        return False  # 不抑制异常


# ============================================================================
# 5. 便捷函数
# ============================================================================

def create_monitor(
    registry: Optional[Any] = None,
    heartbeat_interval: float = 10.0,
    auto_switch: bool = True,
) -> UnifiedMonitor:
    """
    快速创建并启动 UnifiedMonitor。

    参数：
      registry           : AdapterRegistry — 适配器注册表
      heartbeat_interval : float           — 心跳间隔（秒）
      auto_switch        : bool            — 是否自动切换

    返回：
      UnifiedMonitor — 已启动的监控器实例

    使用方式：
      monitor = create_monitor(registry)
      monitor.watch_all()
      report = monitor.get_health_report()

    类比：
      - Express.js 的 app.listen() 一行启动
      - Python logging 的 basicConfig() 一行配置
    """
    monitor = UnifiedMonitor(
        registry=registry,
        heartbeat_interval=heartbeat_interval,
        auto_switch=auto_switch,
    )
    monitor.watch_all()
    return monitor


# ============================================================================
# 6. 自测
# ============================================================================

if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print("=" * 60)
    print("Unified Monitor — 统一监听器自测")
    print("=" * 60)

    # ---- 测试 1: 无注册表模式 ----
    print("\n[测试 1] 无 AdapterRegistry 模式...")
    monitor = UnifiedMonitor(
        heartbeat_interval=2.0,
        fault_threshold=2,
        auto_switch=False,
    )

    # 注册一个故障回调
    def on_fault(event: AdapterEvent):
        print(f"  🔔 故障回调触发: {event.message}")

    monitor.on_adapter_fault(on_fault)

    # 启动监控
    monitor.watch_all()

    # 等待几次心跳
    time.sleep(3.0)

    # 获取健康报告
    report = monitor.get_health_report()
    print(f"  健康报告: total={report['total_adapters']}, "
          f"healthy={report['healthy_count']}, fault={report['fault_count']}")

    # 获取事件流
    events = monitor.get_event_stream(limit=10)
    print(f"  事件流: {len(events)} 条事件")
    for evt in events[:3]:
        print(f"    - [{evt.event_type}] {evt.adapter_id}: {evt.message}")

    # 停止
    monitor.stop()

    # ---- 测试 2: 上下文管理器 ----
    print("\n[测试 2] 上下文管理器模式...")
    with UnifiedMonitor(heartbeat_interval=2.0) as m:
        time.sleep(2.5)
        report = m.get_health_report()
        print(f"  上下文内报告: {report['total_adapters']} 个适配器")

    # ---- 测试 3: 自动切换开关 ----
    print("\n[测试 3] 自动切换开关...")
    monitor2 = UnifiedMonitor(heartbeat_interval=5.0, auto_switch=True)
    print(f"  自动切换状态: {monitor2._auto_switch}")
    monitor2.auto_switch_on_fault(False)
    print(f"  切换后状态: {monitor2._auto_switch}")

    # ---- 测试 4: 事件流 ----
    print("\n[测试 4] 事件流测试...")
    monitor3 = UnifiedMonitor(heartbeat_interval=10.0)
    # 手动推送几个事件
    for i in range(3):
        monitor3._push_event(AdapterEvent(
            adapter_id=f"test-adapter-{i}",
            event_type="heartbeat",
            message=f"测试事件 #{i}",
        ))
    events = monitor3.get_event_stream(limit=2)
    print(f"  最近 2 条事件: {[e.message for e in events]}")

    # 按适配器过滤
    adapter_events = monitor3.get_events_by_adapter("test-adapter-1")
    print(f"  test-adapter-1 的事件: {len(adapter_events)} 条")

    print("\n✅ 统一监听器自测完成")
