"""
对话事件监听器 (Conversation Event Listener)
============================================
类比 Node.js EventEmitter / Python signal — 提供发布-订阅式的事件总线，
用于在对话生命周期中解耦地响应关键事件（新轮次、会话切换、压缩等）。

线程安全：所有公共方法均受 threading.Lock 保护，可在多线程环境中安全使用。
"""

import enum
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# ---------------------------------------------------------------------------
# 1. ConversationEvent 枚举 — 所有可监听的事件类型
# ---------------------------------------------------------------------------

class ConversationEvent(enum.Enum):
    """
    对话生命周期中的关键事件。
    每个事件携带不同的 data 字典，具体见 emit() 的文档。
    """

    TURN_ADDED = "turn_added"
    """新对话轮次被添加到当前会话。data: {session_id, turn_index, role, content_preview}"""

    SESSION_CREATED = "session_created"
    """新会话被创建。data: {session_id, created_at, metadata}"""

    SESSION_SWITCHED = "session_switched"
    """用户切换到另一个会话。data: {from_session_id, to_session_id, switched_at}"""

    HISTORY_REFERENCED = "history_referenced"
    """用户或系统引用了历史会话中的内容。data: {session_id, query, matched_sessions}"""

    COMPRESSION_TRIGGERED = "compression_triggered"
    """某个会话触发了压缩操作。data: {session_id, turn_count, compressed_at}"""

    DECOMPRESSION_TRIGGERED = "decompression_triggered"
    """某个压缩过的会话被解压以恢复上下文。data: {session_id, decompressed_at}"""


# ---------------------------------------------------------------------------
# 辅助数据类 — 会话摘要（供内置处理器使用）
# ---------------------------------------------------------------------------

@dataclass
class _SessionMeta:
    """
    内部维护的会话元数据，供内置压缩/解压逻辑使用。
    不对外暴露；外部代码只通过事件和回调与监听器交互。
    """
    session_id: str
    turn_count: int = 0                      # 当前轮次数
    compressed: bool = False                 # 是否已压缩
    compressed_at: Optional[float] = None    # 压缩发生的时间戳
    created_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# 2. ConversationListener 类 — 事件总线主体
# ---------------------------------------------------------------------------

class ConversationListener:
    """
    对话事件监听器 — 发布/订阅事件总线。

    使用方式
    --------
    >>> listener = ConversationListener()
    >>> listener.on(ConversationEvent.TURN_ADDED, lambda data: print(data))
    >>> listener.emit(ConversationEvent.TURN_ADDED, {"session_id": "abc", "turn_index": 3})

    内置行为
    --------
    - 会话切换时自动压缩旧会话（如果未压缩）。
    - 引用历史时自动搜索并解压匹配的会话。
    - 超过 50 轮自动触发压缩。

    线程安全
    --------
    所有注册、注销、发射操作均由 _lock 保护；回调在锁外执行以避免死锁。
    """

    # 内置超参数
    AUTO_COMPRESS_TURN_THRESHOLD = 50   # 超过此轮数自动触发压缩
    HISTORY_SEARCH_LIMIT = 5            # 引用历史时最多返回的匹配会话数

    # ------------------------------------------------------------------
    # 构造
    # ------------------------------------------------------------------

    def __init__(self):
        """初始化事件总线：创建回调注册表、会话追踪表和线程锁。"""
        # {事件类型 → [回调函数列表]}
        self._listeners: Dict[ConversationEvent, List[Callable[[Dict[str, Any]], None]]] = (
            defaultdict(list)
        )

        # {session_id → _SessionMeta} — 追踪每个会话的轮次和压缩状态
        self._sessions: Dict[str, _SessionMeta] = {}

        # 线程安全锁 — 保护 _listeners 和 _sessions 的并发访问
        self._lock = threading.Lock()

        # ── 注册内置处理器 ──
        self._register_builtin_handlers()

    # ------------------------------------------------------------------
    # 公开 API — 注册 / 注销
    # ------------------------------------------------------------------

    def on(self, event_type: ConversationEvent,
           callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        为指定事件类型注册一个回调函数。

        参数
        ----
        event_type : ConversationEvent
            要监听的事件类型（如 TURN_ADDED）。
        callback : Callable[[Dict[str, Any]], None]
            事件触发时调用的函数，接收一个 data 字典作为唯一参数。

        类比
        ----
        Node.js: emitter.on('event', callback)
        Python signal: signal.signal(signum, handler)
        """
        with self._lock:
            self._listeners[event_type].append(callback)

    def off(self, event_type: ConversationEvent,
            callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        注销之前注册的回调函数。

        参数
        ----
        event_type : ConversationEvent
            事件类型。
        callback : Callable
            要移除的回调（必须是同一个可哈希对象）。
        """
        with self._lock:
            callbacks = self._listeners.get(event_type, [])
            if callback in callbacks:
                callbacks.remove(callback)

    # ------------------------------------------------------------------
    # 公开 API — 触发事件
    # ------------------------------------------------------------------

    def emit(self, event_type: ConversationEvent, data: Optional[Dict[str, Any]] = None) -> None:
        """
        触发一个事件，通知所有注册的回调。

        参数
        ----
        event_type : ConversationEvent
            要触发的事件类型。
        data : dict, optional
            随事件传递的数据。如果为 None，自动填充空字典。
            各事件推荐的 data 键值见 ConversationEvent 的文档。

        线程安全说明
        ------------
        回调函数在锁外执行，以避免回调内部再次调用 on/emit 时死锁。
        这意味着回调执行期间可能有新的事件被触发 — 回调自身需做好并发防护。
        """
        if data is None:
            data = {}

        # ── 确保时间戳存在（如果调用方未提供），拷贝 data 以避免修改调用方字典 ──
        data = dict(data)  # 浅拷贝，避免隐式副作用
        if "timestamp" not in data:
            data["timestamp"] = time.time()

        # ── 第 1 步：锁内更新内部状态（会话追踪） ──
        with self._lock:
            self._update_session_state(event_type, data)
            # 在释放锁之前拷贝回调列表，避免在锁外遍历时被修改
            callbacks = list(self._listeners.get(event_type, []))

        # ── 第 2 步：锁外执行所有回调 ──
        for callback in callbacks:
            try:
                callback(data)
            except Exception as exc:
                # 某个回调出错不应影响其他回调的执行
                # 实际项目中可替换为 logging.exception
                print(f"[ConversationListener] 回调异常 ({event_type.value}): {exc}")

    # ------------------------------------------------------------------
    # 公开 API — 工具方法
    # ------------------------------------------------------------------

    def listener_count(self, event_type: Optional[ConversationEvent] = None) -> int:
        """
        返回已注册的回调数量。

        参数
        ----
        event_type : ConversationEvent, optional
            如果指定，只统计该事件；否则统计所有事件的总回调数。
        """
        with self._lock:
            if event_type is not None:
                return len(self._listeners.get(event_type, []))
            return sum(len(cbs) for cbs in self._listeners.values())

    def session_turn_count(self, session_id: str) -> int:
        """
        返回指定会话当前记录的轮次数。

        参数
        ----
        session_id : str
            会话唯一标识。

        返回
        ----
        int — 轮次数；如果会话不存在则返回 0。
        """
        with self._lock:
            meta = self._sessions.get(session_id)
            return meta.turn_count if meta else 0

    # ==================================================================
    # 内部方法 — 会话状态更新 & 内置处理器
    # ==================================================================

    def _update_session_state(self, event_type: ConversationEvent,
                              data: Dict[str, Any]) -> None:
        """
        根据事件更新内部会话追踪表（_sessions）。
        此方法在锁内调用，不需要额外加锁。

        参数
        ----
        event_type : ConversationEvent
            当前触发的事件类型。
        data : dict
            事件携带的数据。
        """
        sid = data.get("session_id", "")

        if event_type == ConversationEvent.SESSION_CREATED and sid:
            # 新会话：初始化元数据
            self._sessions[sid] = _SessionMeta(
                session_id=sid,
                created_at=data.get("created_at", time.time()),
            )

        elif event_type == ConversationEvent.TURN_ADDED and sid:
            # 新轮次：递增轮次计数
            meta = self._sessions.get(sid)
            if meta is None:
                meta = _SessionMeta(session_id=sid)
                self._sessions[sid] = meta
            meta.turn_count += 1

        elif event_type == ConversationEvent.COMPRESSION_TRIGGERED and sid:
            # 压缩完成：标记会话为已压缩
            meta = self._sessions.get(sid)
            if meta:
                meta.compressed = True
                meta.compressed_at = data.get("timestamp", time.time())

        elif event_type == ConversationEvent.DECOMPRESSION_TRIGGERED and sid:
            # 解压完成：清除压缩标记
            meta = self._sessions.get(sid)
            if meta:
                meta.compressed = False
                meta.compressed_at = None

    def _register_builtin_handlers(self) -> None:
        """
        注册所有内置事件处理器。

        这些处理器在用户回调之前运行（因为它们先注册），
        实现了开箱即用的压缩/解压自动化行为。
        """
        # ── 内置处理器 1：会话切换 → 自动压缩旧会话 ──
        self.on(ConversationEvent.SESSION_SWITCHED, self._on_session_switched)

        # ── 内置处理器 2：引用历史 → 自动搜索并解压匹配会话 ──
        self.on(ConversationEvent.HISTORY_REFERENCED, self._on_history_referenced)

        # ── 内置处理器 3：超过 50 轮 → 自动触发压缩 ──
        self.on(ConversationEvent.TURN_ADDED, self._on_turn_added_check_compress)

    # ------------------------------------------------------------------
    # 内置处理器 1：会话切换时自动压缩旧会话
    # ------------------------------------------------------------------

    def _on_session_switched(self, data: Dict[str, Any]) -> None:
        """
        当用户切换到新会话时，自动压缩旧会话（如果它尚未被压缩且存在）。

        参数
        ----
        data : dict
            SESSION_SWITCHED 事件数据；需要 from_session_id 键。
        """
        from_sid = data.get("from_session_id", "")
        if not from_sid:
            return  # 无旧会话（例如首次进入）

        # ── 在锁内完成所有条件判断，快照所需数据后释放锁 ──
        should_compress = False
        turn_count = 0
        with self._lock:
            meta = self._sessions.get(from_sid)
            if meta is not None and not meta.compressed:
                should_compress = True
                turn_count = meta.turn_count

        if not should_compress:
            return  # 未追踪或已压缩，跳过

        # 触发对旧会话的压缩 — 用 emit 而非直接调用，让其他监听者也能感知
        print(f"[ConversationListener] 内置: 会话切换，自动压缩旧会话 {from_sid}")
        self.emit(ConversationEvent.COMPRESSION_TRIGGERED, {
            "session_id": from_sid,
            "turn_count": turn_count,
            "reason": "session_switched",
        })

    # ------------------------------------------------------------------
    # 内置处理器 2：引用历史时自动搜索并解压匹配会话
    # ------------------------------------------------------------------

    def _on_history_referenced(self, data: Dict[str, Any]) -> None:
        """
        当用户引用历史时，查找匹配的会话，并对压缩过的匹配会话自动解压。

        参数
        ----
        data : dict
            HISTORY_REFERENCED 事件数据；需要 query（搜索词）键。
        """
        query = data.get("query", "")
        if not query:
            return

        # ── 锁内收集会话快照 ──
        with self._lock:
            sessions_snapshot = list(self._sessions.values())

        # ── 简单关键词匹配（实际项目可替换为向量搜索） ──
        matched: List[_SessionMeta] = []
        query_lower = query.lower()
        for meta in sessions_snapshot:
            if query_lower in meta.session_id.lower():
                matched.append(meta)
            if len(matched) >= self.HISTORY_SEARCH_LIMIT:
                break

        # ── 将匹配结果写回 data，供外部回调使用 ──
        data["matched_sessions"] = [m.session_id for m in matched]

        # ── 对已压缩的匹配会话自动解压 ──
        for meta in matched:
            if meta.compressed:
                print(f"[ConversationListener] 内置: 引用历史，自动解压会话 {meta.session_id}")
                self.emit(ConversationEvent.DECOMPRESSION_TRIGGERED, {
                    "session_id": meta.session_id,
                    "reason": "history_referenced",
                    "query": query,
                })

    # ------------------------------------------------------------------
    # 内置处理器 3：超过 50 轮自动触发压缩
    # ------------------------------------------------------------------

    def _on_turn_added_check_compress(self, data: Dict[str, Any]) -> None:
        """
        每新增一轮时检查：如果当前会话轮次超过阈值（默认 50），自动触发压缩。

        参数
        ----
        data : dict
            TURN_ADDED 事件数据；需要 session_id 键。
        """
        sid = data.get("session_id", "")
        if not sid:
            return

        # ── 在锁内完成所有条件判断，快照所需数据后释放锁 ──
        should_compress = False
        turn_count = 0
        threshold = self.AUTO_COMPRESS_TURN_THRESHOLD
        with self._lock:
            meta = self._sessions.get(sid)
            if meta is not None and meta.turn_count >= threshold and not meta.compressed:
                should_compress = True
                turn_count = meta.turn_count

        if not should_compress:
            return

        print(
            f"[ConversationListener] 内置: 会话 {sid} 已达 {turn_count} 轮，"
            f"自动触发压缩（阈值 {threshold}）"
        )
        self.emit(ConversationEvent.COMPRESSION_TRIGGERED, {
            "session_id": sid,
            "turn_count": turn_count,
            "reason": "auto_threshold",
            "threshold": threshold,
        })


# ===========================================================================
# 模块自测 — 验证基本功能
# ===========================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("ConversationListener 自测")
    print("=" * 60)

    # ── 创建监听器实例 ──
    listener = ConversationListener()

    # ── 注册用户自定义回调 ──
    received_events: List[str] = []  # 记录收到的所有事件

    def user_callback(data: Dict[str, Any]) -> None:
        """模拟用户回调：只记录事件类型和数据摘要。"""
        event_type = data.get("_event_type", "unknown")
        received_events.append(event_type)
        print(f"  [用户回调] 收到 {event_type}: sid={data.get('session_id', '-')}")

    # 为所有事件类型注册同一个回调（实际项目中可按需注册）
    for evt in ConversationEvent:
        listener.on(evt, user_callback)

    # ── 场景模拟 ──
    print("\n1. 创建会话 A...")
    listener.emit(ConversationEvent.SESSION_CREATED, {
        "session_id": "session-A",
        "_event_type": "SESSION_CREATED",
    })

    print("\n2. 在会话 A 中添加 3 轮对话...")
    for i in range(1, 4):
        listener.emit(ConversationEvent.TURN_ADDED, {
            "session_id": "session-A",
            "turn_index": i,
            "role": "user" if i % 2 == 1 else "assistant",
            "content_preview": f"第 {i} 轮消息内容...",
            "_event_type": "TURN_ADDED",
        })

    print(f"\n   会话 A 当前轮次: {listener.session_turn_count('session-A')}")

    print("\n3. 模拟超过 50 轮（快速触发自动压缩）...")
    # 临时降低阈值以便测试
    old_threshold = listener.AUTO_COMPRESS_TURN_THRESHOLD
    listener.AUTO_COMPRESS_TURN_THRESHOLD = 3  # 改为 3 轮即触发
    listener.emit(ConversationEvent.TURN_ADDED, {
        "session_id": "session-A",
        "turn_index": 4,
        "role": "user",
        "content_preview": "第 4 轮消息...",
        "_event_type": "TURN_ADDED",
    })
    listener.AUTO_COMPRESS_TURN_THRESHOLD = old_threshold  # 恢复

    print("\n4. 切换到会话 B（应自动压缩会话 A）...")
    listener.emit(ConversationEvent.SESSION_CREATED, {
        "session_id": "session-B",
        "_event_type": "SESSION_CREATED",
    })
    listener.emit(ConversationEvent.SESSION_SWITCHED, {
        "from_session_id": "session-A",
        "to_session_id": "session-B",
        "_event_type": "SESSION_SWITCHED",
    })

    print("\n5. 引用历史（搜索 'session-A'，应自动解压）...")
    listener.emit(ConversationEvent.HISTORY_REFERENCED, {
        "session_id": "session-B",
        "query": "session-A",
        "_event_type": "HISTORY_REFERENCED",
    })

    print(f"\n总回调数: {listener.listener_count()}")
    print(f"收到的用户事件数: {len(received_events)}")
    print("✅ 自测完成")
