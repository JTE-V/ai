"""
对话生命周期管理模块 — Conversation Lifecycle Manager
======================================================
管理 AI 查询框架中的所有对话会话：创建、切换、压缩、解压、搜索与导出。

核心概念：
  - 活跃会话（Active Session）：  当前在内存中、可直接操作的会话（≤3个）
  - 压缩会话（Compressed Session）：已持久化到磁盘的 .json.gz 文件
  - 索引文件（Index File）：      data/sessions/index.json，记录所有会话元数据

生命周期：
  创建会话 ──▶ 添加轮次 ──▶ [超过50轮自动压缩]
    │                          │
    ├── 切换会话 ──▶ 旧会话自动压缩 ──▶ 新会话解压（如果是压缩的）
    │                          │
    ├── LRU淘汰 ──▶ 内存超过3个时，最久未用的会话被压缩
    │                          │
    └── 搜索历史 ──▶ 自动解压匹配的会话 ──▶ 返回匹配结果

存储结构：
  ai-query-framework/
  └── data/
      └── sessions/
          ├── index.json            ← 所有会话的元数据索引
          ├── abc123.json.gz        ← 已压缩的会话文件
          └── def456.json.gz

类比（Python/JS）：
  - Python:  类似 shelve 模块 —— 活跃对象在内存，非活跃对象序列化到磁盘
  - JS:      类似 IndexedDB —— 数据持久化存储，按需加载到内存
  - 通用:     类似操作系统的虚拟内存管理 —— 热数据在 RAM，冷数据换出到磁盘
  - LRU:     类似 Redis 的 volatile-lru 淘汰策略
  - 压缩:     类似 Node.js 的 zlib.createGzip() 流式压缩
  - 索引:     类似 SQLite 的系统表 sqlite_master
"""

import gzip
import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Literal, Optional

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
MAX_ACTIVE_SESSIONS = 3       # 内存中最多同时保持的活跃会话数
MAX_TURNS_BEFORE_COMPRESS = 50  # 单个会话超过此轮数则自动压缩
DATA_DIR_NAME = "data"        # 数据目录名称
SESSIONS_DIR_NAME = "sessions"  # 会话子目录名称
INDEX_FILE_NAME = "index.json"  # 索引文件名

# ---------------------------------------------------------------------------
# 数据类 —— 纯数据结构，类似 JSON Schema
# ---------------------------------------------------------------------------


@dataclass
class Turn:
    """对话中的一轮（一次提问 + 一次回答 或 一条系统消息）。

    类比：
      - Python:  chat_messages 列表中的单个 dict（role + content）
      - JS:      OpenAI Chat Completions API 的一条 message 对象
      - 通用:    聊天记录中的一条"气泡"
    """

    role: str  # "user" | "assistant" | "system"
    content: str  # 消息正文
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    query_refs: List[str] = field(default_factory=list)  # 关联的查询 ID（溯源用）
    metadata: Dict = field(default_factory=dict)  # 扩展元数据（模型名、token 数等）


@dataclass
class ConversationSession:
    """一个完整的对话会话。

    类比：
      - Python:  一个 ChatHistory 对象，包含多轮消息
      - JS:      Express.js 的 req.session（会话级存储）
      - 通用:    ChatGPT 左侧边栏的一个"对话"
    """

    session_id: str  # 会话唯一 ID（UUID4）
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    turns: List[Turn] = field(default_factory=list)  # 对话轮次列表
    metadata: Dict = field(default_factory=dict)  # 元数据（模板名、用户ID、标签等）
    file_path: Optional[str] = None  # 对应的压缩文件路径（仅 compressed=True 时有效）
    compressed: bool = False  # 是否已压缩到磁盘

    def to_dict(self) -> Dict:
        """将会话序列化为字典，用于 JSON 存储。

        注意：turns 中的 datetime 需要显式转为 ISO 字符串，
        因为 dataclasses.asdict 只做浅层转换。
        """
        result = asdict(self)
        # 深层转换：每个 Turn 的 timestamp → ISO 字符串
        result["turns"] = [
            {**t, "timestamp": t["timestamp"].isoformat() if isinstance(t.get("timestamp"), str) is False else t["timestamp"]}
            for t in result["turns"]
        ]
        # 顶层时间戳 → ISO 字符串
        result["created_at"] = self.created_at.isoformat()
        result["updated_at"] = self.updated_at.isoformat()
        return result

    @classmethod
    def from_dict(cls, data: Dict) -> "ConversationSession":
        """从字典反序列化会话，将 ISO 时间字符串还原为 datetime。"""
        # 还原 turns 中的 timestamp
        turns_data = data.pop("turns", [])
        turns = []
        for t in turns_data:
            ts = t.get("timestamp")
            if isinstance(ts, str):
                t["timestamp"] = datetime.fromisoformat(ts)
            turns.append(Turn(**t))

        # 还原顶层时间戳
        for key in ("created_at", "updated_at"):
            val = data.get(key)
            if isinstance(val, str):
                data[key] = datetime.fromisoformat(val)

        session = cls(**data)
        session.turns = turns
        return session


# ---------------------------------------------------------------------------
# ConversationManager —— 对话生命周期管理器
# ---------------------------------------------------------------------------


class ConversationManager:
    """对话生命周期管理器。

    职责：
      1. 会话的创建 / 切换 / 销毁
      2. 对话轮次的追加
      3. 会话的压缩（内存 → .json.gz 磁盘文件）与解压
      4. LRU 淘汰 —— 活跃会话超过上限时，将最久未用的压缩到磁盘
      5. 历史搜索 —— 跨活跃和已压缩会话搜索关键词
      6. 导出 —— 将会话导出为 JSON 或 Markdown

    线程安全：所有公共方法使用 threading.Lock 保护。

    类比：
      - Python:  类似 logging.handlers.RotatingFileHandler —— 自动轮转和清理
      - JS:      类似 Redux store 的 middleware —— 管理状态的持久化和恢复
      - 通用:    类似操作系统的虚拟内存管理器（VM Manager）
                活跃会话 = 驻留集（Resident Set），压缩会话 = 交换空间（Swap）
      - 压缩存储: 类似 Git 的 packfile —— 将对象压缩存储以减少空间占用
    """

    def __init__(self, base_dir: Optional[str] = None):
        """初始化对话管理器。

        Args:
            base_dir: 数据根目录。如果为 None，则自动推断为
                      ai-query-framework/data/sessions/
        """
        # ---------- 确定存储目录 ----------
        if base_dir is not None:
            self._base_dir = Path(base_dir)
        else:
            # 自动推断：当前文件所在目录的上一级（即 ai-query-framework/）
            current_file = Path(__file__).resolve()
            framework_root = current_file.parent.parent  # src/ → framework/
            self._base_dir = framework_root / DATA_DIR_NAME / SESSIONS_DIR_NAME

        # 确保目录存在（类似 mkdir -p）
        self._base_dir.mkdir(parents=True, exist_ok=True)

        # ---------- 内存中的活跃会话 ----------
        # 类比：操作系统的页表（Page Table）—— 只保留最近使用的页在物理内存中
        self._active_sessions: Dict[str, ConversationSession] = {}

        # LRU 跟踪列表 —— 最近使用的放在末尾
        # 类比：Python functools.lru_cache 的内部双向链表
        self._session_lru: List[str] = []

        # ---------- 当前活跃会话 ID ----------
        self._current_session_id: Optional[str] = None

        # ---------- 索引缓存（从 index.json 加载）----------
        self._index: Dict[str, Dict] = {}

        # ---------- 线程锁 ----------
        # 类比：Python threading.Lock，类似 JS 的 Mutex
        self._lock = threading.Lock()

        # ---------- 初始化：加载索引文件 ----------
        self._load_index()

        logger.info(
            "ConversationManager 初始化完成：data_dir=%s，活跃会话上限=%d，"
            "压缩阈值=%d 轮，索引中 %d 个会话",
            str(self._base_dir),
            MAX_ACTIVE_SESSIONS,
            MAX_TURNS_BEFORE_COMPRESS,
            len(self._index),
        )

    # ------------------------------------------------------------------
    # 公开 API
    # ------------------------------------------------------------------

    def create_session(
        self,
        session_id: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> str:
        """创建新会话并设为当前活跃会话。

        如果当前已有活跃会话且符合压缩条件，则先压缩旧会话。
        新会话会自动设为当前会话。

        Args:
            session_id: 可选的会话 ID。如果为 None，自动生成 UUID4。
            metadata:  可选的元数据字典（如 {"template": "search_agent", "user_id": "u1"}）

        Returns:
            新会话的 session_id（字符串）

        类比：
          - Python:  uuid.uuid4() 生成唯一标识
          - JS:      crypto.randomUUID() 生成 v4 UUID
          - 通用:    ChatGPT 中点击 "New Chat" 按钮
        """
        with self._lock:
            # 生成会话 ID
            if session_id is None:
                session_id = uuid.uuid4().hex  # 32字符十六进制，无连字符

            # 如果 ID 已存在，追加后缀避免冲突
            original_id = session_id
            suffix = 1
            while session_id in self._active_sessions or session_id in self._index:
                session_id = f"{original_id}_{suffix}"
                suffix += 1

            # 如果当前有活跃会话且轮数较多，先压缩
            if self._current_session_id is not None:
                current = self._active_sessions.get(self._current_session_id)
                if current is not None and len(current.turns) >= MAX_TURNS_BEFORE_COMPRESS:
                    logger.info("create_session：当前会话 %s 超过 %d 轮，触发自动压缩",
                                self._current_session_id, MAX_TURNS_BEFORE_COMPRESS)
                    self._compress_session_impl(self._current_session_id)

            # 构建新会话对象
            now = datetime.now(timezone.utc)
            session = ConversationSession(
                session_id=session_id,
                created_at=now,
                updated_at=now,
                metadata=metadata or {},
            )

            # 加入活跃会话
            self._active_sessions[session_id] = session
            self._touch_lru(session_id)

            # 设为当前会话
            self._current_session_id = session_id

            # 写入索引
            self._index[session_id] = {
                "session_id": session_id,
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
                "turn_count": 0,
                "compressed": False,
                "file_path": None,
                "metadata": metadata or {},
            }
            self._save_index()

            logger.info("create_session：新建会话 %s", session_id)
            return session_id

    def switch_session(self, session_id: str) -> None:
        """切换到指定会话。

        如果目标会话当前处于压缩状态，则先自动解压。
        当前活跃会话会被自动压缩（如果满足条件）。

        Args:
            session_id: 目标会话 ID

        Raises:
            KeyError: 会话不存在（不在活跃列表也不在索引中）

        类比：
          - JS:     浏览器标签页切换 —— 当前页面的状态保存，新页面恢复
          - Python: os.chdir() —— 切换"当前工作目录"
          - 通用:   tmux 的 attach-session —— 从后台恢复到前台
        """
        with self._lock:
            # 检查会话是否存在
            if session_id not in self._active_sessions and session_id not in self._index:
                raise KeyError(f"会话 {session_id} 不存在（活跃列表和索引中均未找到）")

            # 压缩当前会话（如果存在且有内容）
            if self._current_session_id is not None and self._current_session_id != session_id:
                current = self._active_sessions.get(self._current_session_id)
                if current is not None:
                    logger.info("switch_session：离开会话 %s，触发自动压缩",
                                self._current_session_id)
                    self._compress_session_impl(self._current_session_id)

            # 如果目标会话被压缩，先解压
            if session_id not in self._active_sessions:
                logger.info("switch_session：目标会话 %s 已压缩，正在解压...", session_id)
                self._decompress_session_impl(session_id)

            # 切换当前会话
            self._current_session_id = session_id
            self._touch_lru(session_id)

            logger.info("switch_session：已切换到会话 %s（%d 轮）",
                        session_id, len(self._active_sessions[session_id].turns))

    def add_turn(
        self,
        role: Literal["user", "assistant", "system"],
        content: str,
        query_refs: Optional[List[str]] = None,
    ) -> Turn:
        """在当前活跃会话中添加一轮对话。

        添加后检查是否超过压缩阈值（50 轮）。

        Args:
            role:       角色 —— "user" / "assistant" / "system"
            content:    消息正文
            query_refs: 关联的查询 ID 列表（可选，用于溯源）

        Returns:
            新创建的 Turn 对象

        Raises:
            RuntimeError: 没有当前活跃会话（需先调用 create_session 或 switch_session）

        类比：
          - Python:  list.append() —— 在对话列表末尾追加一条消息
          - JS:      Array.push() —— 同上
          - 通用:    ChatGPT 中发送一条消息，对话记录自动追加
        """
        with self._lock:
            if self._current_session_id is None:
                raise RuntimeError(
                    "没有当前活跃会话。请先调用 create_session() 或 switch_session()"
                )

            session = self._active_sessions.get(self._current_session_id)
            if session is None:
                raise RuntimeError(
                    f"当前会话 {self._current_session_id} 不在活跃列表中（可能已被压缩）"
                )

            # 创建 Turn
            turn = Turn(
                role=role,
                content=content,
                timestamp=datetime.now(timezone.utc),
                query_refs=query_refs or [],
            )

            # 追加到会话
            session.turns.append(turn)
            session.updated_at = datetime.now(timezone.utc)
            self._touch_lru(self._current_session_id)

            # 更新索引中的轮数和时间
            if self._current_session_id in self._index:
                self._index[self._current_session_id]["turn_count"] = len(session.turns)
                self._index[self._current_session_id]["updated_at"] = session.updated_at.isoformat()
                self._save_index()

            # 超过50轮自动压缩
            if len(session.turns) >= MAX_TURNS_BEFORE_COMPRESS:
                logger.info(
                    "add_turn：会话 %s 达到 %d 轮，触发自动压缩",
                    self._current_session_id,
                    len(session.turns),
                )
                self._compress_session_impl(self._current_session_id)

            logger.debug("add_turn：会话 %s 新增 %s 轮 → 共 %d 轮",
                         self._current_session_id, role, len(session.turns))
            return turn

    def compress_session(self, session_id: Optional[str] = None) -> str:
        """将指定会话（或当前会话）压缩为 .json.gz 文件。

        压缩后：
          - turns 列表被清空（释放内存）
          - compressed 标记为 True
          - 会话从活跃列表中移除
          - 索引文件更新

        Args:
            session_id: 要压缩的会话 ID。如果为 None，压缩当前会话。

        Returns:
            压缩文件的路径

        Raises:
            ValueError: 会话不存在或不是活跃会话

        类比：
          - Python:  gzip.open() + json.dump() —— 序列化 + 压缩
          - JS:      zlib.gzipSync(JSON.stringify(data)) —— 同步压缩
          - 通用:    Git 的 git gc —— 将松散对象打包为 packfile
        """
        with self._lock:
            target_id = session_id or self._current_session_id
            if target_id is None:
                raise ValueError("没有指定 session_id，且没有当前活跃会话")
            if target_id not in self._active_sessions:
                raise ValueError(f"会话 {target_id} 不是活跃会话（可能已压缩或不存在）")

            return self._compress_session_impl(target_id)

    def decompress_session(self, session_id: str) -> ConversationSession:
        """从 .json.gz 文件中解压会话到内存。

        解压后会话变为活跃状态，可继续添加轮次。

        Args:
            session_id: 要解压的会话 ID

        Returns:
            解压后的 ConversationSession 对象

        Raises:
            ValueError: 会话不存在于索引中，或找不到对应的压缩文件

        类比：
          - Python:  gzip.open() + json.load() —— 解压 + 反序列化
          - JS:      zlib.gunzipSync(fs.readFileSync(path)) —— 同步解压
          - 通用:    Git 的 git unpack-objects —— 从 packfile 恢复到松散对象
        """
        with self._lock:
            if session_id not in self._index:
                raise ValueError(f"会话 {session_id} 不在索引中")

            # 如果已经在活跃列表中，直接返回
            if session_id in self._active_sessions:
                return self._active_sessions[session_id]

            return self._decompress_session_impl(session_id)

    def list_sessions(self) -> List[Dict]:
        """列出所有会话的摘要信息（包括已压缩的）。

        Returns:
            会话摘要列表，每项包含：
            - session_id:    会话 ID
            - created_at:    创建时间
            - updated_at:    最后更新时间
            - turn_count:    轮数
            - compressed:    是否已压缩
            - is_current:    是否为当前活跃会话
            - metadata:      元数据

        类比：
          - Python:  os.listdir() + 元数据汇总
          - JS:      Array.map() 生成摘要列表
          - 通用:    ChatGPT 左侧边栏的对话列表
        """
        with self._lock:
            result = []
            for sid, info in self._index.items():
                item = dict(info)  # 浅拷贝
                item["is_current"] = (sid == self._current_session_id)
                # 如果会话在活跃列表中，用实际轮数覆盖
                if sid in self._active_sessions:
                    item["turn_count"] = len(self._active_sessions[sid].turns)
                    item["compressed"] = False
                result.append(item)

            # 按更新时间倒序排列（最近的在前面）
            result.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
            return result

    def search_history(self, keyword: str) -> List[Dict]:
        """在所有会话历史中搜索关键词。

        搜索范围：
          - 所有活跃会话的轮次
          - 所有已压缩会话的轮次（自动解压后搜索，搜索完毕可选择保留或重新压缩）

        匹配逻辑：
          - 在 Turn.content 中进行子字符串匹配（不区分大小写）
          - 匹配的会话会被自动解压（如果之前是压缩状态）

        Args:
            keyword: 搜索关键词

        Returns:
            匹配结果列表，每项包含：
            - session_id:      会话 ID
            - turn_index:      轮次索引（从0开始）
            - role:            角色
            - content_preview: 内容预览（关键词前后各80字符）
            - timestamp:       该轮的时间戳
            - query_refs:      关联的查询 ID

        类比：
          - Python:  str.find() 或 re.search() 进行子字符串匹配
          - JS:      String.prototype.includes() 或 indexOf()
          - 通用:    ChatGPT 的搜索对话功能
                    浏览器的 Ctrl+F 页面搜索
                    grep 命令行工具
        """
        with self._lock:
            results = []
            keyword_lower = keyword.lower()

            # ---------- 1. 搜索活跃会话 ----------
            for sid, session in self._active_sessions.items():
                for i, turn in enumerate(session.turns):
                    if keyword_lower in turn.content.lower():
                        results.append(self._build_search_result(sid, i, turn, keyword))

            # ---------- 2. 搜索已压缩会话 ----------
            for sid, info in self._index.items():
                # 跳过已经在活跃列表中搜索过的
                if sid in self._active_sessions:
                    continue
                # 跳过未压缩的（理论上不应该出现，但防御一下）
                if not info.get("compressed"):
                    continue

                file_path = info.get("file_path")
                if file_path is None or not os.path.exists(file_path):
                    logger.warning("search_history：会话 %s 的压缩文件 %s 不存在，跳过",
                                   sid, file_path)
                    continue

                try:
                    # 临时解压以进行搜索
                    with gzip.open(file_path, "rt", encoding="utf-8") as f:
                        session_data = json.load(f)
                        turns_data = session_data.get("turns", [])

                    for i, turn_data in enumerate(turns_data):
                        content = turn_data.get("content", "")
                        if keyword_lower in content.lower():
                            # 将 ISO 时间戳转为字符串展示
                            ts = turn_data.get("timestamp", "")
                            results.append({
                                "session_id": sid,
                                "turn_index": i,
                                "role": turn_data.get("role", ""),
                                "content_preview": _preview_around(content, keyword, context_chars=80),
                                "timestamp": ts,
                                "query_refs": turn_data.get("query_refs", []),
                                "compressed": True,  # 标记该会话当前是压缩状态
                            })
                except Exception as e:
                    logger.error("search_history：读取压缩文件 %s 失败：%s", file_path, e)
                    continue

            logger.info("search_history：关键词 '%s' → %d 条匹配", keyword, len(results))
            return results

    def get_current_session(self) -> Optional[ConversationSession]:
        """获取当前活跃会话。

        Returns:
            当前的 ConversationSession 对象，如果没有当前会话则返回 None

        类比：
          - Python:  threading.current_thread() —— 获取当前上下文
          - JS:      document.activeElement —— 获取当前焦点元素
        """
        with self._lock:
            if self._current_session_id is None:
                return None
            return self._active_sessions.get(self._current_session_id)

    def export_session(
        self,
        session_id: str,
        format: Literal["json", "markdown"] = "json",
    ) -> str:
        """导出指定会话为 JSON 或 Markdown 格式的字符串。

        如果会话是压缩状态，会临时解压以读取数据，但不会加载到活跃列表中。

        Args:
            session_id: 要导出的会话 ID
            format:     导出格式 —— "json" 或 "markdown"

        Returns:
            导出内容的字符串

        Raises:
            KeyError: 会话不存在

        类比：
          - Python:  json.dumps() —— JSON 序列化
          - JS:      JSON.stringify() —— 同上
          - 通用:    ChatGPT 的 "Share Chat" / "Export Data" 功能
                    Evernote 的导出为 HTML 功能
        """
        with self._lock:
            # 尝试从活跃会话获取
            if session_id in self._active_sessions:
                session = self._active_sessions[session_id]
                return self._export_session_obj(session, format)

            # 尝试从压缩文件中读取
            if session_id in self._index:
                info = self._index[session_id]
                file_path = info.get("file_path")
                if file_path and os.path.exists(file_path):
                    with gzip.open(file_path, "rt", encoding="utf-8") as f:
                        data = json.load(f)
                    session = ConversationSession.from_dict(data)
                    return self._export_session_obj(session, format)
                else:
                    # 索引中有但文件不存在
                    raise KeyError(
                        f"会话 {session_id} 的索引记录存在但压缩文件缺失：{file_path}"
                    )

            raise KeyError(f"会话 {session_id} 不存在（活跃列表和索引中均未找到）")

    # ------------------------------------------------------------------
    # 内部实现方法（加锁由上层公开方法负责）
    # ------------------------------------------------------------------

    def _touch_lru(self, session_id: str) -> None:
        """更新 LRU 顺序：将该会话移到最近使用端（列表末尾）。

        类比：
          - Python:  functools.lru_cache 内部的双向链表节点移动
          - JS:      Map 迭代顺序 —— 最近 set 的 key 在最后
          - Redis:   Redis LRU 的时钟访问记录
        """
        # 从旧位置移除
        if session_id in self._session_lru:
            self._session_lru.remove(session_id)
        # 追加到末尾（最近使用）
        self._session_lru.append(session_id)

    def _evict_lru_if_needed(self) -> None:
        """如果活跃会话超过上限，淘汰最久未使用的会话（压缩并移除）。

        淘汰策略：
          - 选择 _session_lru[0]（最久未使用）
          - 跳过当前活跃会话（不能淘汰正在使用的）
          - 将其压缩后从活跃列表中移除

        类比：
          - 操作系统:  页面置换算法（Page Replacement）—— LRU 淘汰
          - Redis:     maxmemory-policy volatile-lru
          - Python:    functools.lru_cache 的缓存驱逐
        """
        while len(self._active_sessions) > MAX_ACTIVE_SESSIONS:
            # 找到第一个可淘汰的 LRU 会话
            victim_id = None
            for sid in self._session_lru:
                if sid != self._current_session_id and sid in self._active_sessions:
                    victim_id = sid
                    break

            if victim_id is None:
                # 所有 LRU 条目恰好都是当前会话？不应该发生，但防御一下
                logger.warning("_evict_lru_if_needed：找不到可淘汰的会话，跳过")
                break

            logger.info("_evict_lru_if_needed：LRU 淘汰会话 %s（活跃数=%d，上限=%d）",
                        victim_id, len(self._active_sessions), MAX_ACTIVE_SESSIONS)
            self._compress_session_impl(victim_id)

    def _compress_session_impl(self, session_id: str) -> str:
        """（内部）将活跃会话压缩为 .json.gz 文件。

        步骤：
          1. 序列化会话为字典
          2. gzip 压缩写入磁盘
          3. 更新索引
          4. 清空 turns（释放内存）
          5. 从活跃列表移除（但保留在索引中）
        """
        session = self._active_sessions[session_id]

        # 生成文件路径
        file_name = f"{session_id}.json.gz"
        file_path = self._base_dir / file_name

        # 序列化 + 压缩写入
        session_dict = session.to_dict()
        json_bytes = json.dumps(session_dict, ensure_ascii=False, indent=2).encode("utf-8")

        with gzip.open(str(file_path), "wb", compresslevel=6) as f:
            f.write(json_bytes)

        # 更新会话对象状态
        session.compressed = True
        session.file_path = str(file_path)
        session.turns = []  # 释放内存

        # 更新索引
        self._index[session_id] = {
            "session_id": session_id,
            "created_at": session.created_at.isoformat(),
            "updated_at": session.updated_at.isoformat(),
            "turn_count": len(session_dict.get("turns", [])),
            "compressed": True,
            "file_path": str(file_path),
            "metadata": session.metadata,
        }
        self._save_index()

        # 从活跃列表中移除
        self._active_sessions.pop(session_id, None)
        if session_id in self._session_lru:
            self._session_lru.remove(session_id)

        logger.info("_compress_session_impl：会话 %s 已压缩 → %s", session_id, file_path)
        return str(file_path)

    def _decompress_session_impl(self, session_id: str) -> ConversationSession:
        """（内部）从 .json.gz 文件解压会话到内存。

        步骤：
          1. 从索引获取文件路径
          2. gzip 解压 + JSON 反序列化
          3. 重建 ConversationSession 对象
          4. 加入活跃列表
          5. LRU 检查（可能触发淘汰）
        """
        info = self._index.get(session_id)
        if info is None:
            raise ValueError(f"会话 {session_id} 不在索引中")

        file_path = info.get("file_path")
        if file_path is None or not os.path.exists(file_path):
            raise ValueError(f"会话 {session_id} 的压缩文件不存在：{file_path}")

        # 读取并解压
        with gzip.open(file_path, "rt", encoding="utf-8") as f:
            data = json.load(f)

        # 反序列化
        session = ConversationSession.from_dict(data)
        session.compressed = False
        session.file_path = None  # 清除压缩文件路径标记

        # 加入活跃列表
        self._active_sessions[session_id] = session
        self._touch_lru(session_id)

        # 更新索引
        self._index[session_id] = {
            "session_id": session_id,
            "created_at": session.created_at.isoformat(),
            "updated_at": session.updated_at.isoformat(),
            "turn_count": len(session.turns),
            "compressed": False,
            "file_path": None,
            "metadata": session.metadata,
        }
        self._save_index()

        # LRU 淘汰检查
        self._evict_lru_if_needed()

        logger.info("_decompress_session_impl：会话 %s 已解压（%d 轮）",
                    session_id, len(session.turns))
        return session

    def _export_session_obj(self, session: ConversationSession, format: str) -> str:
        """将会话对象导出为指定格式的字符串。"""
        if format == "json":
            return json.dumps(session.to_dict(), ensure_ascii=False, indent=2)
        elif format == "markdown":
            return self._to_markdown(session)
        else:
            raise ValueError(f"不支持的导出格式：{format}（仅支持 'json' 或 'markdown'）")

    def _to_markdown(self, session: ConversationSession) -> str:
        """将会话转换为 Markdown 格式。

        格式示例：
            # 会话：abc123
            > 创建时间：2025-01-15 10:30:00 UTC

            ## 第 1 轮
            **user**（2025-01-15 10:30:05）：
            你好，请帮我分析...

            **assistant**（2025-01-15 10:30:12）：
            好的，分析结果如下...
        """
        lines = []
        lines.append(f"# 会话：{session.session_id}")
        lines.append(f"> 创建时间：{session.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"> 最后更新：{session.updated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"> 总轮数：{len(session.turns)}")
        if session.metadata:
            lines.append(f"> 元数据：{json.dumps(session.metadata, ensure_ascii=False)}")
        lines.append("")

        for i, turn in enumerate(session.turns, start=1):
            lines.append(f"## 第 {i} 轮")
            ts = turn.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            lines.append(f"**{turn.role}**（{ts}）：")
            lines.append("")
            lines.append(turn.content)
            lines.append("")
            if turn.query_refs:
                refs = ", ".join(turn.query_refs)
                lines.append(f"> 关联查询：{refs}")
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def _build_search_result(
        self,
        session_id: str,
        turn_index: int,
        turn: Turn,
        keyword: str,
    ) -> Dict:
        """构建单条搜索结果字典。"""
        return {
            "session_id": session_id,
            "turn_index": turn_index,
            "role": turn.role,
            "content_preview": _preview_around(turn.content, keyword, context_chars=80),
            "timestamp": turn.timestamp.isoformat(),
            "query_refs": turn.query_refs,
            "compressed": False,  # 来自活跃会话
        }

    def _load_index(self) -> None:
        """从磁盘加载索引文件 index.json。

        如果索引文件不存在，创建一个空的索引。
        """
        index_path = self._base_dir / INDEX_FILE_NAME
        if index_path.exists():
            try:
                with open(index_path, "r", encoding="utf-8") as f:
                    self._index = json.load(f)
                logger.debug("_load_index：已加载索引，%d 个会话", len(self._index))
            except (json.JSONDecodeError, IOError) as e:
                logger.warning("_load_index：索引文件损坏（%s），重建空索引", e)
                self._index = {}
                self._save_index()
        else:
            self._index = {}
            self._save_index()
            logger.debug("_load_index：索引文件不存在，已创建空索引")

    def _save_index(self) -> None:
        """将索引字典持久化到 index.json。

        类比：
          - Python:  json.dump() —— 原子写入磁盘
          - JS:      fs.writeFileSync() —— 同步写入
          - 通用:    SQLite 的 WAL 日志 —— 先写日志再更新主文件
        """
        index_path = self._base_dir / INDEX_FILE_NAME
        # 先写临时文件再原子重命名，避免写入过程中崩溃导致索引损坏
        tmp_path = self._base_dir / (INDEX_FILE_NAME + ".tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self._index, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, index_path)  # 原子操作（Windows / POSIX 均支持）
        except Exception as e:
            logger.error("_save_index：保存索引失败：%s", e)
            raise


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------


def _preview_around(text: str, keyword: str, context_chars: int = 80) -> str:
    """提取关键词周围的文本预览。

    在文本中找到关键词（不区分大小写），截取其前后各 context_chars 个字符。

    Args:
        text:          全文
        keyword:       搜索关键词
        context_chars: 前后保留的字符数

    Returns:
        预览字符串，例如 "...这是关键词周围的文本..."

    类比：
      - Python:  textwrap.shorten() —— 截断并添加省略号
      - JS:      String.prototype.slice() —— 子字符串截取
      - 通用:    Google 搜索结果的摘要片段（snippet）
    """
    if not keyword or not text:
        return text[: context_chars * 2] if text else ""

    # 找到关键词位置（不区分大小写）
    idx = text.lower().find(keyword.lower())
    if idx == -1:
        # 关键词未找到（理论上不应发生），返回开头
        return text[: context_chars * 2] + ("..." if len(text) > context_chars * 2 else "")

    # 计算截取范围
    start = max(0, idx - context_chars)
    end = min(len(text), idx + len(keyword) + context_chars)

    preview = ""
    if start > 0:
        preview += "..."
    preview += text[start:end]
    if end < len(text):
        preview += "..."

    return preview


# ---------------------------------------------------------------------------
# 模块自测
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    # 简单的冒烟测试
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s:%(name)s:%(message)s")

    mgr = ConversationManager()

    # 1. 创建会话
    sid = mgr.create_session(metadata={"template": "test", "user": "tester"})
    print(f"✅ 创建会话：{sid}")

    # 2. 添加轮次
    mgr.add_turn("user", "你好，请帮我分析这段代码的性能瓶颈")
    mgr.add_turn("assistant", "好的，我来分析...（分析结果）")
    print(f"✅ 当前会话轮数：{len(mgr.get_current_session().turns)}")

    # 3. 列出所有会话
    sessions = mgr.list_sessions()
    print(f"✅ 会话列表：{len(sessions)} 个")

    # 4. 搜索历史
    results = mgr.search_history("性能瓶颈")
    print(f"✅ 搜索 '性能瓶颈' → {len(results)} 条结果")
    for r in results:
        print(f"   - {r['session_id']}[{r['turn_index']}] {r['role']}: {r['content_preview'][:60]}...")

    # 5. 压缩会话
    compressed_path = mgr.compress_session(sid)
    print(f"✅ 已压缩到：{compressed_path}")

    # 6. 搜索历史（应能搜索到压缩会话）
    results2 = mgr.search_history("性能瓶颈")
    print(f"✅ 压缩后搜索 '性能瓶颈' → {len(results2)} 条结果")

    # 7. 解压会话
    session = mgr.decompress_session(sid)
    print(f"✅ 已解压会话：{session.session_id}，{len(session.turns)} 轮")

    # 8. 导出
    md = mgr.export_session(sid, format="markdown")
    print(f"✅ Markdown 导出（前200字符）：\n{md[:200]}...")

    print("\n🎉 全部冒烟测试通过！")
