"""
结构化查询日志 (Structured Query Logger)
==========================================
类比 Python structlog / Go zerolog — 输出 JSON 格式的结构化日志，
而非 print() 的纯文本。每条查询被记录为一行 JSON（JSONL），
便于后续用 jq、pandas、ELK 等工具分析。

输出文件：data/logs/query_{date}.jsonl
"""

import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional


# ===========================================================================
# 1. QueryLogEntry 数据类 — 单条查询日志的结构定义
# ===========================================================================

@dataclass
class QueryLogEntry:
    """
    单条查询的结构化日志条目。

    每个字段对应查询生命周期中的一个关键维度，
    便于后续按任意维度过滤、聚合和统计。

    字段说明
    --------
    query_id : str
        全局唯一的查询标识符（UUID v4）。
    session_id : str
        关联的对话会话 ID，用于把查询归到同一个对话上下文中。
    timestamp : str
        ISO 8601 格式的时间戳（精确到毫秒）。
    template_name : str
        使用的查询模板名称；若未使用模板则为 "raw"。
    query_sources : List[str]
        查询涉及的数据源列表（如 ["postgres", "redis", "elasticsearch"]）。
    duration_ms : float
        查询总耗时，单位毫秒。
    result_summary : str
        结果摘要，截断到前 200 字符。
    degradation_level : int
        降级级别：0 = 正常，1 = 部分降级，2 = 严重降级，3 = 完全失败。
    errors : List[str]
        查询过程中遇到的错误消息列表。
    metadata : Dict[str, Any]
        自由扩展的元数据字典，可存放任意键值对。
    """

    query_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    """全局唯一查询 ID（UUID v4）"""

    session_id: str = ""
    """关联的会话 ID"""

    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"))
    """ISO 8601 UTC 时间戳"""

    template_name: str = "raw"
    """使用的模板名称"""

    query_sources: List[str] = field(default_factory=list)
    """查询数据源列表"""

    duration_ms: float = 0.0
    """耗时（毫秒）"""

    result_summary: str = ""
    """结果摘要（≤200 字符）"""

    degradation_level: int = 0
    """降级级别：0=正常, 1=部分降级, 2=严重降级, 3=完全失败"""

    errors: List[str] = field(default_factory=list)
    """错误消息列表"""

    metadata: Dict[str, Any] = field(default_factory=dict)
    """扩展元数据"""

    # ── 内部常量 ──
    _SUMMARY_MAX_LENGTH: ClassVar[int] = 200  # 结果摘要最大长度（类私有常量，ClassVar 避免被 asdict 序列化）

    def to_dict(self) -> Dict[str, Any]:
        """
        将条目序列化为字典（用于 JSON 写入）。

        会自动截断 result_summary 到 _SUMMARY_MAX_LENGTH 字符。
        """
        d = asdict(self)
        # 截断摘要到规定长度
        summary = d.get("result_summary", "")
        if isinstance(summary, str) and len(summary) > self._SUMMARY_MAX_LENGTH:
            d["result_summary"] = summary[: self._SUMMARY_MAX_LENGTH]
        return d

    def to_json(self) -> str:
        """
        将条目序列化为单行 JSON 字符串（紧凑格式，适合 JSONL）。
        """
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))


# ===========================================================================
# 2. QueryLogger 类 — 查询日志写入和检索
# ===========================================================================

class QueryLogger:
    """
    结构化查询日志记录器 — 将每条查询以 JSONL 格式持久化到磁盘。

    使用方式
    --------
    >>> logger = QueryLogger()
    >>> entry = QueryLogEntry(session_id="abc", template_name="search", duration_ms=42.0)
    >>> logger.log(entry)
    >>> results = logger.search({"session_id": "abc"})
    >>> stats = logger.get_stats()

    日志文件路径
    ------------
    data/logs/query_{YYYY-MM-DD}.jsonl  — 按日期自动分文件。

    线程安全
    --------
    文件写入在 _write_lock 保护下进行；同一时刻只有一个线程在写文件。
    """

    # ── 路径默认值 ──
    DEFAULT_LOG_DIR = os.path.join("data", "logs")
    """默认日志目录"""

    DEFAULT_MAX_SIZE_MB = 50
    """默认日志文件大小上限（MiB）"""

    # ── 构造函数 ──

    def __init__(self, log_dir: Optional[str] = None, max_size_mb: float = DEFAULT_MAX_SIZE_MB):
        """
        初始化查询日志记录器。

        参数
        ----
        log_dir : str, optional
            日志文件存放目录。默认 "data/logs"。
        max_size_mb : float
            单个日志文件大小上限（MiB）。默认 50 MiB。
        """
        self._log_dir = Path(log_dir or self.DEFAULT_LOG_DIR)
        self._max_size_bytes = int(max_size_mb * 1024 * 1024)
        self._write_lock = threading.Lock()  # 线程安全写锁

        # 确保日志目录存在
        self._log_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 公开 API — 写入日志
    # ------------------------------------------------------------------

    def log(self, entry: QueryLogEntry) -> str:
        """
        写入一条查询日志（追加到当前日期的 JSONL 文件）。

        参数
        ----
        entry : QueryLogEntry
            要记录的查询日志条目。

        返回
        ----
        str — 该条目的 query_id，方便调用方后续引用。

        副作用
        ------
        - 追加一行 JSON 到 data/logs/query_{date}.jsonl
        - 写入后检查文件大小，若超过阈值则自动轮转
        """
        # 确定当天的日志文件路径
        filepath = self._today_filepath()

        # 序列化为一行 JSON
        line = entry.to_json() + "\n"

        # ── 线程安全写入 ──
        with self._write_lock:
            # 写入前检查是否需要轮转（在锁内避免竞态）
            if self._should_rotate(filepath):
                self._rotate_file(filepath)

            with open(filepath, "a", encoding="utf-8") as fh:
                fh.write(line)

        return entry.query_id

    # ------------------------------------------------------------------
    # 公开 API — 检索日志
    # ------------------------------------------------------------------

    def search(self, filters: Dict[str, Any],
               days_back: int = 7,
               limit: int = 100) -> List[Dict[str, Any]]:
        """
        按条件检索查询日志。

        参数
        ----
        filters : dict
            过滤条件字典，键为字段名，值为期望匹配的值。
            对字符串字段执行模糊匹配（子串包含），对数值/列表执行精确匹配。
            示例：{"session_id": "abc", "degradation_level": 2}
        days_back : int
            向前搜索多少天的日志文件。默认 7 天。
        limit : int
            最多返回的条数。默认 100。

        返回
        ----
        List[dict] — 匹配的日志条目列表（按时间倒序）。
        """
        results: List[Dict[str, Any]] = []

        # 收集最近 N 天的日志文件
        today = datetime.now(timezone.utc).date()
        for offset in range(days_back):
            date = today - timedelta(days=offset)
            filepath = self._filepath_for_date(date)
            if not filepath.exists():
                continue

            # 逐行读取 JSONL，按过滤条件筛选
            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry_dict = json.loads(line)
                        except json.JSONDecodeError:
                            continue  # 跳过损坏行

                        # 检查是否满足所有过滤条件
                        if self._matches_filters(entry_dict, filters):
                            results.append(entry_dict)
                            if len(results) >= limit:
                                break
            except FileNotFoundError:
                continue

            if len(results) >= limit:
                break

        # 按时间戳倒序排列（最新的在前）
        results.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        return results

    # ------------------------------------------------------------------
    # 公开 API — 统计信息
    # ------------------------------------------------------------------

    def get_stats(self, days_back: int = 7) -> Dict[str, Any]:
        """
        计算指定时间窗口内的统计信息。

        参数
        ----
        days_back : int
            统计最近多少天的日志。默认 7 天。

        返回
        ----
        dict — 包含以下键：
            total_queries : int            — 总查询数
            avg_duration_ms : float        — 平均延迟（毫秒）
            degradation_rate : float       — 降级率（降级查询 / 总查询）
            degradation_breakdown : dict   — 各级别降级的数量分布
            errors_count : int             — 包含错误的查询数
            date_range : dict              — 统计的日期范围
        """
        total = 0
        total_duration = 0.0
        degradation_count = 0
        degradation_breakdown: Dict[int, int] = {}
        errors_count = 0

        today = datetime.now(timezone.utc).date()
        dates_scanned: List[str] = []

        for offset in range(days_back):
            date = today - timedelta(days=offset)
            filepath = self._filepath_for_date(date)
            if not filepath.exists():
                continue

            dates_scanned.append(date.isoformat())

            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        total += 1
                        total_duration += entry.get("duration_ms", 0.0)

                        level = entry.get("degradation_level", 0)
                        if level > 0:
                            degradation_count += 1
                            degradation_breakdown[level] = (
                                degradation_breakdown.get(level, 0) + 1
                            )

                        errs = entry.get("errors", [])
                        if errs and len(errs) > 0:
                            errors_count += 1

            except FileNotFoundError:
                continue

        # 计算统计值（避免除零）
        avg_duration = total_duration / total if total > 0 else 0.0
        degradation_rate = degradation_count / total if total > 0 else 0.0

        return {
            "total_queries": total,
            "avg_duration_ms": round(avg_duration, 2),
            "degradation_rate": round(degradation_rate, 4),
            "degradation_breakdown": degradation_breakdown,
            "errors_count": errors_count,
            "date_range": {
                "start": dates_scanned[-1] if dates_scanned else today.isoformat(),
                "end": dates_scanned[0] if dates_scanned else today.isoformat(),
                "days_scanned": len(dates_scanned),
            },
        }

    # ------------------------------------------------------------------
    # 公开 API — 日志轮转
    # ------------------------------------------------------------------

    def rotate(self, max_size_mb: Optional[float] = None) -> int:
        """
        手动触发日志轮转：将当天的日志文件重命名为带序号的归档文件。

        参数
        ----
        max_size_mb : float, optional
            如果提供，临时覆盖轮转阈值（MiB）。本次调用结束后恢复原阈值。

        返回
        ----
        int — 本次轮转的文件数。
        """
        old_max_size = self._max_size_bytes  # 保存原值以便恢复
        if max_size_mb is not None:
            self._max_size_bytes = int(max_size_mb * 1024 * 1024)

        try:
            rotated = 0
            filepath = self._today_filepath()

            with self._write_lock:
                if filepath.exists():
                    self._rotate_file(filepath)
                    rotated = 1

            return rotated
        finally:
            if max_size_mb is not None:
                self._max_size_bytes = old_max_size  # 恢复原阈值

    # ------------------------------------------------------------------
    # 公开 API — 导出
    # ------------------------------------------------------------------

    def export(self, format: str = "jsonl",
               output_path: Optional[str] = None,
               days_back: int = 7) -> str:
        """
        导出指定时间窗口的日志。

        参数
        ----
        format : str
            导出格式。目前支持 "jsonl"。
        output_path : str, optional
            导出文件路径。默认 "data/logs/export_{timestamp}.jsonl"。
        days_back : int
            导出最近多少天。默认 7。

        返回
        ----
        str — 导出文件的绝对路径。
        """
        if format != "jsonl":
            raise ValueError(f"不支持的导出格式: {format}。目前仅支持 'jsonl'。")

        # 生成导出路径
        if output_path is None:
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            output_path = str(self._log_dir / f"export_{ts}.jsonl")

        export_path = Path(output_path)
        export_path.parent.mkdir(parents=True, exist_ok=True)

        total_lines = 0
        today = datetime.now(timezone.utc).date()

        with open(export_path, "w", encoding="utf-8") as out_fh:
            for offset in range(days_back):
                date = today - timedelta(days=offset)
                filepath = self._filepath_for_date(date)
                if not filepath.exists():
                    continue

                with open(filepath, "r", encoding="utf-8") as in_fh:
                    for line in in_fh:
                        out_fh.write(line)
                        total_lines += 1

        print(f"[QueryLogger] 导出完成: {total_lines} 条 → {export_path}")
        return str(export_path.absolute())

    # ==================================================================
    # 内部方法 — 文件路径 & 轮转逻辑
    # ==================================================================

    def _today_filepath(self) -> Path:
        """
        返回当天日志文件的绝对路径。

        文件名格式：query_{YYYY-MM-DD}.jsonl
        """
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self._log_dir / f"query_{today_str}.jsonl"

    def _filepath_for_date(self, date: datetime.date) -> Path:
        """
        返回指定日期的日志文件路径。

        参数
        ----
        date : datetime.date
            指定日期。

        返回
        ----
        Path — 对应日期的日志文件路径。
        """
        return self._log_dir / f"query_{date.isoformat()}.jsonl"

    def _should_rotate(self, filepath: Path) -> bool:
        """
        检查指定文件是否超过轮转大小阈值。

        参数
        ----
        filepath : Path
            要检查的日志文件路径。

        返回
        ----
        bool — True 表示需要轮转。
        """
        if not filepath.exists():
            return False
        return filepath.stat().st_size >= self._max_size_bytes

    def _rotate_file(self, filepath: Path) -> None:
        """
        对指定日志文件执行轮转（重命名为带递增序号的名称）。

        轮转命名规则：query_{date}.jsonl → query_{date}.1.jsonl
        如果 .1 已存在则递增为 .2，以此类推。

        参数
        ----
        filepath : Path
            要轮转的日志文件路径。

        注意
        ----
        此方法在 _write_lock 内调用，调用方需确保已持有锁。
        """
        if not filepath.exists():
            return

        # 找到下一个可用的序号
        stem = filepath.stem  # 如 query_2025-01-15
        idx = 1
        while True:
            rotated_path = filepath.with_name(f"{stem}.{idx}.jsonl")
            if not rotated_path.exists():
                break
            idx += 1

        filepath.rename(rotated_path)
        print(f"[QueryLogger] 日志轮转: {filepath.name} → {rotated_path.name}")

    # ------------------------------------------------------------------
    # 内部方法 — 过滤匹配
    # ------------------------------------------------------------------

    @staticmethod
    def _matches_filters(entry_dict: Dict[str, Any],
                         filters: Dict[str, Any]) -> bool:
        """
        检查一条日志条目是否满足所有过滤条件。

        匹配规则
        --------
        - 字符串字段：子串包含匹配（不区分大小写）。
        - 数值字段：精确匹配。
        - 列表字段：精确匹配（整个列表相等）。

        参数
        ----
        entry_dict : dict
            已解析的日志条目。
        filters : dict
            过滤条件。

        返回
        ----
        bool — 是否所有条件都满足。
        """
        for key, expected in filters.items():
            actual = entry_dict.get(key)

            # 值不存在直接不匹配
            if actual is None and expected is not None:
                return False

            # 字符串：子串包含（不区分大小写）
            if isinstance(expected, str) and isinstance(actual, str):
                if expected.lower() not in actual.lower():
                    return False

            # 列表：精确匹配
            elif isinstance(expected, list) and isinstance(actual, list):
                if expected != actual:
                    return False

            # 数值/其他：精确匹配
            else:
                if actual != expected:
                    return False

        return True


# ===========================================================================
# 模块自测 — 验证基本功能
# ===========================================================================

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("QueryLogger 自测")
    print("=" * 60)

    # ── 使用临时目录避免污染实际日志 ──
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = QueryLogger(log_dir=tmpdir, max_size_mb=0.001)  # 1 KB 阈值方便测轮转

        # ── 1. 写入几条不同的查询日志 ──
        print("\n1. 写入查询日志...")

        # 正常查询
        e1 = QueryLogEntry(
            session_id="session-001",
            template_name="sql_search",
            query_sources=["postgres"],
            duration_ms=23.5,
            result_summary="找到 42 条匹配记录。用户张三在 2025-01-15 创建了订单 #8848...",
            degradation_level=0,
        )
        logger.log(e1)
        print(f"   已记录: {e1.query_id}")

        # 部分降级查询
        e2 = QueryLogEntry(
            session_id="session-001",
            template_name="full_text_search",
            query_sources=["elasticsearch", "redis"],
            duration_ms=150.0,
            result_summary="ES 超时，回退到 Redis 缓存结果。共 8 条。",
            degradation_level=1,
            errors=["elasticsearch timeout after 100ms"],
            metadata={"fallback_used": True, "cache_hit": True},
        )
        logger.log(e2)
        print(f"   已记录: {e2.query_id}")

        # 严重失败的查询
        e3 = QueryLogEntry(
            session_id="session-002",
            template_name="raw",
            query_sources=["postgres", "elasticsearch"],
            duration_ms=5200.0,
            result_summary="所有数据源不可用。",
            degradation_level=3,
            errors=["postgres connection refused", "elasticsearch cluster unreachable"],
            metadata={"retry_count": 3, "final_status": "complete_failure"},
        )
        logger.log(e3)
        print(f"   已记录: {e3.query_id}")

        # ── 2. 检索日志 ──
        print("\n2. 检索日志...")
        results = logger.search({"session_id": "session-001"}, days_back=1)
        print(f"   session-001 匹配: {len(results)} 条")
        for r in results:
            print(f"     - {r['template_name']}: {r['result_summary'][:50]}...")

        # ── 3. 统计信息 ──
        print("\n3. 统计信息...")
        stats = logger.get_stats(days_back=1)
        print(f"   总查询数: {stats['total_queries']}")
        print(f"   平均延迟: {stats['avg_duration_ms']} ms")
        print(f"   降级率:   {stats['degradation_rate']}")
        print(f"   降级分布: {stats['degradation_breakdown']}")
        print(f"   含错误:   {stats['errors_count']}")
        print(f"   日期范围: {stats['date_range']}")

        # ── 4. 日志轮转 ──
        print("\n4. 日志轮转 (阈值 1KB)...")
        # 写入大量数据触发轮转
        big_entry = QueryLogEntry(
            session_id="bulk",
            template_name="stress",
            result_summary="X" * 200,  # 填满摘要
            metadata={"padding": "Y" * 500},  # 增加体积
        )
        for _ in range(20):
            logger.log(big_entry)
        # 检查是否有轮转文件
        rotated_files = list(Path(tmpdir).glob("query_*.1.jsonl"))
        print(f"   轮转后 .1 文件数: {len(rotated_files)}")
        if rotated_files:
            print(f"   轮转文件: {rotated_files[0].name}")

        # ── 5. 导出 ──
        print("\n5. 导出 JSONL...")
        export_path = logger.export(format="jsonl", days_back=1)
        print(f"   导出至: {export_path}")
        with open(export_path, "r", encoding="utf-8") as f:
            line_count = sum(1 for _ in f)
        print(f"   导出行数: {line_count}")

        # ── 6. 展示 JSON 格式 vs 普通 print ──
        print("\n6. JSON 格式示例（对比 print）...")
        sample = e1.to_json()
        print(f"   JSONL: {sample}")

    print("\n✅ 自测完成")
