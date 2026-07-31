#!/usr/bin/env python3
"""
Query Guardian — 五层查询防护系统
===================================
从 protect_plass 架构平移而来，专为 AI 查询框架设计。

五层防护：
  ┌──────────────────────────────────────────────────────────────┐
  │ 第1层: ProgressiveQueryEngine — 渐进式查询（漏斗过滤）       │
  │ 第2层: QueryBackpressure     — 查询背压（队列+延迟+限流）    │
  │ 第3层: ContextMemoryGC       — 上下文内存 GC（KV Cache 回收）│
  │ 第4层: QueryWatchdog         — 查询看门狗（超时熔断）        │
  │ 第5层: ResponseDegrader      — 回答降级（4 级降级策略）      │
  └──────────────────────────────────────────────────────────────┘

核心理念：
  不是"崩了再重启"——而是"在崩之前主动降低服务质量以保证存活"。
  99% 的无关查询在底层就被丢弃，只有真正的"硬查询"才走到生成层。

类比：
  - 渐进式查询 = Service Worker 的 Cache-First 策略 +
                数据库的 Index-Only Scan → Filter → Sort → Limit
  - 背压      = TCP 拥塞控制 + Node.js stream.pipe() 的背压机制
  - 内存 GC   = JVM GC（Young/Old 代）+ Redis maxmemory-policy
  - 看门狗    = 硬件看门狗定时器 + Kubernetes liveness probe
  - 降级      = CloudFront 的 Error Pages + Circuit Breaker 模式
"""

import os
import sys
import time
import signal
import threading
import logging
import hashlib
import json
import gc
from abc import ABC, abstractmethod
from collections import deque, OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Tuple, Set
from enum import IntEnum, Enum
from concurrent.futures import ThreadPoolExecutor, Future, TimeoutError as FutureTimeoutError

# ================================================================
# 可选依赖检查
# ================================================================
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ================================================================
# 常量与枚举
# ================================================================

class DegradationLevel(IntEnum):
    """
    回答降级级别——数字越大降级越激进。

    类比：HTTP 状态码
      200 FULL      — 正常完整响应
      304 REDUCED   — 缓存命中（Not Modified）
      503 MINIMAL    — 服务降级（Service Unavailable 但有 fallback）
      500 EMERGENCY  — 紧急拒答（Internal Server Error）
    """
    FULL = 0        # 全量 RAG + 多轮推理（最优质量）
    REDUCED = 1     # 缓存命中直接返回（中质量）
    MINIMAL = 2     # 预置模板回答（低质量但可用）
    EMERGENCY = 3   # 拒答 + 告警（只保证不崩溃）


class QueryLayer(IntEnum):
    """
    渐进查询的四层架构。

    类比：数据库查询执行计划的算子树
      CACHE       → Index-Only Scan（直接命中索引，无需回表）
      COARSE_FILTER → Bitmap Index Scan（快速过滤，召回率高）
      FINE_RERANK   → Sort + Limit（精细排序，精确率优先）
      GENERATE      → 最终投影 + JOIN（最昂贵的步骤）
    """
    CACHE = 1        # L1: 精确缓存命中
    COARSE_FILTER = 2  # L2: 粗筛（向量相似度 Top-K）
    FINE_RERANK = 3    # L3: 精排（Cross-Encoder / 重排序）
    GENERATE = 4       # L4: LLM 生成（最贵的一步）


# ================================================================
# 数据类
# ================================================================

@dataclass
class QueryContext:
    """
    查询上下文——封装一次查询的完整生命周期数据。

    类比：HTTP Request 对象
      - query_id    = X-Request-Id
      - query_text  = Request Body
      - source      = User-Agent / Origin
      - start_time  = 打点起始时间
    """
    query_id: str                          # 全局唯一查询 ID
    query_text: str                        # 原始查询文本
    source: str = "default"                # 查询来源（如 "web", "api", "vector_db"）
    start_time: float = field(default_factory=time.time)
    # 每层产出的中间结果
    layer_results: Dict[QueryLayer, Any] = field(default_factory=dict)
    # 额外元数据
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DegradedResponse:
    """
    降级回答——当系统无法给出完整回答时的替代品。

    类比：Nginx 的自定义错误页面
          CloudFront 的 Custom Error Response
    """
    level: DegradationLevel
    answer: str
    is_degraded: bool = True
    original_query: str = ""
    degrade_reason: str = ""
    # 降级回答仍然可以携带部分有用信息
    partial_results: Optional[List[Any]] = None
    cached_at: Optional[float] = None


# ================================================================
# 第1层: ProgressiveQueryEngine — 渐进式查询引擎
# ================================================================

class ProgressiveQueryEngine:
    """
    渐进式查询引擎：四层漏斗，逐层过滤。

    架构：
      ┌─────────────────────────────────────────────────────────┐
      │  输入查询                                               │
      │    ↓                                                    │
      │  [CACHE] ──命中──→ 直接返回（0ms 级延迟）               │
      │    ↓ 未命中                                             │
      │  [COARSE_FILTER] ──Top 1000──→ 粗筛（向量相似度）       │
      │    ↓                                                    │
      │  [FINE_RERANK]   ──Top 50────→ 精排（Cross-Encoder）    │
      │    ↓                                                    │
      │  [GENERATE]      ──最终 Top-K→ LLM 生成回答             │
      └─────────────────────────────────────────────────────────┘

    核心原则：
      - 每层只把 Top-K 推给下一层（漏斗模型）
      - 99% 无关查询在 COARSE_FILTER 层被丢弃
      - 只有真正需要推理的查询才到达 GENERATE 层

    类比：
      - Service Worker 的 Cache-First 策略：
        Cache（L1）→ Network（L4），中间加了两层精筛
      - 搜索引擎的 Query → Recall → Rank → Display 流水线
      - MySQL 的 Index Merge → Filter → Sort → Limit
    """

    # 各层默认最大条目数（类似数据库的 LIMIT 子句）
    DEFAULT_MAX_ITEMS: Dict[QueryLayer, int] = {
        QueryLayer.CACHE: 1,            # 缓存命中只取 1 条
        QueryLayer.COARSE_FILTER: 1000,  # 粗筛保留 1000 条
        QueryLayer.FINE_RERANK: 50,      # 精排保留 50 条
        QueryLayer.GENERATE: 5,          # 最终生成用 Top-5
    }

    def __init__(self, max_items: Optional[Dict[QueryLayer, int]] = None):
        """
        初始化渐进查询引擎。

        Args:
            max_items: 每层最大条目数，不传则使用默认值。
                       例: {QueryLayer.COARSE_FILTER: 500} 表示粗筛层只保留 500 条。

        类比：Elasticsearch 的 size 参数 + rescore 的 window_size
        """
        # 合并用户配置与默认值
        self.max_items = dict(self.DEFAULT_MAX_ITEMS)
        if max_items:
            self.max_items.update(max_items)

        # 缓存存储（简单内存缓存，生产环境应替换为 Redis）
        # 类比：浏览器 Cache Storage API 的 Map 实现
        self._cache: OrderedDict[str, Tuple[float, Any]] = OrderedDict()
        self._cache_max_size: int = 1000  # 最多缓存 1000 条结果

        # 各层的自定义处理器（插件式，可替换）
        # 类比：Koa 中间件机制——每层是一个可插拔的中间件
        self._layer_handlers: Dict[QueryLayer, Optional[Callable]] = {
            QueryLayer.CACHE: None,
            QueryLayer.COARSE_FILTER: None,
            QueryLayer.FINE_RERANK: None,
            QueryLayer.GENERATE: None,
        }

        # 统计信息
        self._stats: Dict[str, int] = {
            "total_queries": 0,           # 总查询数
            "cache_hits": 0,              # 缓存命中数
            "coarse_discarded": 0,        # 粗筛丢弃数（99% 在这里）
            "fine_reranked": 0,           # 进入精排的查询数
            "generated": 0,               # 进入 LLM 生成的查询数
        }
        self._stats_lock = threading.Lock()

    # ------------------------------------------------------------------
    # 缓存层（L1: CACHE）
    # ------------------------------------------------------------------

    def _cache_key(self, query_text: str) -> str:
        """
        生成缓存键。

        使用 SHA256 而非 MD5，避免碰撞攻击。
        类比：HTTP 的 ETag 生成（内容的哈希摘要）
        """
        return hashlib.sha256(query_text.encode("utf-8")).hexdigest()

    def _cache_get(self, query_text: str) -> Optional[Any]:
        """
        从缓存中查找精确匹配。

        类比：Service Worker 的 caches.match(request)
              ——精确 URL 匹配，变一点都不命中
        """
        key = self._cache_key(query_text)
        if key in self._cache:
            # LRU: 命中时移到末尾（最近使用）
            # 类比：Redis LRU 的访问时间戳更新
            timestamp, value = self._cache.pop(key)
            self._cache[key] = (time.time(), value)
            return value
        return None

    def _cache_set(self, query_text: str, value: Any):
        """
        写入缓存，超出容量时淘汰最旧条目。

        类比：Redis 的 volatile-lru 淘汰策略
        """
        key = self._cache_key(query_text)
        # 如果 key 已存在，先移除再插入（更新位置）
        if key in self._cache:
            del self._cache[key]
        # 容量检查：超出时淘汰最旧条目（OrderedDict 开头）
        while len(self._cache) >= self._cache_max_size:
            oldest_key, _ = self._cache.popitem(last=False)  # FIFO 淘汰
        self._cache[key] = (time.time(), value)

    # ------------------------------------------------------------------
    # 层处理器注册
    # ------------------------------------------------------------------

    def register_handler(self, layer: QueryLayer, handler: Callable):
        """
        为指定层注册处理器。

        处理器签名：
          handler(query_text: str, candidates: List[Any], max_items: int) -> List[Any]

        Args:
            layer: 要注册的层
            handler: 处理函数

        类比：Express.js 的 app.use(path, middleware)
              ——为特定路由（层）注册中间件
        """
        self._layer_handlers[layer] = handler

    # ------------------------------------------------------------------
    # 核心执行方法
    # ------------------------------------------------------------------

    def execute(self, query_ctx: QueryContext) -> QueryContext:
        """
        执行渐进式查询：从 L1 到 L4 逐层推进。

        流程：
          1. CACHE 层：查缓存，命中则直接结束
          2. COARSE_FILTER 层：粗筛，只保留 Top-K
          3. FINE_RERANK 层：精排，进一步收窄
          4. GENERATE 层：LLM 生成最终回答

        类比：数据库执行器的火山模型（Volcano Model）
              ——每层调用 next() 从下层拉取，处理后返回给上层
        """
        with self._stats_lock:
            self._stats["total_queries"] += 1

        # ---- L1: CACHE ----
        cache_result = self._execute_cache_layer(query_ctx)
        if cache_result is not None:
            # 缓存命中——直接返回，不再经过后续层
            return query_ctx

        # ---- L2: COARSE_FILTER ----
        coarse_results = self._execute_coarse_filter_layer(query_ctx)
        if coarse_results is None or len(coarse_results) == 0:
            # 粗筛无结果——查询无相关数据
            with self._stats_lock:
                self._stats["coarse_discarded"] += 1
            return query_ctx  # 返回空结果（上层降级处理）

        # ---- L3: FINE_RERANK ----
        fine_results = self._execute_fine_rerank_layer(query_ctx, coarse_results)
        if fine_results is None or len(fine_results) == 0:
            return query_ctx

        # ---- L4: GENERATE ----
        final_results = self._execute_generate_layer(query_ctx, fine_results)
        # 缓存最终结果（下次相同查询直接命中 CACHE 层）
        if final_results:
            self._cache_set(query_ctx.query_text, final_results)

        return query_ctx

    def _execute_cache_layer(self, query_ctx: QueryContext) -> Optional[Any]:
        """
        L1: CACHE 层——精确缓存命中。

        类比：CPU L1 Cache ——最小、最快、命中率最高
              Service Worker 的 Cache Only 策略
        """
        handler = self._layer_handlers[QueryLayer.CACHE]
        if handler:
            # 使用自定义处理器
            result = handler(query_ctx.query_text, [], self.max_items[QueryLayer.CACHE])
        else:
            # 默认：内存缓存查找
            result = self._cache_get(query_ctx.query_text)

        if result is not None:
            query_ctx.layer_results[QueryLayer.CACHE] = result
            with self._stats_lock:
                self._stats["cache_hits"] += 1
            return result
        return None

    def _execute_coarse_filter_layer(self, query_ctx: QueryContext) -> Optional[List[Any]]:
        """
        L2: COARSE_FILTER 层——粗筛。

        目的：从海量候选中快速过滤出 Top-1000。
        技术：向量相似度（余弦距离 / 内积）——召回率优先。
        成本：极低（单个向量点积，可在 GPU 上批量计算）。

        类比：Elasticsearch 的 inverted index 查找
              ——快速定位候选文档集合，不保证精确排序
        """
        max_k = self.max_items[QueryLayer.COARSE_FILTER]
        handler = self._layer_handlers[QueryLayer.COARSE_FILTER]
        if handler:
            results = handler(query_ctx.query_text, [], max_k)
        else:
            # 默认：模拟粗筛（生产环境对接 FAISS / Milvus）
            results = self._mock_coarse_filter(query_ctx.query_text, max_k)

        query_ctx.layer_results[QueryLayer.COARSE_FILTER] = results
        return results

    def _execute_fine_rerank_layer(self, query_ctx: QueryContext,
                                    candidates: List[Any]) -> Optional[List[Any]]:
        """
        L3: FINE_RERANK 层——精排。

        目的：对粗筛结果（~1000 条）进行精确重排序，保留 Top-50。
        技术：Cross-Encoder / ColBERT / 学习排序（LTR）。
        成本：中等（每条需要完整前向传播，但只对 1000 条做）。

        类比：Google 搜索的 RankBrain 重排序阶段
              ——在候选池上应用昂贵的 ML 模型进行精排
        """
        max_k = self.max_items[QueryLayer.FINE_RERANK]
        handler = self._layer_handlers[QueryLayer.FINE_RERANK]
        if handler:
            results = handler(query_ctx.query_text, candidates, max_k)
        else:
            # 默认：模拟精排（生产环境对接 Cross-Encoder 模型）
            results = self._mock_fine_rerank(query_ctx.query_text, candidates, max_k)

        query_ctx.layer_results[QueryLayer.FINE_RERANK] = results
        with self._stats_lock:
            self._stats["fine_reranked"] += 1
        return results

    def _execute_generate_layer(self, query_ctx: QueryContext,
                                 top_candidates: List[Any]) -> Optional[Any]:
        """
        L4: GENERATE 层——LLM 生成。

        目的：基于精排后的 Top-K 文档，用 LLM 生成最终回答。
        技术：RAG（Retrieval-Augmented Generation）。
        成本：极高（LLM 推理通常是整个流水线最贵的步骤）。

        只有真正需要的查询才会到达这一层——99% 的查询已被前面层过滤或满足。

        类比：GPT-4 的 RAG 模式——
              只有需要深度推理的问题才调用 LLM
        """
        max_k = self.max_items[QueryLayer.GENERATE]
        handler = self._layer_handlers[QueryLayer.GENERATE]
        if handler:
            results = handler(query_ctx.query_text, top_candidates, max_k)
        else:
            results = self._mock_generate(query_ctx.query_text, top_candidates, max_k)

        query_ctx.layer_results[QueryLayer.GENERATE] = results
        with self._stats_lock:
            self._stats["generated"] += 1
        return results

    # ------------------------------------------------------------------
    # 模拟处理器（自测用，生产环境替换为真实实现）
    # ------------------------------------------------------------------

    def _mock_coarse_filter(self, query_text: str, max_k: int) -> List[Dict]:
        """
        模拟粗筛——返回假候选文档。

        生产环境替换为：
          - FAISS Index.search(query_vector, k=max_k)
          - Milvus collection.search(...)
          - Elasticsearch knn query
        """
        # 模拟：基于查询长度的"相似度"打分（纯演示用）
        results = []
        for i in range(min(max_k, 200)):  # 模拟返回 200 条候选
            # 模拟不同的相关性分数（0~1），大部分是低分
            score = 0.95 - (i * 0.004)  # 分数递减
            if score < 0.1:
                score = 0.05  # 低分尾巴
            results.append({
                "id": f"doc_{i:04d}",
                "score": max(score, 0.01),
                "title": f"Document {i}",
                "snippet": f"This is a mock snippet for doc {i} matching '{query_text[:20]}...'",
            })
        return results

    def _mock_fine_rerank(self, query_text: str,
                           candidates: List[Dict], max_k: int) -> List[Dict]:
        """
        模拟精排——对候选重打分并截断。

        生产环境替换为：
          - Cross-Encoder (sentence-transformers)
          - Cohere Rerank API
          - 自训练 LTR 模型
        """
        if not candidates:
            return []
        # 模拟：按原始分数排序 + 小幅随机扰动（模拟精排的不确定性）
        import random
        reranked = sorted(candidates, key=lambda x: x.get("score", 0) * random.uniform(0.9, 1.1),
                          reverse=True)
        return reranked[:max_k]

    def _mock_generate(self, query_text: str,
                        top_candidates: List[Dict], max_k: int) -> Dict:
        """
        模拟 LLM 生成——返回假生成结果。

        生产环境替换为：
          - OpenAI Chat Completion API
          - Claude Messages API
          - 本地 vLLM / TGI 推理
        """
        return {
            "answer": f"这是对查询「{query_text[:30]}...」的模拟回答。"
                      f"基于 {len(top_candidates)} 个文档生成。",
            "sources": [c["id"] for c in top_candidates[:max_k]],
            "model": "mock-llm-v1",
            "tokens_used": len(query_text) * 3,
        }

    # ------------------------------------------------------------------
    # 统计与监控
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """返回查询引擎的统计数据。"""
        with self._stats_lock:
            stats = dict(self._stats)
        # 计算缓存命中率
        total = stats["total_queries"]
        stats["cache_hit_rate"] = (stats["cache_hits"] / total) if total > 0 else 0.0
        # 计算各层通过率
        stats["coarse_pass_rate"] = ((total - stats["coarse_discarded"]) / total) if total > 0 else 0.0
        stats["generate_rate"] = (stats["generated"] / total) if total > 0 else 0.0
        # 缓存大小
        stats["cache_size"] = len(self._cache)
        stats["cache_max_size"] = self._cache_max_size
        return stats

    def clear_cache(self):
        """清空缓存。类比：Redis FLUSHDB。"""
        self._cache.clear()


# ================================================================
# 第2层: QueryBackpressure — 查询背压
# ================================================================

class QueryBackpressure:
    """
    查询背压控制器。

    三个维度的保护：
      1. 队列深度监控——队列 > 5000 时限流
      2. P99 延迟监控——P99 > 500ms 触发降级
      3. Per-source 限流——如"向量库最多 100 QPS"

    类比：
      - TCP 拥塞控制：接收窗口（rwnd）满了 → 通知发送方减速
      - Node.js stream.pipe()：可写端 drain 之前，可读端暂停
      - Nginx limit_req_zone：按 zone 限流
      - Kubernetes HPA：根据指标自动伸缩
    """

    # 默认阈值
    DEFAULT_MAX_QUEUE_DEPTH = 5000     # 队列深度硬限
    DEFAULT_WARN_QUEUE_DEPTH = 3000    # 队列深度软限（开始预警）
    DEFAULT_P99_THRESHOLD_MS = 500.0   # P99 延迟阈值（毫秒）

    def __init__(self,
                 max_queue_depth: int = DEFAULT_MAX_QUEUE_DEPTH,
                 warn_queue_depth: int = DEFAULT_WARN_QUEUE_DEPTH,
                 p99_threshold_ms: float = DEFAULT_P99_THRESHOLD_MS):
        """
        初始化背压控制器。

        Args:
            max_queue_depth: 队列深度硬限制（超过则强制限流）
            warn_queue_depth: 队列深度软限制（超过则预警）
            p99_threshold_ms: P99 延迟阈值（毫秒），超过则触发降级

        类比：配置 Nginx 的 worker_connections + limit_req
        """
        self.max_queue_depth = max_queue_depth
        self.warn_queue_depth = warn_queue_depth
        self.p99_threshold_ms = p99_threshold_ms

        # 全局查询队列深度（原子操作由锁保护）
        self._queue_depth: int = 0
        self._queue_lock = threading.Lock()

        # 延迟统计窗口（保留最近 1000 个样本用于 P99 计算）
        # 类比：Prometheus 的 histogram 的 bucket 采样
        self._latency_samples: deque = deque(maxlen=1000)
        self._latency_lock = threading.Lock()

        # Per-source 限流器
        # 结构: {source_name: RateLimiter}
        self._source_limiters: Dict[str, "_RateLimiter"] = {}
        self._source_limits: Dict[str, float] = {}  # {source: max_qps}
        self._source_lock = threading.Lock()

        # 限流统计
        self._throttled_count: int = 0
        self._total_processed: int = 0
        self._stats_lock = threading.Lock()

    # ------------------------------------------------------------------
    # 队列深度管理
    # ------------------------------------------------------------------

    def increment_queue(self):
        """
        查询入队时调用——队列深度 +1。

        类比：信号量的 P 操作（prolaag / wait）
              ——获取资源前增加计数
        """
        with self._queue_lock:
            self._queue_depth += 1

    def decrement_queue(self):
        """
        查询完成时调用——队列深度 -1。

        类比：信号量的 V 操作（verhoog / signal）
              ——释放资源后减少计数
        """
        with self._queue_lock:
            self._queue_depth = max(0, self._queue_depth - 1)

    @property
    def queue_depth(self) -> int:
        """当前队列深度。类比：RabbitMQ 的 queue.messages_ready。"""
        with self._queue_lock:
            return self._queue_depth

    # ------------------------------------------------------------------
    # 延迟统计
    # ------------------------------------------------------------------

    def record_latency(self, latency_ms: float):
        """
        记录一次查询的端到端延迟。

        Args:
            latency_ms: 查询延迟（毫秒）

        类比：Prometheus Histogram 的 Observe() 方法
        """
        with self._latency_lock:
            self._latency_samples.append(latency_ms)

    @property
    def avg_latency_ms(self) -> float:
        """平均延迟（毫秒）。"""
        with self._latency_lock:
            if not self._latency_samples:
                return 0.0
            return sum(self._latency_samples) / len(self._latency_samples)

    @property
    def p99_latency_ms(self) -> float:
        """
        P99 延迟（毫秒）。

        类比：CloudWatch 的 p99 指标
              ——99% 的请求在此延迟以下完成
        """
        with self._latency_lock:
            # 注意: 不能调用 self.avg_latency_ms(会再次获取同一把不可重入锁 → 死锁)
            n = len(self._latency_samples)
            if n == 0:
                return 0.0
            if n < 100:
                return sum(self._latency_samples) / n  # 样本不足时用平均值代替
            sorted_l = sorted(self._latency_samples)
            idx = int(n * 0.99)
            return sorted_l[min(idx, n - 1)]

    # ------------------------------------------------------------------
    # Per-source 限流
    # ------------------------------------------------------------------

    def set_source_limit(self, source: str, max_qps: float):
        """
        设置某个来源的最大 QPS。

        Args:
            source: 来源名称（如 "vector_db", "llm_api", "web_search"）
            max_qps: 每秒最大查询数

        类比：AWS API Gateway 的 Usage Plan
              ——为每个 API Key 设置 rate limit
        """
        with self._source_lock:
            self._source_limits[source] = max_qps
            if source not in self._source_limiters:
                self._source_limiters[source] = _RateLimiter(max_qps)

    def check_source_allowed(self, source: str) -> bool:
        """
        检查某个来源是否允许通过当前查询。

        Returns:
            True 表示允许通过，False 表示被限流。

        类比：Nginx 的 limit_req_zone 检查
              ——ngx_http_limit_req_module 的 ngx_http_limit_req_lookup()
        """
        with self._source_lock:
            if source not in self._source_limits:
                return True  # 未设置限制的来源默认放行
            limiter = self._source_limiters.get(source)
            if limiter is None:
                return True
            return limiter.allow()

    # ------------------------------------------------------------------
    # 核心判断方法
    # ------------------------------------------------------------------

    @property
    def is_under_pressure(self) -> bool:
        """
        是否处于轻度背压状态。

        条件：队列深度超过软限 或 P99 延迟超过阈值

        类比：系统负载 > 70% 时触发黄色告警
        """
        return (self.queue_depth > self.warn_queue_depth or
                self.p99_latency_ms > self.p99_threshold_ms)

    @property
    def is_critical(self) -> bool:
        """
        是否处于严重背压状态。

        条件：队列深度超过硬限

        类比：系统负载 > 95% 时触发红色告警
        """
        return self.queue_depth > self.max_queue_depth

    def should_throttle(self) -> bool:
        """
        是否需要限流。

        决策逻辑：
          1. 严重背压 → 立即限流（丢弃低优先级查询）
          2. 轻度背压 + 队列增长中 → 限流
          3. 正常 → 不限流

        类比：TCP Reno 的拥塞窗口调整算法
              ——检测到丢包（队列满）→ 减半 cwnd
        """
        # 严重背压——必须限流
        if self.is_critical:
            with self._stats_lock:
                self._throttled_count += 1
            return True
        # 轻度背压——酌情限流
        if self.is_under_pressure:
            # 按 50% 概率限流（避免全部拒绝）
            import random
            if random.random() < 0.5:
                with self._stats_lock:
                    self._throttled_count += 1
                return True
        return False

    # ------------------------------------------------------------------
    # 统计
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """返回背压控制器的统计数据。"""
        with self._latency_lock:
            latency_count = len(self._latency_samples)
        with self._stats_lock:
            throttled = self._throttled_count
            processed = self._total_processed
        source_stats = {}
        with self._source_lock:
            for src, limiter in self._source_limiters.items():
                source_stats[src] = {
                    "limit_qps": self._source_limits.get(src, 0),
                    "current_qps": limiter.current_rate(),
                }
        return {
            "queue_depth": self.queue_depth,
            "max_queue_depth": self.max_queue_depth,
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "p99_latency_ms": round(self.p99_latency_ms, 2),
            "p99_threshold_ms": self.p99_threshold_ms,
            "is_under_pressure": self.is_under_pressure,
            "is_critical": self.is_critical,
            "throttled_count": throttled,
            "total_processed": processed,
            "throttle_rate": (throttled / max(processed, 1)),
            "source_limits": source_stats,
        }


# ------------------------------------------------------------------
# Per-source 限流器（内部类）
# ------------------------------------------------------------------

class _RateLimiter:
    """
    令牌桶限流器。

    类比：
      - Guava RateLimiter（Java）
      - Django Ratelimit 的令牌桶实现
      - AWS API Gateway 的 Token Bucket Algorithm
    """

    def __init__(self, max_qps: float):
        """
        Args:
            max_qps: 每秒允许的最大请求数
        """
        self.max_qps = max_qps
        self._tokens = max_qps          # 当前令牌数（初始满桶）
        self._last_refill = time.time()  # 上次填充时间
        self._lock = threading.Lock()
        # 请求计数（用于统计当前 QPS）
        self._request_times: deque = deque(maxlen=100)

    def allow(self) -> bool:
        """
        检查是否允许通过。

        令牌桶算法：
          1. 根据时间差补充令牌
          2. 如果有令牌 → 消耗 1 个 → 允许
          3. 如果没令牌 → 拒绝

        类比：高速公路收费站的通行卡
              ——每辆车需要一张卡，卡按固定速率补充
        """
        now = time.time()
        with self._lock:
            # 1. 补充令牌（基于时间差）
            elapsed = now - self._last_refill
            self._tokens = min(self.max_qps, self._tokens + elapsed * self.max_qps)
            self._last_refill = now

            # 2. 尝试消耗
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                self._request_times.append(now)
                return True
            return False

    def current_rate(self) -> float:
        """当前实际 QPS（基于滑动窗口）。"""
        now = time.time()
        with self._lock:
            # 清理过期记录（1 秒前）
            cutoff = now - 1.0
            while self._request_times and self._request_times[0] < cutoff:
                self._request_times.popleft()
            return len(self._request_times)


# ================================================================
# 第3层: ContextMemoryGC — 上下文内存 GC
# ================================================================

class ContextMemoryGC:
    """
    上下文内存垃圾回收器。

    解决的问题：
      - 对话历史膨胀 → KV Cache 爆内存 → OOM
      - 多个并发会话 → 总上下文超出 GPU 显存

    策略：
      1. 软限（soft_limit_mb，默认 200M）：压缩早期上下文（摘要替代原文）
      2. 硬限（hard_limit_mb，默认 500M）：丢弃最旧上下文
      3. LRU 淘汰：最近最少使用的上下文优先淘汰

    类比：
      - JVM GC 的分代回收：Young Gen（新对话）→ Old Gen（长对话）
      - Redis 的 maxmemory-policy allkeys-lru
      - 浏览器的 Back/Forward Cache（bfcache）淘汰
      - Linux 内核的 page reclaim（kswapd）
    """

    # 默认内存阈值（MB）
    DEFAULT_SOFT_LIMIT_MB = 200.0
    DEFAULT_HARD_LIMIT_MB = 500.0

    def __init__(self,
                 soft_limit_mb: float = DEFAULT_SOFT_LIMIT_MB,
                 hard_limit_mb: float = DEFAULT_HARD_LIMIT_MB):
        """
        初始化上下文内存 GC。

        Args:
            soft_limit_mb: 软限制（MB），触发压缩
            hard_limit_mb: 硬限制（MB），触发丢弃

        类比：JVM -Xms（初始堆）和 -Xmx（最大堆）
        """
        self.soft_limit_mb = soft_limit_mb
        self.hard_limit_mb = hard_limit_mb

        # 上下文存储
        # key = context_id（如 session_id），value = ContextItem
        self._contexts: OrderedDict[str, "_ContextItem"] = OrderedDict()
        self._context_lock = threading.Lock()

        # 统计
        self._total_compressions: int = 0
        self._total_evictions: int = 0
        self._total_bytes_freed: int = 0

    # ------------------------------------------------------------------
    # 上下文管理
    # ------------------------------------------------------------------

    def store_context(self, context_id: str, content: Any,
                       estimated_size_bytes: int = 0):
        """
        存储/更新一个上下文。

        Args:
            context_id: 上下文唯一 ID（如 session_id）
            content: 上下文内容（对话历史、KV Cache 等）
            estimated_size_bytes: 估算的字节大小（如不传则自动估算）

        类比：浏览器的 Cache.put(request, response)
              ——存入时自动触发淘汰检查
        """
        if estimated_size_bytes <= 0:
            estimated_size_bytes = self._estimate_size(content)

        with self._context_lock:
            # 如果已存在，先移除（OrderedDict 用于 LRU 排序）
            if context_id in self._contexts:
                old_item = self._contexts.pop(context_id)
                self._total_bytes_freed += old_item.size_bytes

            # 创建新条目
            item = _ContextItem(
                context_id=context_id,
                content=content,
                size_bytes=estimated_size_bytes,
                created_at=time.time(),
                last_accessed=time.time(),
            )
            self._contexts[context_id] = item

            # 检查内存限制
            self._gc_if_needed()

    def get_context(self, context_id: str) -> Optional[Any]:
        """
        获取上下文（LRU 访问——移到末尾）。

        类比：Redis GET 命令会自动更新 key 的 LRU 时间戳
        """
        with self._context_lock:
            if context_id not in self._contexts:
                return None
            # LRU: 移到末尾（最近使用）
            item = self._contexts.pop(context_id)
            item.last_accessed = time.time()
            self._contexts[context_id] = item
            return item.content

    def remove_context(self, context_id: str):
        """
        显式删除上下文。

        类比：Redis DEL key
        """
        with self._context_lock:
            if context_id in self._contexts:
                item = self._contexts.pop(context_id)
                self._total_bytes_freed += item.size_bytes

    # ------------------------------------------------------------------
    # GC 逻辑
    # ------------------------------------------------------------------

    def _gc_if_needed(self):
        """
        检查并执行垃圾回收（在 _context_lock 内部调用）。

        决策流程：
          1. 总内存 < 软限 → 不操作
          2. 软限 ≤ 总内存 < 硬限 → 压缩最旧的上下文
          3. 总内存 ≥ 硬限 → 丢弃最旧的上下文（LRU）
        """
        total_mb = self._total_memory_mb()

        # 硬限：强制丢弃最旧上下文
        while total_mb > self.hard_limit_mb and len(self._contexts) > 0:
            self._evict_oldest()
            total_mb = self._total_memory_mb()

        # 软限：压缩早期上下文
        while total_mb > self.soft_limit_mb and len(self._contexts) > 0:
            # 找到最旧的未压缩上下文
            compressed_any = self._compress_oldest_uncompressed()
            if not compressed_any:
                # 所有上下文都已压缩，但仍然超限 → 丢弃最旧
                self._evict_oldest()
            total_mb = self._total_memory_mb()

    def _total_memory_mb(self) -> float:
        """计算当前总内存（MB）。需在 _context_lock 内调用。"""
        total = sum(item.size_bytes for item in self._contexts.values())
        return total / (1024 * 1024)  # bytes → MB

    def _evict_oldest(self):
        """
        淘汰最旧的上下文（OrderedDict 开头 = 最早插入/最久未访问）。

        类比：Redis 的 allkeys-lru 淘汰
        """
        if len(self._contexts) == 0:
            return
        oldest_key, oldest_item = self._contexts.popitem(last=False)
        freed_mb = oldest_item.size_bytes / (1024 * 1024)
        self._total_bytes_freed += oldest_item.size_bytes
        self._total_evictions += 1
        logging.warning(
            f"[ContextMemoryGC] 硬限淘汰: context_id={oldest_key}, "
            f"释放 {freed_mb:.1f}MB, 总计淘汰 {self._total_evictions} 次"
        )

    def _compress_oldest_uncompressed(self) -> bool:
        """
        找到最旧的未压缩上下文并压缩它。

        压缩策略：用摘要（前 200 字 + "...[已压缩]..."）替代原文。

        类比：浏览器的 discarding tab
              ——保留标签页标题，丢弃渲染状态
            JVM 的 String Deduplication
              ——相同内容只保留一份

        Returns:
            True 表示压缩了一个上下文，False 表示没有可压缩的。
        """
        # 遍历找到第一个未压缩的（OrderedDict 按插入顺序）
        for key, item in self._contexts.items():
            if not item.is_compressed:
                # 执行压缩
                original_size = item.size_bytes
                item.content = self._summarize(item.content)
                item.size_bytes = self._estimate_size(item.content)
                item.is_compressed = True
                freed = original_size - item.size_bytes
                self._total_bytes_freed += freed
                self._total_compressions += 1
                # LRU: 移到末尾
                self._contexts.move_to_end(key)
                logging.info(
                    f"[ContextMemoryGC] 软限压缩: context_id={key}, "
                    f"原始 {original_size}B → 压缩后 {item.size_bytes}B "
                    f"(释放 {freed}B), 总计压缩 {self._total_compressions} 次"
                )
                return True
        return False  # 所有都已被压缩

    def _summarize(self, content: Any) -> Any:
        """
        生成上下文的摘要。

        对字符串：取前 200 字符 + "...[已压缩]..."
        对列表（如对话历史）：保留最近 3 轮 + 摘要标记
        对字典：递归压缩

        类比：GitHub Copilot Chat 的上下文窗口管理
              ——长对话自动截断并加摘要前缀
        """
        if isinstance(content, str):
            if len(content) > 200:
                return content[:200] + f"...[已压缩，原始长度 {len(content)} 字符]..."
            return content
        elif isinstance(content, list):
            if len(content) > 3:
                # 保留最后 3 条 + 压缩标记
                compressed = content[-3:]
                compressed.insert(0, f"[前面的 {len(content) - 3} 条消息已压缩]")
                return compressed
            return content
        elif isinstance(content, dict):
            # 递归压缩 dict 中的值
            return {k: self._summarize(v) for k, v in content.items()}
        return content

    # ------------------------------------------------------------------
    # 大小估算
    # ------------------------------------------------------------------

    def _estimate_size(self, content: Any) -> int:
        """
        估算对象的内存大小。

        使用 sys.getsizeof 作为基础估算，对于复杂对象递归计算。

        类比：Python 的 sys.getsizeof + 递归遍历
              Chrome DevTools 的 Memory 面板的 Shallow Size
        """
        seen: Set[int] = set()
        return self._estimate_recursive(content, seen)

    def _estimate_recursive(self, obj: Any, seen: Set[int]) -> int:
        """递归估算对象大小，避免重复计数。"""
        obj_id = id(obj)
        if obj_id in seen:
            return 0  # 已计数（循环引用处理）
        seen.add(obj_id)

        total = sys.getsizeof(obj)

        if isinstance(obj, dict):
            for k, v in obj.items():
                total += self._estimate_recursive(k, seen)
                total += self._estimate_recursive(v, seen)
        elif isinstance(obj, (list, tuple, set)):
            for item in obj:
                total += self._estimate_recursive(item, seen)
        elif isinstance(obj, str):
            # sys.getsizeof 已经包含字符串内容
            pass

        return total

    # ------------------------------------------------------------------
    # 统计
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """返回 GC 统计数据。"""
        with self._context_lock:
            total_mb = self._total_memory_mb()
            context_count = len(self._contexts)
            compressed_count = sum(1 for item in self._contexts.values()
                                   if item.is_compressed)
        return {
            "total_memory_mb": round(total_mb, 2),
            "soft_limit_mb": self.soft_limit_mb,
            "hard_limit_mb": self.hard_limit_mb,
            "context_count": context_count,
            "compressed_count": compressed_count,
            "compression_ratio": (compressed_count / max(context_count, 1)),
            "total_compressions": self._total_compressions,
            "total_evictions": self._total_evictions,
            "total_bytes_freed": self._total_bytes_freed,
            "freed_mb": round(self._total_bytes_freed / (1024 * 1024), 2),
        }

    def force_gc(self):
        """
        强制执行一次完整 GC。

        类比：Python 的 gc.collect()
              JVM 的 System.gc()
        """
        with self._context_lock:
            self._gc_if_needed()
        # 同时触发 Python 原生 GC
        gc.collect()


# ------------------------------------------------------------------
# 上下文条目（内部类）
# ------------------------------------------------------------------

@dataclass
class _ContextItem:
    """
    单个上下文条目。

    类比：Redis 的 redisObject + dictEntry 组合
    """
    context_id: str
    content: Any
    size_bytes: int
    created_at: float
    last_accessed: float
    is_compressed: bool = False


# ================================================================
# 第4层: QueryWatchdog — 查询看门狗
# ================================================================

class QueryWatchdog:
    """
    查询看门狗——单查询超时熔断。

    原理：
      1. 每个查询启动时注册到看门狗
      2. 独立线程定期检查所有活跃查询
      3. 超时（默认 30s）→ 熔断该查询 → 保存现场 → 返回降级答案

    类比：
      - 硬件看门狗定时器（WDT）：MCU 死机 → 自动复位
      - Kubernetes liveness probe：Pod 无响应 → kill + restart
      - Python concurrent.futures 的 timeout 参数
      - HTTP 客户端的请求超时（connect timeout / read timeout）
    """

    DEFAULT_TIMEOUT_SECONDS = 30.0  # 默认单查询超时（秒）

    def __init__(self, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS):
        """
        初始化看门狗。

        Args:
            timeout_seconds: 单个查询的超时时间（秒）

        类比：设置 axios 的 timeout: 30000（毫秒）
        """
        self.timeout_seconds = timeout_seconds

        # 活跃查询注册表 {query_id: QueryWatchEntry}
        self._active_queries: Dict[str, "_QueryWatchEntry"] = {}
        self._watch_lock = threading.Lock()

        # 看门狗线程
        self._running = False
        self._watch_thread: Optional[threading.Thread] = None
        self._check_interval = min(1.0, timeout_seconds / 5)  # 检查间隔

        # 超时回调（熔断时调用）
        self._timeout_callbacks: List[Callable[[str, QueryContext], None]] = []

        # 查询现场保存目录
        self._dump_dir: Optional[str] = None

        # 统计
        self._timeout_count: int = 0
        self._total_registered: int = 0

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def start(self):
        """
        启动看门狗线程。

        类比：systemd 启动 watchdog 服务
        """
        if self._running:
            return
        self._running = True
        self._watch_thread = threading.Thread(
            target=self._watch_loop, daemon=True, name="query-watchdog")
        self._watch_thread.start()
        logging.info(f"[QueryWatchdog] 启动，超时阈值 {self.timeout_seconds}s")

    def stop(self):
        """
        停止看门狗线程。

        类比：systemd 停止 watchdog 服务
        """
        self._running = False
        if self._watch_thread:
            self._watch_thread.join(timeout=5.0)
            self._watch_thread = None

    # ------------------------------------------------------------------
    # 查询注册/注销
    # ------------------------------------------------------------------

    def register(self, query_ctx: QueryContext):
        """
        注册一个查询到看门狗——查询开始时调用。

        Args:
            query_ctx: 查询上下文

        类比：setTimeout(query_id, timeout_handler, 30000)
              JavaScript 的定时器机制
        """
        with self._watch_lock:
            self._active_queries[query_ctx.query_id] = _QueryWatchEntry(
                query_ctx=query_ctx,
                registered_at=time.time(),
                timeout_at=time.time() + self.timeout_seconds,
            )
            self._total_registered += 1

    def unregister(self, query_id: str):
        """
        注销一个查询——查询完成时调用。

        类比：JavaScript 的 clearTimeout(timer_id)
        """
        with self._watch_lock:
            self._active_queries.pop(query_id, None)

    def heartbeat(self, query_id: str):
        """
        查询心跳——长时间查询定期调用以续命。

        类比：Kubernetes liveness probe 的 success 响应
              ——告诉看门狗"我还活着，别杀我"
        """
        with self._watch_lock:
            entry = self._active_queries.get(query_id)
            if entry:
                entry.timeout_at = time.time() + self.timeout_seconds
                entry.query_ctx.metadata["last_heartbeat"] = time.time()

    # ------------------------------------------------------------------
    # 看门狗主循环
    # ------------------------------------------------------------------

    def _watch_loop(self):
        """
        看门狗检查循环。

        定期扫描所有活跃查询，超时则熔断。
        """
        while self._running:
            time.sleep(self._check_interval)
            self._check_timeouts()

    def _check_timeouts(self):
        """
        检查所有活跃查询是否超时。

        超时处理：
          1. 保存查询现场（输入参数 + 中间结果）
          2. 调用超时回调
          3. 从活跃列表移除
        """
        now = time.time()
        timed_out: List[Tuple[str, QueryContext]] = []

        with self._watch_lock:
            for query_id, entry in list(self._active_queries.items()):
                if now >= entry.timeout_at:
                    timed_out.append((query_id, entry.query_ctx))
                    del self._active_queries[query_id]

        # 在锁外处理超时（避免死锁）
        for query_id, ctx in timed_out:
            self._handle_timeout(query_id, ctx)

    def _handle_timeout(self, query_id: str, query_ctx: QueryContext):
        """
        处理查询超时。

        步骤：
          1. 记录日志
          2. 保存查询现场（dump）
          3. 调用用户注册的超时回调
          4. 更新统计
        """
        elapsed = time.time() - query_ctx.start_time
        logging.warning(
            f"[QueryWatchdog] ⚠️ 查询超时熔断: query_id={query_id}, "
            f"耗时 {elapsed:.1f}s (阈值 {self.timeout_seconds}s), "
            f"查询文本: '{query_ctx.query_text[:50]}...'"
        )
        self._timeout_count += 1

        # 保存查询现场（用于事后分析）
        self._dump_query_context(query_id, query_ctx)

        # 调用超时回调
        for callback in self._timeout_callbacks:
            try:
                callback(query_id, query_ctx)
            except Exception as e:
                logging.error(f"[QueryWatchdog] 超时回调异常: {e}")

    # ------------------------------------------------------------------
    # 查询现场保存
    # ------------------------------------------------------------------

    def set_dump_dir(self, directory: str):
        """
        设置查询现场的保存目录。

        Args:
            directory: 目录路径

        类比：Node.js 的 --heapsnapshot-signal
              ——收到信号时保存堆快照
        """
        self._dump_dir = directory
        os.makedirs(directory, exist_ok=True)

    def _dump_query_context(self, query_id: str, query_ctx: QueryContext):
        """
        保存查询现场到磁盘。

        内容包括：
          - 原始查询文本
          - 查询来源
          - 各层中间结果（如果有）
          - 元数据
          - 时间戳

        类比：浏览器崩溃时的 crash dump
              Kubernetes Pod 的 termination message
        """
        if not self._dump_dir:
            return

        try:
            dump = {
                "query_id": query_id,
                "query_text": query_ctx.query_text,
                "source": query_ctx.source,
                "start_time": query_ctx.start_time,
                "dump_time": time.time(),
                "elapsed_seconds": time.time() - query_ctx.start_time,
                "metadata": query_ctx.metadata,
                "layer_results": {},
            }
            # 序列化各层中间结果（只保留可 JSON 化的字段）
            for layer, result in query_ctx.layer_results.items():
                try:
                    # 尝试 JSON 序列化
                    json.dumps(result)
                    dump["layer_results"][layer.name] = result
                except (TypeError, ValueError):
                    dump["layer_results"][layer.name] = str(result)[:1000]

            # 写入文件
            filename = f"watchdog_dump_{query_id}_{int(time.time())}.json"
            filepath = os.path.join(self._dump_dir, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(dump, f, ensure_ascii=False, indent=2, default=str)

            logging.info(f"[QueryWatchdog] 查询现场已保存: {filepath}")
        except Exception as e:
            logging.error(f"[QueryWatchdog] 保存查询现场失败: {e}")

    # ------------------------------------------------------------------
    # 回调与统计
    # ------------------------------------------------------------------

    def on_timeout(self, callback: Callable[[str, QueryContext], None]):
        """
        注册超时回调。

        Args:
            callback: 签名为 (query_id: str, query_ctx: QueryContext) -> None

        类比：JavaScript 的 EventEmitter.on('timeout', handler)
        """
        self._timeout_callbacks.append(callback)

    def get_active_count(self) -> int:
        """当前活跃查询数。"""
        with self._watch_lock:
            return len(self._active_queries)

    def get_stats(self) -> Dict[str, Any]:
        """返回看门狗统计数据。"""
        with self._watch_lock:
            active_ids = list(self._active_queries.keys())
        return {
            "active_queries": len(active_ids),
            "active_query_ids": active_ids[:20],  # 最多展示 20 个
            "timeout_seconds": self.timeout_seconds,
            "total_registered": self._total_registered,
            "timeout_count": self._timeout_count,
            "timeout_rate": (self._timeout_count / max(self._total_registered, 1)),
            "check_interval": self._check_interval,
        }


# ------------------------------------------------------------------
# 看门狗条目（内部类）
# ------------------------------------------------------------------

@dataclass
class _QueryWatchEntry:
    """看门狗注册条目。"""
    query_ctx: QueryContext
    registered_at: float
    timeout_at: float


# ================================================================
# 第5层: ResponseDegrader — 回答降级
# ================================================================

class ResponseDegrader:
    """
    回答降级策略。

    四级降级（从优到劣）：
      ┌──────────┬──────────────────────────────────────────────┐
      │ FULL     │ 全量 RAG + 多轮推理（最优质量）              │
      │ REDUCED  │ 缓存命中直接返回（中质量，0 推理成本）       │
      │ MINIMAL  │ 预置模板回答（低质量但可用）                 │
      │ EMERGENCY│ 拒答 + 告警（只保证不崩溃）                  │
      └──────────┴──────────────────────────────────────────────┘

    降级决策矩阵：
      ┌─────────────┬────────────┬─────────────┬─────────────┐
      │             │ 背压正常   │ 背压轻度    │ 背压严重    │
      ├─────────────┼────────────┼─────────────┼─────────────┤
      │ 缓存命中    │ FULL(缓存) │ REDUCED     │ MINIMAL     │
      │ 缓存未命中  │ FULL(RAG)  │ REDUCED     │ MINIMAL     │
      │ 看门狗超时  │ —          │ MINIMAL     │ EMERGENCY   │
      │ 内存>硬限   │ —          │ MINIMAL     │ EMERGENCY   │
      └─────────────┴────────────┴─────────────┴─────────────┘

    类比：
      - CloudFront / Cloudflare 的 Error Pages（多层 fallback）
      - Netflix Hystrix 的 fallback 机制
      - Kubernetes 的 Pod Disruption Budget（尽力保证可用性）
    """

    # 预置模板回答（MINIMAL 级别使用）
    DEFAULT_TEMPLATES: Dict[str, str] = {
        "default": (
            "抱歉，当前系统负载较高，暂时无法提供完整回答。"
            "请稍后重试或简化您的问题。"
        ),
        "timeout": (
            "您的问题处理超时，系统已自动降级。"
            "建议将问题拆分为更小的子问题逐一提问。"
        ),
        "overload": (
            "系统正在经历高负载，已启用降级模式。"
            "您的请求已被记录，我们将在恢复后优先处理。"
        ),
        "emergency": (
            "系统当前处于紧急保护模式，暂时无法处理新查询。"
            "运维团队已收到告警，正在紧急修复中。"
        ),
    }

    def __init__(self,
                 templates: Optional[Dict[str, str]] = None):
        """
        初始化降级器。

        Args:
            templates: 自定义模板字典，会合并到默认模板中

        类比：Nginx 的自定义 error_page 指令
              error_page 502 /custom_502.html;
        """
        self.templates = dict(self.DEFAULT_TEMPLATES)
        if templates:
            self.templates.update(templates)

        # 当前降级级别
        self._current_level = DegradationLevel.FULL
        self._level_lock = threading.Lock()

        # 降级历史（用于趋势分析）
        self._level_history: deque = deque(maxlen=100)

        # 降级统计
        self._response_counts: Dict[DegradationLevel, int] = {
            DegradationLevel.FULL: 0,
            DegradationLevel.REDUCED: 0,
            DegradationLevel.MINIMAL: 0,
            DegradationLevel.EMERGENCY: 0,
        }
        self._stats_lock = threading.Lock()

    # ------------------------------------------------------------------
    # 降级决策
    # ------------------------------------------------------------------

    def evaluate(self,
                 cache_hit: bool,
                 backpressure: QueryBackpressure,
                 memory_gc: ContextMemoryGC,
                 watchdog_timeout: bool = False) -> DegradationLevel:
        """
        评估当前应使用的降级级别。

        决策逻辑（按优先级）：
          1. 看门狗超时 或 内存超过硬限 → EMERGENCY
          2. 背压严重 → MINIMAL
          3. 背压轻度 → REDUCED
          4. 正常 → FULL

        Args:
            cache_hit: 是否缓存命中
            backpressure: 背压控制器
            memory_gc: 内存 GC
            watchdog_timeout: 是否发生看门狗超时

        Returns:
            降级级别

        类比：Hystrix 的 getFallback() 决策
              ——根据熔断器状态决定返回哪个 fallback
        """
        # 紧急情况：看门狗超时 → 直接 EMERGENCY
        if watchdog_timeout:
            new_level = DegradationLevel.EMERGENCY
        # 紧急情况：内存超过硬限
        elif memory_gc.get_stats()["total_memory_mb"] > memory_gc.hard_limit_mb:
            new_level = DegradationLevel.EMERGENCY
        # 严重背压 → MINIMAL
        elif backpressure.is_critical:
            new_level = DegradationLevel.MINIMAL
        # 轻度背压 → REDUCED
        elif backpressure.is_under_pressure:
            new_level = DegradationLevel.REDUCED
        # 正常 → FULL
        else:
            new_level = DegradationLevel.FULL

        with self._level_lock:
            old_level = self._current_level
            self._current_level = new_level
            self._level_history.append(new_level)

        # 级别变化时记录
        if old_level != new_level:
            logging.warning(
                f"[ResponseDegrader] 降级级别变更: {old_level.name} → {new_level.name}, "
                f"原因: cache_hit={cache_hit}, backpressure_critical={backpressure.is_critical}, "
                f"watchdog_timeout={watchdog_timeout}"
            )

        return new_level

    # ------------------------------------------------------------------
    # 按级别生成回答
    # ------------------------------------------------------------------

    def generate_response(self,
                          level: DegradationLevel,
                          query_text: str,
                          full_response_func: Optional[Callable[[], str]] = None,
                          cached_response: Optional[str] = None,
                          template_key: str = "default") -> DegradedResponse:
        """
        根据降级级别生成回答。

        Args:
            level: 降级级别
            query_text: 原始查询文本
            full_response_func: 完整回答的生成函数（FULL 级别调用）
            cached_response: 缓存的回答（REDUCED 级别使用）
            template_key: 模板键名（MINIMAL/EMERGENCY 级别使用）

        Returns:
            DegradedResponse 对象

        类比：Express.js 的错误处理中间件
              ——根据错误类型返回不同的响应格式
        """
        with self._stats_lock:
            self._response_counts[level] += 1

        if level == DegradationLevel.FULL:
            # 完整回答：调用 RAG + LLM 推理
            if full_response_func:
                answer = full_response_func()
            else:
                answer = cached_response or self._mock_full_response(query_text)
            return DegradedResponse(
                level=level,
                answer=answer,
                is_degraded=False,
                original_query=query_text,
            )

        elif level == DegradationLevel.REDUCED:
            # 降级回答：缓存命中直接返回
            if cached_response:
                return DegradedResponse(
                    level=level,
                    answer=cached_response,
                    is_degraded=True,
                    original_query=query_text,
                    degrade_reason="缓存命中（REDUCED 模式）",
                    cached_at=time.time(),
                )
            # 缓存不可用 → 退回 MINIMAL
            return self.generate_response(
                DegradationLevel.MINIMAL, query_text,
                template_key="default"
            )

        elif level == DegradationLevel.MINIMAL:
            # 最小回答：预置模板
            template = self.templates.get(template_key, self.templates["default"])
            return DegradedResponse(
                level=level,
                answer=template,
                is_degraded=True,
                original_query=query_text,
                degrade_reason=f"系统负载高，使用预置模板（{template_key}）",
            )

        elif level == DegradationLevel.EMERGENCY:
            # 紧急模式：拒答 + 告警
            template = self.templates.get("emergency", self.templates["emergency"])
            # 触发告警（生产环境对接 PagerDuty / 飞书 / 钉钉）
            logging.critical(
                f"[ResponseDegrader] 🚨 紧急降级触发！"
                f"查询: '{query_text[:50]}...', 模板: {template_key}"
            )
            return DegradedResponse(
                level=level,
                answer=template,
                is_degraded=True,
                original_query=query_text,
                degrade_reason="系统处于紧急保护模式",
            )

        # 不应该到达这里
        return DegradedResponse(
            level=DegradationLevel.EMERGENCY,
            answer=self.templates["emergency"],
            is_degraded=True,
            original_query=query_text,
            degrade_reason="未知降级级别",
        )

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _mock_full_response(self, query_text: str) -> str:
        """模拟完整 RAG 回答（自测用）。"""
        return (f"这是对「{query_text}」的完整 RAG 回答。"
                f"经过多轮推理和文档检索后生成。")

    @property
    def current_level(self) -> DegradationLevel:
        """当前降级级别。"""
        with self._level_lock:
            return self._current_level

    def get_template(self, key: str) -> str:
        """获取指定模板。"""
        return self.templates.get(key, self.templates["default"])

    def set_template(self, key: str, template: str):
        """
        设置自定义模板。

        Args:
            key: 模板键名
            template: 模板内容，支持 {query} 占位符
        """
        self.templates[key] = template

    # ------------------------------------------------------------------
    # 统计
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """返回降级统计。"""
        with self._level_lock:
            current = self._current_level
        with self._stats_lock:
            counts = dict(self._response_counts)
        total = sum(counts.values())
        return {
            "current_level": current.name,
            "current_level_value": int(current),
            "response_counts": {level.name: count for level, count in counts.items()},
            "degradation_rate": (
                (total - counts[DegradationLevel.FULL]) / max(total, 1)
            ),
            "total_responses": total,
            "available_templates": list(self.templates.keys()),
        }


# ================================================================
# QueryGuardian — 门面类（整合所有五层防护）
# ================================================================

class QueryGuardian:
    """
    查询卫士——五层防护的门面。

    整合：
      - ProgressiveQueryEngine  (L1: 渐进查询)
      - QueryBackpressure       (L2: 查询背压)
      - ContextMemoryGC         (L3: 内存 GC)
      - QueryWatchdog           (L4: 查询看门狗)
      - ResponseDegrader        (L5: 回答降级)

    使用方式：
      guardian = QueryGuardian(
          coarse_max_items=500,
          backpressure_max_queue=5000,
          memory_soft_limit_mb=200,
          watchdog_timeout=30.0,
      )
      guardian.start()

      # 执行查询
      response = guardian.ask("什么是渐进式查询？")

      # 获取健康报告
      print(guardian.get_health_report())

      guardian.stop()

    类比：
      - Kubernetes Controller Manager：管理多个控制循环，统一对外接口
      - Spring Boot Actuator：健康检查 + 指标暴露的统一端点
      - Node.js 的 cluster 模块：worker 管理 + 健康检查
    """

    def __init__(self,
                 # 渐进查询引擎参数
                 coarse_max_items: int = 1000,
                 fine_max_items: int = 50,
                 generate_max_items: int = 5,
                 # 背压参数
                 backpressure_max_queue: int = 5000,
                 backpressure_warn_queue: int = 3000,
                 backpressure_p99_threshold_ms: float = 500.0,
                 # 内存 GC 参数
                 memory_soft_limit_mb: float = 200.0,
                 memory_hard_limit_mb: float = 500.0,
                 # 看门狗参数
                 watchdog_timeout_seconds: float = 30.0,
                 # 降级模板
                 degrade_templates: Optional[Dict[str, str]] = None,
                 # 其他
                 enable_psutil: bool = True):
        """
        初始化查询卫士。

        所有参数均可选，使用合理的默认值。
        """
        # 五层防护组件
        self.engine = ProgressiveQueryEngine(
            max_items={
                QueryLayer.COARSE_FILTER: coarse_max_items,
                QueryLayer.FINE_RERANK: fine_max_items,
                QueryLayer.GENERATE: generate_max_items,
            }
        )
        self.backpressure = QueryBackpressure(
            max_queue_depth=backpressure_max_queue,
            warn_queue_depth=backpressure_warn_queue,
            p99_threshold_ms=backpressure_p99_threshold_ms,
        )
        self.memory_gc = ContextMemoryGC(
            soft_limit_mb=memory_soft_limit_mb,
            hard_limit_mb=memory_hard_limit_mb,
        )
        self.watchdog = QueryWatchdog(
            timeout_seconds=watchdog_timeout_seconds,
        )
        self.degrader = ResponseDegrader(
            templates=degrade_templates,
        )

        # 看门狗超时时 → 自动降级到 EMERGENCY
        self.watchdog.on_timeout(self._on_watchdog_timeout)

        # 线程池（用于异步执行查询）
        self._executor = ThreadPoolExecutor(
            max_workers=10, thread_name_prefix="query-guardian"
        )

        # 运行状态
        self._running = False

        # psutil 资源监控（可选）
        self._resource_monitor: Optional["_ResourceMonitor"] = None
        if enable_psutil and HAS_PSUTIL:
            self._resource_monitor = _ResourceMonitor()

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def start(self):
        """
        启动所有防护机制。

        类比：微服务启动时注册健康检查、启用熔断器
        """
        if self._running:
            return
        self._running = True
        self.watchdog.start()
        if self._resource_monitor:
            self._resource_monitor.start()
        logging.info("[QueryGuardian] 五层查询防护已启动")

    def stop(self):
        """
        停止所有防护机制。

        类比：微服务的 graceful shutdown
        """
        self._running = False
        self.watchdog.stop()
        self._executor.shutdown(wait=True, cancel_futures=True)
        if self._resource_monitor:
            self._resource_monitor.stop()
        logging.info("[QueryGuardian] 五层查询防护已停止")

    # ------------------------------------------------------------------
    # 核心方法: ask() —— 带完整防护的查询
    # ------------------------------------------------------------------

    def ask(self,
            query_text: str,
            source: str = "default",
            metadata: Optional[Dict[str, Any]] = None) -> DegradedResponse:
        """
        执行一次带完整防护的查询。

        这是整个 QueryGuardian 的入口方法——用户只需要调用这一个方法，
        所有五层防护自动生效。

        执行流程：
          1. 背压检查——是否应该限流？
          2. Source 限流——来源是否超 QPS？
          3. 创建查询上下文 + 注册看门狗
          4. 渐进查询：CACHE → COARSE → RERANK → GENERATE
          5. 评估降级级别
          6. 生成回答（根据降级级别）
          7. 注销看门狗 + 记录延迟

        Args:
            query_text: 查询文本
            source: 查询来源（如 "web", "api", "vector_db", "llm"）
            metadata: 额外元数据

        Returns:
            DegradedResponse 对象（可能包含降级回答）

        类比：AWS API Gateway 的请求处理流水线
              ——鉴权 → 限流 → 路由 → 处理 → 响应
        """
        start_time = time.time()

        # ---- Step 1: 背压检查 ----
        if self.backpressure.should_throttle():
            # 被限流——直接返回降级回答
            return self.degrader.generate_response(
                level=DegradationLevel.MINIMAL,
                query_text=query_text,
                template_key="overload",
            )

        # ---- Step 2: Per-source 限流 ----
        if not self.backpressure.check_source_allowed(source):
            return self.degrader.generate_response(
                level=DegradationLevel.MINIMAL,
                query_text=query_text,
                template_key="overload",
            )

        # ---- Step 3: 创建查询上下文 ----
        query_id = self._generate_query_id(query_text, source)
        query_ctx = QueryContext(
            query_id=query_id,
            query_text=query_text,
            source=source,
            metadata=metadata or {},
        )

        # 注册到看门狗
        self.watchdog.register(query_ctx)
        self.backpressure.increment_queue()

        try:
            # ---- Step 4: 渐进式查询 ----
            # 在独立线程中执行（可被看门狗中断）
            future = self._executor.submit(self.engine.execute, query_ctx)
            try:
                query_ctx = future.result(timeout=self.watchdog.timeout_seconds)
            except FutureTimeoutError:
                # 执行超时——看门狗会处理，这里返回降级回答
                return self.degrader.generate_response(
                    level=DegradationLevel.EMERGENCY,
                    query_text=query_text,
                    template_key="timeout",
                )

            # ---- Step 5: 评估降级级别 ----
            cache_hit = QueryLayer.CACHE in query_ctx.layer_results
            watchdog_timeout = query_ctx.metadata.get("watchdog_timeout", False)

            level = self.degrader.evaluate(
                cache_hit=cache_hit,
                backpressure=self.backpressure,
                memory_gc=self.memory_gc,
                watchdog_timeout=watchdog_timeout,
            )

            # ---- Step 6: 生成回答 ----
            if level == DegradationLevel.FULL and QueryLayer.GENERATE in query_ctx.layer_results:
                # 完整模式 + 有生成结果 → 返回完整回答
                gen_result = query_ctx.layer_results[QueryLayer.GENERATE]
                if isinstance(gen_result, dict) and "answer" in gen_result:
                    response = DegradedResponse(
                        level=level,
                        answer=gen_result["answer"],
                        is_degraded=False,
                        original_query=query_text,
                        partial_results=gen_result.get("sources"),
                    )
                else:
                    response = DegradedResponse(
                        level=level,
                        answer=str(gen_result),
                        is_degraded=False,
                        original_query=query_text,
                    )
            elif cache_hit and level <= DegradationLevel.REDUCED:
                # 缓存命中 → 降级模式用缓存结果
                cached = query_ctx.layer_results[QueryLayer.CACHE]
                response = self.degrader.generate_response(
                    level=level,
                    query_text=query_text,
                    cached_response=str(cached) if cached else None,
                )
            elif level >= DegradationLevel.MINIMAL:
                # 降级到模板
                response = self.degrader.generate_response(
                    level=level,
                    query_text=query_text,
                    template_key="default",
                )
            else:
                # 兜底
                response = self.degrader.generate_response(
                    level=DegradationLevel.MINIMAL,
                    query_text=query_text,
                    template_key="default",
                )

            # ---- Step 7: 更新内存 GC（存储查询上下文） ----
            self.memory_gc.store_context(
                context_id=query_id,
                content={"query_ctx": query_ctx, "response": response},
                estimated_size_bytes=0,  # 自动估算
            )

            return response

        except Exception as e:
            logging.error(f"[QueryGuardian] 查询异常: {e}", exc_info=True)
            return self.degrader.generate_response(
                level=DegradationLevel.EMERGENCY,
                query_text=query_text,
                template_key="emergency",
            )
        finally:
            # 清理
            self.watchdog.unregister(query_id)
            self.backpressure.decrement_queue()
            # 记录延迟
            elapsed_ms = (time.time() - start_time) * 1000
            self.backpressure.record_latency(elapsed_ms)

    # ------------------------------------------------------------------
    # 便捷方法
    # ------------------------------------------------------------------

    def ask_with_cache(self,
                        query_text: str,
                        source: str = "default") -> DegradedResponse:
        """
        查询并尝试缓存（REDUCED 降级时优先使用缓存）。
        这是 ask() 的别名，语义更明确。
        """
        return self.ask(query_text=query_text, source=source)

    def warm_cache(self, query_text: str, answer: str):
        """
        预热缓存——将已知的问答对写入缓存。

        类比：CDN 的缓存预热（cache warming）
              ——在上线前预先填充热门内容
        """
        self.engine._cache_set(query_text, answer)

    def clear_cache(self):
        """清空所有缓存。类比：CDN 的缓存刷新（cache purge）。"""
        self.engine.clear_cache()

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    def _generate_query_id(self, query_text: str, source: str) -> str:
        """生成全局唯一查询 ID。"""
        raw = f"{source}:{query_text}:{time.time()}:{id(query_text)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _on_watchdog_timeout(self, query_id: str, query_ctx: QueryContext):
        """
        看门狗超时回调——标记查询上下文。

        类比：Kubernetes Pod 的 preStop hook
              ——容器被终止前执行清理逻辑
        """
        query_ctx.metadata["watchdog_timeout"] = True
        query_ctx.metadata["timeout_at"] = time.time()

    # ------------------------------------------------------------------
    # 健康报告
    # ------------------------------------------------------------------

    def get_health_report(self) -> Dict[str, Any]:
        """
        返回完整健康报告——五层防护的全部指标。

        类比：Spring Boot Actuator 的 /health 端点
              Kubernetes 的 Pod Status + Conditions
        """
        report = {
            "timestamp": time.time(),
            "running": self._running,
            "layers": {
                "1_progressive_engine": self.engine.get_stats(),
                "2_backpressure": self.backpressure.get_stats(),
                "3_memory_gc": self.memory_gc.get_stats(),
                "4_watchdog": self.watchdog.get_stats(),
                "5_response_degrader": self.degrader.get_stats(),
            },
        }
        if self._resource_monitor:
            report["resource"] = self._resource_monitor.get_snapshot()
        return report

    def print_health_report(self):
        """以可读格式打印健康报告。"""
        report = self.get_health_report()
        print("=" * 60)
        print("📊 Query Guardian — 健康报告")
        print("=" * 60)
        for layer_name, stats in report["layers"].items():
            print(f"\n[{layer_name}]")
            for k, v in stats.items():
                print(f"  {k}: {v}")
        if "resource" in report:
            print(f"\n[resource]")
            for k, v in report["resource"].items():
                print(f"  {k}: {v}")
        print("=" * 60)


# ================================================================
# 资源监控器（内部类）
# ================================================================

class _ResourceMonitor:
    """
    轻量资源监控器——用于健康报告中的系统指标。

    类比：Node.js 的 os.loadavg() + process.memoryUsage()
    """

    def __init__(self):
        self._process = psutil.Process() if HAS_PSUTIL else None
        self._running = False
        self._lock = threading.Lock()
        self._cpu_pct: float = 0.0
        self._mem_mb: float = 0.0

    def start(self):
        if not self._process:
            return
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True, name="resource-monitor")
        t.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                with self._lock:
                    if self._process:
                        self._cpu_pct = self._process.cpu_percent(interval=0.5)
                        self._mem_mb = self._process.memory_info().rss / (1024 * 1024)
            except Exception:
                pass
            time.sleep(2.0)

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {"cpu_pct": self._cpu_pct, "mem_mb": self._mem_mb}


# ================================================================
# 自测
# ================================================================
if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print("=" * 60)
    print("Query Guardian — 五层查询防护自测")
    print("=" * 60)

    # ── 创建 QueryGuardian 实例 ──
    guardian = QueryGuardian(
        coarse_max_items=500,           # 粗筛保留 500 条
        fine_max_items=30,              # 精排保留 30 条
        generate_max_items=3,           # 最终 Top-3
        backpressure_max_queue=5000,    # 队列深度硬限 5000
        backpressure_p99_threshold_ms=500.0,  # P99 阈值 500ms
        memory_soft_limit_mb=200.0,     # 内存软限 200MB
        memory_hard_limit_mb=500.0,     # 内存硬限 500MB
        watchdog_timeout_seconds=5.0,   # 看门狗超时 5s（自测用较短值）
    )
    guardian.start()

    print("\n🧪 测试 1: 基本查询（应走完整流水线）")
    print("-" * 40)
    response = guardian.ask("什么是渐进式查询？", source="test")
    print(f"  级别: {response.level.name}")
    print(f"  降级: {response.is_degraded}")
    print(f"  回答: {response.answer[:80]}...")

    print("\n🧪 测试 2: 相同查询再次执行（应命中缓存）")
    print("-" * 40)
    response2 = guardian.ask("什么是渐进式查询？", source="test")
    print(f"  级别: {response2.level.name}")
    print(f"  降级: {response2.is_degraded}")
    print(f"  回答: {response2.answer[:80]}...")

    print("\n🧪 测试 3: 设置 per-source 限流")
    print("-" * 40)
    guardian.backpressure.set_source_limit("api", 2.0)  # api 来源最多 2 QPS
    print("  已设置 api 来源限流: 2 QPS")
    for i in range(5):
        resp = guardian.ask(f"测试查询 {i+1}", source="api")
        print(f"  第 {i+1} 次: 级别={resp.level.name}, 降级={resp.is_degraded}")

    print("\n🧪 测试 4: 内存 GC 功能")
    print("-" * 40)
    # 存储大量上下文模拟内存压力
    for i in range(20):
        large_content = "x" * (10 * 1024 * 1024)  # 10MB 字符串
        guardian.memory_gc.store_context(
            context_id=f"session_{i}",
            content=large_content,
            estimated_size_bytes=10 * 1024 * 1024,
        )
    gc_stats = guardian.memory_gc.get_stats()
    print(f"  总内存: {gc_stats['total_memory_mb']:.1f}MB")
    print(f"  上下文数: {gc_stats['context_count']}")
    print(f"  已压缩: {gc_stats['compressed_count']}")
    print(f"  已淘汰: {gc_stats['total_evictions']}")
    print(f"  总释放: {gc_stats['freed_mb']:.1f}MB")

    # 清理
    for i in range(20):
        guardian.memory_gc.remove_context(f"session_{i}")

    print("\n🧪 测试 5: 看门狗超时熔断")
    print("-" * 40)
    # 创建一个处理耗时很长的查询场景
    def slow_handler(query_text, candidates, max_k):
        """模拟一个需要 10 秒才能完成的处理器"""
        time.sleep(10)
        return [{"id": "slow_doc", "score": 0.9}]

    # 注册一个慢处理器到粗筛层
    guardian.engine.register_handler(QueryLayer.COARSE_FILTER, slow_handler)
    resp = guardian.ask("这是一个很慢的查询", source="test")
    print(f"  级别: {resp.level.name}")
    print(f"  降级: {resp.is_degraded}")
    print(f"  原因: {resp.degrade_reason}")
    print(f"  回答: {resp.answer[:80]}...")

    # 恢复默认处理器
    guardian.engine.register_handler(QueryLayer.COARSE_FILTER, None)

    print("\n🧪 测试 6: 回答降级模板")
    print("-" * 40)
    # 手动测试各级降级
    for level in DegradationLevel:
        resp = guardian.degrader.generate_response(
            level=level,
            query_text="测试查询",
            template_key="default",
        )
        print(f"  {level.name:10s}: 降级={resp.is_degraded}, "
              f"回答='{resp.answer[:50]}...'")

    print("\n🧪 测试 7: 自定义降级模板")
    print("-" * 40)
    guardian.degrader.set_template(
        "custom",
        "自定义模板：您的问题「{query}」暂时无法处理。请稍后再试。"
    )
    resp = guardian.degrader.generate_response(
        level=DegradationLevel.MINIMAL,
        query_text="自定义测试",
        template_key="custom",
    )
    print(f"  级别: {resp.level.name}")
    print(f"  回答: {resp.answer}")

    print("\n" + "=" * 60)
    print("📊 最终健康报告")
    print("=" * 60)
    guardian.print_health_report()

    guardian.stop()
    print("\n✅ 五层查询防护自测完成")
