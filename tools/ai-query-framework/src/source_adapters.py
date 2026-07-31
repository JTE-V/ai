"""
数据源适配器层 — Data Source Adapters
======================================
提供多种数据源后端的统一适配接口。
所有适配器继承自 BaseAdapter，遵循统一的生命周期合约。

适配器列表：
  1. VectorDBAdapter   — 适配向量数据库（Milvus / Pinecone / Chroma）
  2. APIAdapter        — 适配 REST API 数据源
  3. DatabaseAdapter   — 适配 SQL 数据库（MySQL / PostgreSQL / SQLite）
  4. FileAdapter       — 适配本地文件（CSV / JSON / Parquet / TXT）

每个适配器：
  - 完整的 initialize / execute / health_check / shutdown 实现
  - 具体的错误处理和重试逻辑
  - 详细的中文注释

类比：
  - Spring Data 的统一 Repository 抽象
  - Go 的 database/sql 标准接口
  - Python SQLAlchemy 的 Engine 模式
  - LangChain 的 DocumentLoader / VectorStore 抽象

设计原则：
  - 依赖倒置（DIP）：上层依赖 BaseAdapter 抽象
  - 适配器模式（Adapter Pattern）：将异构数据源统一为 execute() 接口
  - 单一职责（SRP）：每个适配器只负责一种数据源类型
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import random
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse

# ---------------------------------------------------------------------------
# 从 llm_adapters 导入基类（框架内依赖）
# ---------------------------------------------------------------------------
from llm_adapters import (
    BaseAdapter,
    AdapterConfig,
    AdapterResponse,
    AdapterState,
)

# ---------------------------------------------------------------------------
# 可选依赖（若未安装则降级）
# ---------------------------------------------------------------------------
try:
    import requests
    _HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]
    _HAS_REQUESTS = False

try:
    import numpy as np  # type: ignore[import-untyped]
    _HAS_NUMPY = True
except ImportError:  # pragma: no cover
    np = None  # type: ignore[assignment]
    _HAS_NUMPY = False

try:
    import chromadb  # type: ignore[import-untyped]
    _HAS_CHROMADB = True
except ImportError:  # pragma: no cover
    chromadb = None  # type: ignore[assignment]
    _HAS_CHROMADB = False

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ============================================================================
# 1. 数据源专属枚举
# ============================================================================

class VectorIndexType(Enum):
    """向量数据库索引类型。"""
    HNSW = "hnsw"          # 分层可导航小世界图 — 高召回、较快
    IVF = "ivf"            # 倒排文件索引 — 内存友好、适度召回
    FLAT = "flat"          # 暴力搜索 — 100% 召回、最慢
    DISKANN = "diskann"    # 磁盘索引 — 适合超大规模（仅 Milvus 支持）
    ANNOY = "annoy"        # 树索引 — 仅读友好（Spotify 出品）


class SimilarityMetric(Enum):
    """向量相似度度量。"""
    COSINE = "cosine"           # 余弦相似度
    EUCLIDEAN = "euclidean"     # 欧几里得距离（L2）
    DOT_PRODUCT = "dot_product" # 点积（内积）
    MANHATTAN = "manhattan"     # 曼哈顿距离（L1）


# ============================================================================
# 2. 面向数据源的查询与结果数据类
# ============================================================================

@dataclass
class SourceQuery:
    """
    数据源查询请求 — 在进入适配器前由上层的 QuerySource 转换而来。

    字段说明：
      query_text   : 查询文本（自然语言或关键词）
      query_vector : 查询向量（向量数据库专用，可选）
      filters      : 过滤条件（如 {"date": "2025-01-01", "category": "finance"}）
      top_k        : 返回结果数量（默认 10）
      extra        : 扩展参数
    """
    query_text: str = ""
    query_vector: Optional[List[float]] = None
    filters: Dict[str, Any] = field(default_factory=dict)
    top_k: int = 10
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SourceResult:
    """
    数据源查询结果 — 适配器 execute() 的标准返回值。

    字段说明：
      items       : 结果项列表
      total_count : 总命中数（可能 > len(items) 当做了截断）
      source_name : 数据源名称（用于多源合并时的溯源）
      latency_ms  : 查询耗时（毫秒）
      metadata    : 扩展元数据
    """
    items: List[Dict[str, Any]] = field(default_factory=list)
    total_count: int = 0
    source_name: str = ""
    latency_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# 3. VectorDBAdapter — 向量数据库适配器
# ============================================================================

class VectorDBAdapter(BaseAdapter):
    """
    适配向量数据库 — 支持 Milvus / Pinecone / Chroma 三种后端。

    特性：
      - 统一的相似度搜索接口（search / hybrid_search）
      - 支持 HNSW / IVF / FLAT / DISKANN 索引类型选择
      - 支持多种相似度度量（余弦、欧几里得、点积）
      - 支持元数据过滤（metadata filtering）
      - 向量插入和删除（用于构建索引）

    配置项（通过 AdapterConfig.extra 传递）：
      backend          : 向量数据库类型 — "milvus" | "pinecone" | "chroma"（默认 "chroma"）
      collection_name  : 集合/索引名称
      dimension        : 向量维度（默认 1536，OpenAI embedding 维度）
      index_type       : 索引类型（默认 hnsw）
      metric           : 相似度度量（默认 cosine）
      connection_uri   : 连接 URI（如 Milvus 的 gRPC 地址，或 Chroma 的持久化目录）
      api_key          : API Key（Pinecone 必需）

    类比：
      - Milvus Python SDK 的 Collection.search()
      - Pinecone 的 Index.query()
      - LangChain 的 Chroma.as_retriever()
    """

    _VALID_BACKENDS = ("milvus", "pinecone", "chroma")

    def __init__(self, config: Optional[AdapterConfig] = None):
        """初始化向量数据库适配器。"""
        super().__init__(config)
        # 底层客户端/集合实例
        self._collection: Optional[Any] = None    # Milvus Collection / Pinecone Index / Chroma Collection
        self._backend: str = ""                    # 当前后端类型
        self._dimension: int = 1536                # 向量维度
        self._index_type: VectorIndexType = VectorIndexType.HNSW
        self._metric: SimilarityMetric = SimilarityMetric.COSINE

    # ------------------------------------------------------------------
    # _do_initialize
    # ------------------------------------------------------------------

    def _do_initialize(self) -> bool:
        """
        初始化向量数据库连接。

        步骤：
          1. 确定后端类型和连接参数
          2. 建立连接
          3. 获取或创建集合
          4. 验证索引配置

        返回：
          True 表示初始化成功
        """
        self._backend = self.config.extra.get("backend", "chroma")
        if self._backend not in self._VALID_BACKENDS:
            logger.error(
                "[%s] 无效的向量数据库后端: %s。支持: %s",
                self.config.adapter_id,
                self._backend,
                self._VALID_BACKENDS,
            )
            return False

        self._dimension = int(self.config.extra.get("dimension", 1536))
        index_str = self.config.extra.get("index_type", "hnsw")
        try:
            self._index_type = VectorIndexType(index_str.lower())
        except ValueError:
            logger.warning(
                "[%s] 未知索引类型 %s，回退到 HNSW",
                self.config.adapter_id,
                index_str,
            )
            self._index_type = VectorIndexType.HNSW

        metric_str = self.config.extra.get("metric", "cosine")
        try:
            self._metric = SimilarityMetric(metric_str.lower())
        except ValueError:
            logger.warning(
                "[%s] 未知度量 %s，回退到 COSINE",
                self.config.adapter_id,
                metric_str,
            )
            self._metric = SimilarityMetric.COSINE

        logger.info(
            "[%s] 初始化向量数据库 (backend=%s, dim=%d, index=%s, metric=%s)",
            self.config.adapter_id,
            self._backend,
            self._dimension,
            self._index_type.value,
            self._metric.value,
        )

        # 根据后端类型分支处理
        if self._backend == "milvus":
            return self._init_milvus()
        elif self._backend == "pinecone":
            return self._init_pinecone()
        elif self._backend == "chroma":
            return self._init_chroma()
        return False

    def _init_milvus(self) -> bool:
        """
        初始化 Milvus 连接。

        依赖: pip install pymilvus
        """
        try:
            from pymilvus import (  # type: ignore[import-untyped]
                Collection,
                CollectionSchema,
                DataType,
                FieldSchema,
                connections,
                utility,
            )
        except ImportError:
            logger.error(
                "[%s] pymilvus 未安装。请执行: pip install pymilvus",
                self.config.adapter_id,
            )
            return False

        connection_uri = self.config.extra.get("connection_uri", "localhost:19530")
        collection_name = self.config.extra.get("collection_name", "ai_query_default")

        try:
            # 建立 gRPC 连接
            connections.connect(
                alias=self.config.adapter_id or "default",
                uri=connection_uri,
            )

            # 检查集合是否存在，不存在则创建
            if utility.has_collection(collection_name):  # type: ignore[union-attr]
                self._collection = Collection(collection_name)
            else:
                logger.info(
                    "[%s] 集合 %s 不存在，自动创建 (dim=%d)",
                    self.config.adapter_id,
                    collection_name,
                    self._dimension,
                )
                # 定义 schema
                fields = [
                    FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
                    FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=self._dimension),
                    FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=65535),
                    FieldSchema(name="metadata", dtype=DataType.JSON),
                ]
                schema = CollectionSchema(fields, description="AIQuery 自动创建的集合")
                self._collection = Collection(collection_name, schema)

                # 创建索引
                index_params = self._build_milvus_index_params()
                self._collection.create_index("embedding", index_params)

            # 加载集合到内存
            self._collection.load()
            logger.info(
                "[%s] Milvus 集合 %s 已加载 (实体数: %d)",
                self.config.adapter_id,
                collection_name,
                self._collection.num_entities,
            )
            return True
        except Exception as exc:
            logger.exception("[%s] Milvus 初始化失败: %s", self.config.adapter_id, exc)
            return False

    def _init_pinecone(self) -> bool:
        """
        初始化 Pinecone 连接。

        依赖: pip install pinecone-client
        """
        try:
            import pinecone  # type: ignore[import-untyped]
        except ImportError:
            logger.error(
                "[%s] pinecone-client 未安装。请执行: pip install pinecone-client",
                self.config.adapter_id,
            )
            return False

        api_key = (
            self.config.extra.get("api_key")
            or os.environ.get("PINECONE_API_KEY")
            or ""
        )
        if not api_key:
            logger.error(
                "[%s] 未提供 Pinecone API Key",
                self.config.adapter_id,
            )
            return False

        index_name = self.config.extra.get("collection_name", "ai-query-default")
        environment = self.config.extra.get("environment", "us-east-1-aws")

        try:
            # Pinecone 新版 SDK (>= 3.0)
            if hasattr(pinecone, "Pinecone"):
                pc = pinecone.Pinecone(api_key=api_key)
                # 检查索引是否存在
                if index_name not in pc.list_indexes().names():
                    logger.info(
                        "[%s] 创建 Pinecone 索引 %s (dim=%d, metric=%s)",
                        self.config.adapter_id,
                        index_name,
                        self._dimension,
                        self._metric.value,
                    )
                    pc.create_index(
                        name=index_name,
                        dimension=self._dimension,
                        metric=self._metric.value,
                    )
                self._collection = pc.Index(index_name)
            else:
                # Pinecone 旧版 SDK (< 3.0)
                pinecone.init(api_key=api_key, environment=environment)
                if index_name not in pinecone.list_indexes():
                    pinecone.create_index(
                        name=index_name,
                        dimension=self._dimension,
                        metric=self._metric.value,
                    )
                self._collection = pinecone.Index(index_name)

            logger.info(
                "[%s] Pinecone 索引 %s 已连接",
                self.config.adapter_id,
                index_name,
            )
            return True
        except Exception as exc:
            logger.exception("[%s] Pinecone 初始化失败: %s", self.config.adapter_id, exc)
            return False

    def _init_chroma(self) -> bool:
        """
        初始化 Chroma 连接。

        Chroma 支持两种模式：
          - 持久化模式 (persistent): 数据存储在本地磁盘
          - 内存模式 (ephemeral): 数据仅在进程生命周期内有效

        依赖: pip install chromadb
        """
        if not _HAS_CHROMADB:
            logger.error(
                "[%s] chromadb 未安装。请执行: pip install chromadb",
                self.config.adapter_id,
            )
            return False

        collection_name = self.config.extra.get("collection_name", "ai_query_default")
        persist_dir = self.config.extra.get("connection_uri", "./chroma_data")

        try:
            if persist_dir:
                # 持久化模式
                client = chromadb.PersistentClient(path=persist_dir)  # type: ignore[union-attr]
            else:
                # 内存模式
                client = chromadb.Client()  # type: ignore[union-attr]

            # 获取或创建集合
            try:
                self._collection = client.get_collection(collection_name)
            except Exception:
                logger.info(
                    "[%s] 创建 Chroma 集合 %s (dim=%d, metric=%s)",
                    self.config.adapter_id,
                    collection_name,
                    self._dimension,
                    self._metric.value,
                )
                self._collection = client.create_collection(
                    name=collection_name,
                    metadata={
                        "dimension": self._dimension,
                        "metric": self._metric.value,
                        "hnsw:space": self._metric.value,
                    },
                )

            logger.info(
                "[%s] Chroma 集合 %s 已就绪 (元素数: %d)",
                self.config.adapter_id,
                collection_name,
                self._collection.count(),
            )
            return True
        except Exception as exc:
            logger.exception("[%s] Chroma 初始化失败: %s", self.config.adapter_id, exc)
            return False

    # ------------------------------------------------------------------
    # _do_execute
    # ------------------------------------------------------------------

    def _do_execute(self, messages: List[Dict[str, str]], **kwargs: Any) -> AdapterResponse:
        """
        执行向量相似度搜索。

        参数：
          messages : 对话消息列表（提取最后一条 user 消息作为查询文本）
          **kwargs : 可包含 query_vector, top_k, filters 等

        注意：向量数据库的 execute() 返回的 AdapterResponse.content
              是 JSON 序列化的搜索结果，方便上层统一处理。
        """
        # 从 kwargs 或 messages 中提取查询参数
        query = self._extract_source_query(messages, **kwargs)

        if not query.query_text and not query.query_vector:
            return AdapterResponse(
                content=json.dumps({"error": "查询文本和查询向量均为空"}),
                finish_reason="error",
                metadata={"error": "empty_query"},
            )

        start_time = time.time()

        try:
            if self._backend == "milvus":
                results = self._search_milvus(query)
            elif self._backend == "pinecone":
                results = self._search_pinecone(query)
            elif self._backend == "chroma":
                results = self._search_chroma(query)
            else:
                results = SourceResult(
                    items=[],
                    source_name=self._backend,
                    metadata={"error": f"不支持的后端: {self._backend}"},
                )
        except Exception as exc:
            logger.exception("[%s] 向量搜索失败: %s", self.config.adapter_id, exc)
            return AdapterResponse(
                content=json.dumps({"error": str(exc), "results": []}),
                finish_reason="error",
                latency_ms=(time.time() - start_time) * 1000,
                metadata={"error": str(exc)},
            )

        results.latency_ms = (time.time() - start_time) * 1000
        results.source_name = f"{self._backend}:{self.config.extra.get('collection_name', 'default')}"

        return AdapterResponse(
            content=json.dumps({
                "results": results.items,
                "total_count": results.total_count,
                "source": results.source_name,
            }, ensure_ascii=False),
            finish_reason="stop",
            latency_ms=results.latency_ms,
            metadata={
                "backend": self._backend,
                "index_type": self._index_type.value,
                "total_count": results.total_count,
            },
        )

    def _search_milvus(self, query: SourceQuery) -> SourceResult:
        """在 Milvus 中执行向量搜索。"""
        if self._collection is None:
            return SourceResult(items=[], metadata={"error": "Milvus 集合未加载"})

        # 生成查询向量（如果只给了文本）
        search_vector = query.query_vector
        if search_vector is None and query.query_text:
            search_vector = self._text_to_vector(query.query_text)

        if search_vector is None:
            return SourceResult(items=[], metadata={"error": "无法生成查询向量"})

        # 构建过滤表达式
        filter_expr = self._build_milvus_filter(query.filters)

        try:
            search_params = self._build_milvus_search_params()
            results = self._collection.search(
                data=[search_vector],
                anns_field="embedding",
                param=search_params,
                limit=query.top_k,
                expr=filter_expr or None,
                output_fields=["text", "metadata"],
            )
            items: List[Dict[str, Any]] = []
            if results and len(results) > 0:
                for hit in results[0]:
                    items.append({
                        "id": str(hit.id),
                        "score": float(hit.distance),
                        "text": hit.entity.get("text", ""),
                        "metadata": hit.entity.get("metadata", {}),
                    })
            return SourceResult(items=items, total_count=len(items))
        except Exception:
            raise

    def _search_pinecone(self, query: SourceQuery) -> SourceResult:
        """在 Pinecone 中执行向量搜索。"""
        if self._collection is None:
            return SourceResult(items=[], metadata={"error": "Pinecone 索引未加载"})

        search_vector = query.query_vector
        if search_vector is None and query.query_text:
            search_vector = self._text_to_vector(query.query_text)

        if search_vector is None:
            return SourceResult(items=[], metadata={"error": "无法生成查询向量"})

        try:
            results = self._collection.query(
                vector=search_vector,
                top_k=query.top_k,
                filter=query.filters if query.filters else None,
                include_metadata=True,
            )
            items: List[Dict[str, Any]] = []
            if "matches" in results:
                for match in results["matches"]:
                    items.append({
                        "id": match.get("id", ""),
                        "score": float(match.get("score", 0)),
                        "text": match.get("metadata", {}).get("text", ""),
                        "metadata": match.get("metadata", {}),
                    })
            return SourceResult(items=items, total_count=len(items))
        except Exception:
            raise

    def _search_chroma(self, query: SourceQuery) -> SourceResult:
        """在 Chroma 中执行向量搜索。"""
        if self._collection is None:
            return SourceResult(items=[], metadata={"error": "Chroma 集合未加载"})

        try:
            # Chroma 支持直接传文本（内部自动 embedding）
            if query.query_text:
                results = self._collection.query(
                    query_texts=[query.query_text],
                    n_results=query.top_k,
                    where=query.filters if query.filters else None,
                )
            elif query.query_vector:
                results = self._collection.query(
                    query_embeddings=[query.query_vector],
                    n_results=query.top_k,
                    where=query.filters if query.filters else None,
                )
            else:
                return SourceResult(items=[], metadata={"error": "查询参数为空"})

            items: List[Dict[str, Any]] = []
            if results and results.get("ids") and results["ids"][0]:
                ids_list = results["ids"][0]
                docs_list = results.get("documents", [[]])[0]
                metas_list = results.get("metadatas", [[]])[0] or []
                distances_list = results.get("distances", [[]])[0] or []

                for i, doc_id in enumerate(ids_list):
                    items.append({
                        "id": str(doc_id),
                        "score": float(distances_list[i]) if i < len(distances_list) else 0.0,
                        "text": docs_list[i] if i < len(docs_list) else "",
                        "metadata": metas_list[i] if i < len(metas_list) else {},
                    })

            return SourceResult(items=items, total_count=len(items))
        except Exception:
            raise

    # ------------------------------------------------------------------
    # _do_health_check
    # ------------------------------------------------------------------

    def _do_health_check(self) -> bool:
        """
        健康检查：验证向量数据库连通性和集合可用性。

        检查项：
          - Milvus:  检查集合是否存在且已加载
          - Pinecone: 检查索引是否存在
          - Chroma:  检查集合是否可访问（调用 count()）
        """
        try:
            if self._backend == "milvus":
                if self._collection is None:
                    return False
                # 检查集合是否正常
                _ = self._collection.num_entities
                logger.info("[%s] Milvus 健康检查通过", self.config.adapter_id)
                return True

            elif self._backend == "pinecone":
                if self._collection is None:
                    return False
                # 调用 describe_index_stats 验证
                stats = self._collection.describe_index_stats()
                logger.info(
                    "[%s] Pinecone 健康检查通过 (向量数: %s)",
                    self.config.adapter_id,
                    stats.get("total_vector_count", "N/A"),
                )
                return True

            elif self._backend == "chroma":
                if self._collection is None:
                    return False
                count = self._collection.count()
                logger.info(
                    "[%s] Chroma 健康检查通过 (元素数: %d)",
                    self.config.adapter_id,
                    count,
                )
                return True

            return False
        except Exception as exc:
            logger.warning(
                "[%s] 向量数据库健康检查失败: %s",
                self.config.adapter_id,
                exc,
            )
            return False

    # ------------------------------------------------------------------
    # _do_shutdown
    # ------------------------------------------------------------------

    def _do_shutdown(self) -> None:
        """
        关闭向量数据库连接，释放资源。

        Milvus 需要在关闭前释放集合（release）。
        Chroma 持久化客户端需要关闭。
        """
        try:
            if self._backend == "milvus" and self._collection is not None:
                try:
                    self._collection.release()
                except Exception:
                    pass

            # 清理引用
            self._collection = None
            logger.info(
                "[%s] 向量数据库连接已关闭 (backend=%s)",
                self.config.adapter_id,
                self._backend,
            )
        except Exception as exc:
            logger.warning(
                "[%s] 关闭向量数据库连接时出错: %s",
                self.config.adapter_id,
                exc,
            )

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _extract_source_query(
        self, messages: List[Dict[str, str]], **kwargs: Any
    ) -> SourceQuery:
        """从 messages 和 kwargs 中提取 SourceQuery。"""
        query_text = kwargs.get("query_text", "")
        if not query_text:
            # 提取最后一条 user 消息
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    query_text = msg.get("content", "")
                    break

        return SourceQuery(
            query_text=query_text,
            query_vector=kwargs.get("query_vector"),
            filters=kwargs.get("filters", {}),
            top_k=kwargs.get("top_k", self.config.extra.get("top_k", 10)),
            extra=kwargs.get("extra", {}),
        )

    def _build_milvus_index_params(self) -> Dict[str, Any]:
        """根据配置构建 Milvus 索引参数。"""
        if self._index_type == VectorIndexType.HNSW:
            return {
                "index_type": "HNSW",
                "metric_type": self._metric.value.upper(),
                "params": {"M": 16, "efConstruction": 200},
            }
        elif self._index_type == VectorIndexType.IVF:
            return {
                "index_type": "IVF_FLAT",
                "metric_type": self._metric.value.upper(),
                "params": {"nlist": 128},
            }
        elif self._index_type == VectorIndexType.DISKANN:
            return {
                "index_type": "DISKANN",
                "metric_type": self._metric.value.upper(),
                "params": {},
            }
        else:
            return {
                "index_type": "FLAT",
                "metric_type": self._metric.value.upper(),
                "params": {},
            }

    def _build_milvus_search_params(self) -> Dict[str, Any]:
        """根据配置构建 Milvus 搜索参数。"""
        if self._index_type == VectorIndexType.HNSW:
            return {"metric_type": self._metric.value.upper(), "params": {"ef": 64}}
        elif self._index_type == VectorIndexType.IVF:
            return {"metric_type": self._metric.value.upper(), "params": {"nprobe": 16}}
        else:
            return {"metric_type": self._metric.value.upper(), "params": {}}

    def _build_milvus_filter(self, filters: Dict[str, Any]) -> Optional[str]:
        """
        将 filters 字典转换为 Milvus 布尔表达式字符串。

        示例：
          {"category": "finance", "year": 2025}
          → 'category == "finance" and year == 2025'
        """
        if not filters:
            return None
        parts: List[str] = []
        for key, value in filters.items():
            if isinstance(value, str):
                parts.append(f'{key} == "{value}"')
            elif isinstance(value, (int, float)):
                parts.append(f"{key} == {value}")
            elif isinstance(value, list):
                values_str = ", ".join(
                    f'"{v}"' if isinstance(v, str) else str(v) for v in value
                )
                parts.append(f"{key} in [{values_str}]")
        return " and ".join(parts) if parts else None

    def _text_to_vector(self, text: str) -> Optional[List[float]]:
        """
        将文本转换为向量（占位 embedding）。

        @TODO 实际项目中应接入真实的 embedding 模型
              （如 OpenAI text-embedding-ada-002 或本地 sentence-transformers）。
        当前使用一个基于文本 hash 的确定性伪向量（仅用于测试）。
        """
        if not text:
            return None
        # 使用 hash 生成确定性伪向量（仅供测试）
        seed = hash(text) % (2 ** 31)
        rng = random.Random(seed)
        return [rng.uniform(-1.0, 1.0) for _ in range(self._dimension)]

    # ------------------------------------------------------------------
    # 公开的扩展方法
    # ------------------------------------------------------------------

    def insert(
        self,
        texts: List[str],
        embeddings: Optional[List[List[float]]] = None,
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None,
    ) -> bool:
        """
        向向量数据库插入数据。

        参数：
          texts      : 文本列表
          embeddings : 向量列表（可选，为 None 时自动生成）
          metadatas  : 元数据列表（可选）
          ids        : ID 列表（可选，为 None 时自动生成）

        返回：
          True 表示插入成功
        """
        n = len(texts)
        if embeddings is None:
            embeddings = [self._text_to_vector(t) for t in texts]
        if metadatas is None:
            metadatas = [{} for _ in range(n)]
        if ids is None:
            ids = [f"doc_{int(time.time() * 1000)}_{i}" for i in range(n)]

        try:
            if self._backend == "chroma" and self._collection is not None:
                self._collection.add(
                    ids=ids,
                    documents=texts,
                    embeddings=embeddings,
                    metadatas=metadatas,
                )
                logger.info(
                    "[%s] Chroma 插入 %d 条记录",
                    self.config.adapter_id,
                    n,
                )
                return True
            elif self._backend == "milvus" and self._collection is not None:
                data = [
                    [t for t in texts],                         # text 列
                    [e for e in embeddings],                     # embedding 列
                    [json.dumps(m) for m in metadatas],          # metadata 列
                ]
                self._collection.insert(data)
                self._collection.flush()
                logger.info(
                    "[%s] Milvus 插入 %d 条记录",
                    self.config.adapter_id,
                    n,
                )
                return True
            elif self._backend == "pinecone" and self._collection is not None:
                vectors = []
                for i in range(n):
                    vectors.append({
                        "id": ids[i],
                        "values": embeddings[i] if embeddings else [],
                        "metadata": {
                            "text": texts[i],
                            **(metadatas[i] if metadatas else {}),
                        },
                    })
                self._collection.upsert(vectors=vectors)
                logger.info(
                    "[%s] Pinecone 插入 %d 条记录",
                    self.config.adapter_id,
                    n,
                )
                return True
            else:
                logger.error("[%s] 插入失败: 集合未加载", self.config.adapter_id)
                return False
        except Exception as exc:
            logger.exception("[%s] 插入数据失败: %s", self.config.adapter_id, exc)
            return False

    def delete(self, ids: List[str]) -> bool:
        """
        从向量数据库删除数据。

        参数：
          ids : 要删除的文档 ID 列表

        返回：
          True 表示删除成功
        """
        try:
            if self._backend == "chroma" and self._collection is not None:
                self._collection.delete(ids=ids)
            elif self._backend == "pinecone" and self._collection is not None:
                self._collection.delete(ids=ids)
            elif self._backend == "milvus" and self._collection is not None:
                # Milvus 通过主键表达式删除
                ids_str = ", ".join(ids)
                expr = f"id in [{ids_str}]"
                self._collection.delete(expr)
            logger.info(
                "[%s] 删除了 %d 条记录",
                self.config.adapter_id,
                len(ids),
            )
            return True
        except Exception as exc:
            logger.exception("[%s] 删除数据失败: %s", self.config.adapter_id, exc)
            return False


# ============================================================================
# 4. APIAdapter — REST API 数据源适配器
# ============================================================================

class APIAdapter(BaseAdapter):
    """
    适配 REST API 数据源 — 统一的 HTTP 客户端封装。

    特性：
      - 支持 GET / POST / PUT / DELETE 方法
      - 支持多种鉴权方式（Bearer Token / API Key / Basic Auth / OAuth2）
      - 支持自动重试（指数退避）
      - 支持超时控制
      - 支持响应缓存（可选）
      - 支持请求/响应拦截器

    配置项（通过 AdapterConfig.extra 传递）：
      base_url     : API 基础 URL（如 https://api.example.com/v1）
      auth_type    : 鉴权类型 — "bearer" | "api_key" | "basic" | "oauth2" | "none"
      auth_token   : Bearer Token / API Key 值
      auth_username: Basic Auth 用户名
      auth_password: Basic Auth 密码
      headers      : 额外的请求头
      verify_ssl   : 是否验证 SSL 证书（默认 True）
      cache_ttl    : 响应缓存 TTL（秒，0 表示不缓存）

    类比：
      - Python requests.Session
      - Axios (JavaScript)
      - Spring RestTemplate
      - Kubernetes client-go 的 RESTClient
    """

    # 支持的 HTTP 方法
    _HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

    def __init__(self, config: Optional[AdapterConfig] = None):
        """初始化 API 适配器。"""
        super().__init__(config)
        self._session: Optional[Any] = None    # requests.Session 实例
        self._base_url: str = ""
        self._auth_type: str = "none"
        # 简易内存缓存（用于可选的响应缓存）
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------------
    # _do_initialize
    # ------------------------------------------------------------------

    def _do_initialize(self) -> bool:
        """
        初始化 HTTP 会话。

        步骤：
          1. 验证依赖（requests）
          2. 构建 requests.Session 并配置默认参数
          3. 设置鉴权头
          4. 设置请求拦截器（日志记录）

        返回：
          True 表示初始化成功
        """
        if not _HAS_REQUESTS:
            logger.error(
                "[%s] requests 库未安装。请执行: pip install requests",
                self.config.adapter_id,
            )
            return False

        self._base_url = self.config.extra.get("base_url", "")
        self._auth_type = self.config.extra.get("auth_type", "none")

        # 创建持久会话（连接复用）
        self._session = requests.Session()

        # 设置默认超时
        self._session.timeout = self.config.timeout

        # 设置 SSL 验证
        verify_ssl = self.config.extra.get("verify_ssl", True)
        self._session.verify = verify_ssl

        # 设置鉴权
        self._setup_auth()

        # 设置默认请求头
        default_headers = self.config.extra.get("headers", {})
        if default_headers:
            self._session.headers.update(default_headers)

        # 确保有 User-Agent
        if "User-Agent" not in self._session.headers:
            self._session.headers["User-Agent"] = (
                f"AIQuery-Framework/1.0 (Adapter: {self.config.adapter_id})"
            )

        logger.info(
            "[%s] API 适配器已初始化 (base_url=%s, auth=%s)",
            self.config.adapter_id,
            self._base_url or "(未设置)",
            self._auth_type,
        )
        return True

    def _setup_auth(self) -> None:
        """根据 auth_type 设置鉴权头。"""
        if self._session is None:
            return

        if self._auth_type == "bearer":
            token = self.config.extra.get("auth_token", "")
            if token:
                self._session.headers["Authorization"] = f"Bearer {token}"

        elif self._auth_type == "api_key":
            api_key = self.config.extra.get("auth_token", "")
            header_name = self.config.extra.get("api_key_header", "X-API-Key")
            if api_key:
                self._session.headers[header_name] = api_key

        elif self._auth_type == "basic":
            username = self.config.extra.get("auth_username", "")
            password = self.config.extra.get("auth_password", "")
            if username and password:
                from requests.auth import HTTPBasicAuth  # type: ignore[union-attr]
                self._session.auth = HTTPBasicAuth(username, password)

        elif self._auth_type == "oauth2":
            # @TODO: 实现 OAuth2 client_credentials flow
            token_url = self.config.extra.get("token_url", "")
            client_id = self.config.extra.get("client_id", "")
            client_secret = self.config.extra.get("client_secret", "")
            if token_url and client_id and client_secret:
                try:
                    token_resp = self._session.post(
                        token_url,
                        data={
                            "grant_type": "client_credentials",
                            "client_id": client_id,
                            "client_secret": client_secret,
                        },
                    )
                    token_resp.raise_for_status()
                    access_token = token_resp.json().get("access_token", "")
                    if access_token:
                        self._session.headers["Authorization"] = f"Bearer {access_token}"
                        logger.info(
                            "[%s] OAuth2 令牌已获取",
                            self.config.adapter_id,
                        )
                except Exception as exc:
                    logger.warning(
                        "[%s] OAuth2 令牌获取失败: %s",
                        self.config.adapter_id,
                        exc,
                    )

    # ------------------------------------------------------------------
    # _do_execute
    # ------------------------------------------------------------------

    def _do_execute(self, messages: List[Dict[str, str]], **kwargs: Any) -> AdapterResponse:
        """
        执行 HTTP API 请求。

        从 kwargs 中提取：
          method   : HTTP 方法（默认 GET）
          path     : API 路径（相对于 base_url）
          params   : URL 查询参数
          data     : 请求体（JSON 或 form）
          headers  : 本次请求的额外头

        messages 的使用：
          将最后一条 user 消息的 content 作为默认的查询参数 q。
        """
        method = kwargs.get("method", "GET").upper()
        if method not in self._HTTP_METHODS:
            return AdapterResponse(
                content=json.dumps({"error": f"不支持的 HTTP 方法: {method}"}),
                finish_reason="error",
            )

        path = kwargs.get("path", "")
        url = urljoin(self._base_url, path) if self._base_url else path
        if not url:
            # 尝试从最后一条 user 消息中解析 URL
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    url = msg.get("content", "")
                    break

        if not url:
            return AdapterResponse(
                content=json.dumps({"error": "未提供 API URL 且无法从消息中推断"}),
                finish_reason="error",
                metadata={"error": "missing_url"},
            )

        params = kwargs.get("params", {})
        data = kwargs.get("data", None)
        req_headers = kwargs.get("headers", {})

        # 如果没有显式 params 且是 GET 请求，尝试把最后一条 user 消息作为 q 参数
        if method == "GET" and not params:
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    content = msg.get("content", "").strip()
                    if content and not content.startswith("http"):
                        params = {"q": content}
                    break

        start_time = time.time()

        for attempt in range(1, self.config.max_retries + 1):
            try:
                # 检查缓存（仅 GET 请求）
                if method == "GET":
                    cache_key = self._build_cache_key(url, params)
                    cached = self._get_from_cache(cache_key)
                    if cached is not None:
                        logger.info(
                            "[%s] 命中缓存: %s",
                            self.config.adapter_id,
                            url,
                        )
                        return AdapterResponse(
                            content=json.dumps(cached, ensure_ascii=False),
                            finish_reason="stop",
                            latency_ms=(time.time() - start_time) * 1000,
                            metadata={"cached": True, "url": url},
                        )

                # 发送请求
                if self._session is None:
                    return AdapterResponse(
                        content=json.dumps({"error": "HTTP 会话未初始化"}),
                        finish_reason="error",
                    )

                response = self._session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=data if isinstance(data, dict) else None,
                    data=data if not isinstance(data, dict) else None,
                    headers=req_headers,
                )
                response.raise_for_status()

                # 解析响应
                try:
                    parsed = response.json()
                except json.JSONDecodeError:
                    parsed = {"text": response.text}

                elapsed = (time.time() - start_time) * 1000

                # 写入缓存（仅 GET）
                if method == "GET":
                    cache_key = self._build_cache_key(url, params)
                    self._put_to_cache(cache_key, parsed)

                return AdapterResponse(
                    content=json.dumps(parsed, ensure_ascii=False),
                    finish_reason="stop",
                    latency_ms=elapsed,
                    metadata={
                        "url": url,
                        "status_code": response.status_code,
                        "method": method,
                    },
                )

            except requests.exceptions.Timeout:  # type: ignore[union-attr]
                logger.warning(
                    "[%s] 第 %d/%d 次请求超时: %s",
                    self.config.adapter_id,
                    attempt,
                    self.config.max_retries,
                    url,
                )
                if attempt == self.config.max_retries:
                    return AdapterResponse(
                        content=json.dumps({"error": f"请求超时（{self.config.timeout}s）"}),
                        finish_reason="error",
                        latency_ms=(time.time() - start_time) * 1000,
                        metadata={"error": "timeout", "url": url},
                    )
                time.sleep(min(2 ** attempt, self.config.timeout / 2))

            except requests.exceptions.HTTPError as exc:  # type: ignore[union-attr]
                status_code = exc.response.status_code if exc.response else 0
                # 5xx 可重试，4xx 不重试（客户端错误）
                if 500 <= status_code < 600 and attempt < self.config.max_retries:
                    logger.warning(
                        "[%s] 第 %d/%d 次服务器错误 %d: %s",
                        self.config.adapter_id,
                        attempt,
                        self.config.max_retries,
                        status_code,
                        url,
                    )
                    time.sleep(min(2 ** attempt, self.config.timeout / 2))
                else:
                    return AdapterResponse(
                        content=json.dumps({
                            "error": f"HTTP {status_code}",
                            "detail": str(exc),
                        }),
                        finish_reason="error",
                        latency_ms=(time.time() - start_time) * 1000,
                        metadata={"status_code": status_code, "url": url},
                    )

            except requests.exceptions.ConnectionError as exc:  # type: ignore[union-attr]
                logger.warning(
                    "[%s] 第 %d/%d 次连接失败: %s",
                    self.config.adapter_id,
                    attempt,
                    self.config.max_retries,
                    exc,
                )
                if attempt == self.config.max_retries:
                    return AdapterResponse(
                        content=json.dumps({"error": f"连接失败: {exc}"}),
                        finish_reason="error",
                        latency_ms=(time.time() - start_time) * 1000,
                        metadata={"error": "connection_error", "url": url},
                    )
                time.sleep(min(2 ** attempt, self.config.timeout / 2))

            except Exception as exc:
                logger.exception("[%s] API 请求异常: %s", self.config.adapter_id, exc)
                return AdapterResponse(
                    content=json.dumps({"error": str(exc)}),
                    finish_reason="error",
                    latency_ms=(time.time() - start_time) * 1000,
                    metadata={"error": str(exc)},
                )

        # 逻辑不可达（安全兜底）
        return AdapterResponse(
            content=json.dumps({"error": "未知错误"}),
            finish_reason="error",
            latency_ms=(time.time() - start_time) * 1000,
        )

    # ------------------------------------------------------------------
    # _do_health_check
    # ------------------------------------------------------------------

    def _do_health_check(self) -> bool:
        """
        健康检查：验证 API 基础 URL 是否可达。

        策略：
          - 如果有 base_url，发送 HEAD 或 GET 请求验证
          - 如果没有 base_url，仅检查 Session 是否创建

        返回：
          True 表示健康
        """
        if self._session is None:
            logger.warning("[%s] 健康检查失败: HTTP 会话未创建", self.config.adapter_id)
            return False

        if self._base_url:
            try:
                resp = self._session.head(
                    self._base_url,
                    timeout=min(10, self.config.timeout),
                )
                # 2xx 或 3xx 都算可达
                if resp.status_code < 500:
                    logger.info(
                        "[%s] 健康检查通过 (base_url=%s, status=%d)",
                        self.config.adapter_id,
                        self._base_url,
                        resp.status_code,
                    )
                    return True
                logger.warning(
                    "[%s] 健康检查: 服务器返回 %d",
                    self.config.adapter_id,
                    resp.status_code,
                )
                return False
            except requests.exceptions.Timeout:  # type: ignore[union-attr]
                logger.warning(
                    "[%s] 健康检查超时: %s",
                    self.config.adapter_id,
                    self._base_url,
                )
                return False
            except Exception as exc:
                logger.warning(
                    "[%s] 健康检查失败: %s",
                    self.config.adapter_id,
                    exc,
                )
                return False

        # 没有 base_url 时，仅验证 Session 对象存在
        logger.info(
            "[%s] 健康检查通过 (无 base_url，仅会话检查)",
            self.config.adapter_id,
        )
        return True

    # ------------------------------------------------------------------
    # _do_shutdown
    # ------------------------------------------------------------------

    def _do_shutdown(self) -> None:
        """关闭 HTTP 会话，释放连接池。"""
        if self._session is not None:
            try:
                self._session.close()
                logger.info("[%s] HTTP 会话已关闭", self.config.adapter_id)
            except Exception as exc:
                logger.warning(
                    "[%s] 关闭 HTTP 会话时出错: %s",
                    self.config.adapter_id,
                    exc,
                )
            finally:
                self._session = None

        # 清空缓存
        with self._cache_lock:
            cache_count = len(self._cache)
            self._cache.clear()
            logger.info(
                "[%s] 清除了 %d 条缓存",
                self.config.adapter_id,
                cache_count,
            )

    # ------------------------------------------------------------------
    # 缓存辅助方法
    # ------------------------------------------------------------------

    def _build_cache_key(self, url: str, params: Dict[str, Any]) -> str:
        """构建缓存键。"""
        raw = f"{url}|{json.dumps(params, sort_keys=True)}"
        return raw

    def _get_from_cache(self, key: str) -> Optional[Any]:
        """从缓存读取（若 TTL 未过期）。"""
        cache_ttl = self.config.extra.get("cache_ttl", 0)
        if cache_ttl <= 0:
            return None
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            timestamp, value = entry
            if time.time() - timestamp > cache_ttl:
                del self._cache[key]
                return None
            return value

    def _put_to_cache(self, key: str, value: Any) -> None:
        """写入缓存。"""
        cache_ttl = self.config.extra.get("cache_ttl", 0)
        if cache_ttl <= 0:
            return
        with self._cache_lock:
            self._cache[key] = (time.time(), value)


# ============================================================================
# 5. DatabaseAdapter — SQL 数据库适配器
# ============================================================================

class DatabaseAdapter(BaseAdapter):
    """
    适配 SQL 数据库 — 统一的数据库访问层。

    特性：
      - 支持 SQLite / MySQL / PostgreSQL（通过连接字符串自动识别）
      - 参数化查询（防 SQL 注入）
      - 连接池管理（SQLite 单连接 + 线程锁；MySQL/PostgreSQL 建议上层连接池）
      - 查询结果自动转字典
      - 支持事务（自动提交 / 手动提交）

    配置项（通过 AdapterConfig.extra 传递）：
      connection_string : 数据库连接字符串
        格式示例：
          sqlite:///path/to/db.sqlite
          mysql+pymysql://user:pass@localhost:3306/dbname
          postgresql://user:pass@localhost:5432/dbname
      pool_size         : 连接池大小（默认 5，仅适用于 MySQL/PostgreSQL）
      auto_commit       : 是否自动提交事务（默认 True）
      query_timeout     : 单次查询超时（秒）

    类比：
      - Python SQLAlchemy 的 create_engine()
      - Go 的 database/sql 标准接口
      - JDBC 的 DataSource
      - Django ORM 的 connection 对象

    安全说明：
      本适配器严格执行参数化查询。execute() 中的 query_text 使用参数绑定，
      绝不直接拼接 SQL 字符串，以防止 SQL 注入攻击。
    """

    def __init__(self, config: Optional[AdapterConfig] = None):
        """初始化数据库适配器。"""
        super().__init__(config)
        # 数据库连接
        self._connection: Optional[Any] = None   # sqlite3.Connection 或 DB-API 2.0 connection
        self._connection_lock = threading.Lock()
        # 数据库类型
        self._db_type: str = "sqlite"
        # 配置
        self._auto_commit: bool = True

    # ------------------------------------------------------------------
    # _do_initialize
    # ------------------------------------------------------------------

    def _do_initialize(self) -> bool:
        """
        初始化数据库连接。

        步骤：
          1. 解析连接字符串，确定数据库类型
          2. 建立连接
          3. 设置连接参数（行工厂、超时等）
          4. 验证连接（发送 SELECT 1）

        返回：
          True 表示初始化成功
        """
        connection_string = self.config.extra.get("connection_string", "")
        self._auto_commit = self.config.extra.get("auto_commit", True)

        if not connection_string:
            logger.error(
                "[%s] 未提供数据库连接字符串。"
                "请在 AdapterConfig.extra['connection_string'] 中设置",
                self.config.adapter_id,
            )
            return False

        # 解析数据库类型
        self._db_type = self._parse_db_type(connection_string)

        try:
            if self._db_type == "sqlite":
                return self._init_sqlite(connection_string)
            elif self._db_type == "mysql":
                return self._init_mysql(connection_string)
            elif self._db_type == "postgresql":
                return self._init_postgresql(connection_string)
            else:
                logger.error(
                    "[%s] 不支持的数据库类型: %s",
                    self.config.adapter_id,
                    self._db_type,
                )
                return False
        except Exception as exc:
            logger.exception(
                "[%s] 数据库连接失败: %s",
                self.config.adapter_id,
                exc,
            )
            return False

    def _init_sqlite(self, connection_string: str) -> bool:
        """
        初始化 SQLite 连接。

        SQLite 使用内置 sqlite3 模块，无需额外依赖。
        格式: sqlite:///path/to/db.sqlite
        """
        # 提取路径: sqlite:///path → path
        path = connection_string
        for prefix in ("sqlite:///", "sqlite://"):
            if path.startswith(prefix):
                path = path[len(prefix):]
                break

        if not path or path == ":memory:":
            path = ":memory:"

        # 确保父目录存在
        if path != ":memory:":
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

        try:
            self._connection = sqlite3.connect(
                path,
                timeout=self.config.timeout,
                check_same_thread=False,  # 多线程访问需要
            )
            # 设置行工厂为 sqlite3.Row（支持列名访问）
            self._connection.row_factory = sqlite3.Row
            # 启用 WAL 模式（提升并发读性能）
            self._connection.execute("PRAGMA journal_mode=WAL")
            # 启用外键约束
            self._connection.execute("PRAGMA foreign_keys=ON")

            logger.info(
                "[%s] SQLite 连接已建立 (path=%s)",
                self.config.adapter_id,
                path,
            )
            return True
        except Exception as exc:
            logger.exception("[%s] SQLite 连接失败: %s", self.config.adapter_id, exc)
            return False

    def _init_mysql(self, connection_string: str) -> bool:
        """
        初始化 MySQL 连接。

        依赖: pip install pymysql（或 mysql-connector-python）
        """
        try:
            import pymysql  # type: ignore[import-untyped]
        except ImportError:
            logger.error(
                "[%s] pymysql 未安装。请执行: pip install pymysql",
                self.config.adapter_id,
            )
            return False

        try:
            # 使用 pymysql 直接连接（简化版，生产建议 SQLAlchemy）
            import pymysql
            # 从连接字符串提取参数: mysql+pymysql://user:pass@host:port/db
            parsed = self._parse_dsn(connection_string)
            self._connection = pymysql.connect(
                host=parsed.get("host", "localhost"),
                port=int(parsed.get("port", 3306)),
                user=parsed.get("user", ""),
                password=parsed.get("password", ""),
                database=parsed.get("database", ""),
                charset="utf8mb4",
                connect_timeout=int(self.config.timeout),
                autocommit=self._auto_commit,
            )
            logger.info(
                "[%s] MySQL 连接已建立 (host=%s, db=%s)",
                self.config.adapter_id,
                parsed.get("host"),
                parsed.get("database"),
            )
            return True
        except Exception as exc:
            logger.exception("[%s] MySQL 连接失败: %s", self.config.adapter_id, exc)
            return False

    def _init_postgresql(self, connection_string: str) -> bool:
        """
        初始化 PostgreSQL 连接。

        依赖: pip install psycopg2 或 psycopg2-binary
        """
        try:
            import psycopg2  # type: ignore[import-untyped]
            import psycopg2.extras
        except ImportError:
            logger.error(
                "[%s] psycopg2 未安装。请执行: pip install psycopg2-binary",
                self.config.adapter_id,
            )
            return False

        try:
            parsed = self._parse_dsn(connection_string)
            self._connection = psycopg2.connect(
                host=parsed.get("host", "localhost"),
                port=int(parsed.get("port", 5432)),
                user=parsed.get("user", ""),
                password=parsed.get("password", ""),
                dbname=parsed.get("database", ""),
                connect_timeout=int(self.config.timeout),
            )
            if self._auto_commit:
                self._connection.autocommit = True
            logger.info(
                "[%s] PostgreSQL 连接已建立 (host=%s, db=%s)",
                self.config.adapter_id,
                parsed.get("host"),
                parsed.get("database"),
            )
            return True
        except Exception as exc:
            logger.exception(
                "[%s] PostgreSQL 连接失败: %s",
                self.config.adapter_id,
                exc,
            )
            return False

    # ------------------------------------------------------------------
    # _do_execute
    # ------------------------------------------------------------------

    def _do_execute(self, messages: List[Dict[str, str]], **kwargs: Any) -> AdapterResponse:
        """
        执行 SQL 查询。

        参数（通过 kwargs）：
          query   : SQL 查询语句（必需）。使用 ? 或 %s 作为参数占位符。
          params  : 参数列表或字典（用于参数化查询，防注入）。
          fetch   : "all"（多条）| "one"（一条）| "none"（无返回，用于 INSERT/UPDATE/DELETE）

        安全：
          一律使用参数化查询（parametrized query）。绝不让用户输入直接拼入 SQL 字符串。
          占位符格式：
            SQLite:      ?
            MySQL:       %s
            PostgreSQL:  %s
        """
        sql = kwargs.get("query", "")
        params = kwargs.get("params", None)
        fetch_mode = kwargs.get("fetch", "all")

        # 如果未提供 SQL，尝试从最后一条 user 消息提取
        if not sql:
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    sql = msg.get("content", "")
                    break

        if not sql:
            return AdapterResponse(
                content=json.dumps({"error": "未提供 SQL 查询语句"}),
                finish_reason="error",
                metadata={"error": "missing_query"},
            )

        # 基本安全检查：拒绝已知危险操作（DROP, TRUNCATE, ALTER）
        dangerous_keywords = ["DROP ", "TRUNCATE ", "ALTER TABLE ", "DROP TABLE "]
        sql_upper = sql.upper().strip()
        for keyword in dangerous_keywords:
            if sql_upper.startswith(keyword):
                return AdapterResponse(
                    content=json.dumps({
                        "error": f"不允许的危险操作: {keyword.strip()}",
                        "message": "该适配器拒绝执行破坏性 DDL 语句。",
                    }),
                    finish_reason="error",
                    metadata={"error": "dangerous_operation", "keyword": keyword.strip()},
                )

        start_time = time.time()

        with self._connection_lock:
            try:
                if self._connection is None:
                    return AdapterResponse(
                        content=json.dumps({"error": "数据库连接未初始化"}),
                        finish_reason="error",
                    )

                cursor = self._connection.cursor()

                # === 执行参数化查询 ===
                if params is not None:
                    cursor.execute(sql, params)
                else:
                    cursor.execute(sql)

                # 根据 fetch_mode 获取结果
                if fetch_mode == "all":
                    rows = cursor.fetchall()
                elif fetch_mode == "one":
                    row = cursor.fetchone()
                    rows = [row] if row else []
                elif fetch_mode == "none":
                    if not self._auto_commit:
                        self._connection.commit()
                    rowcount = cursor.rowcount
                    cursor.close()
                    return AdapterResponse(
                        content=json.dumps({
                            "affected_rows": rowcount,
                            "message": f"操作完成，影响了 {rowcount} 行",
                        }),
                        finish_reason="stop",
                        latency_ms=(time.time() - start_time) * 1000,
                    )
                else:
                    cursor.close()
                    return AdapterResponse(
                        content=json.dumps({"error": f"未知的 fetch 模式: {fetch_mode}"}),
                        finish_reason="error",
                    )

                # 将结果转为字典列表
                if rows and hasattr(cursor, "description") and cursor.description:
                    columns = [desc[0] for desc in cursor.description]
                    result_list = [
                        dict(zip(columns, row)) for row in rows
                    ]
                else:
                    result_list = []

                cursor.close()

                elapsed = (time.time() - start_time) * 1000
                return AdapterResponse(
                    content=json.dumps({
                        "results": result_list,
                        "total_count": len(result_list),
                        "query": sql[:200],  # 截断长查询用于日志
                    }, ensure_ascii=False, default=str),
                    finish_reason="stop",
                    latency_ms=elapsed,
                    metadata={
                        "db_type": self._db_type,
                        "total_count": len(result_list),
                    },
                )

            except Exception as exc:
                logger.exception(
                    "[%s] 数据库查询失败: %s",
                    self.config.adapter_id,
                    exc,
                )
                return AdapterResponse(
                    content=json.dumps({"error": str(exc)}),
                    finish_reason="error",
                    latency_ms=(time.time() - start_time) * 1000,
                    metadata={"error": str(exc)},
                )

    # ------------------------------------------------------------------
    # _do_health_check
    # ------------------------------------------------------------------

    def _do_health_check(self) -> bool:
        """
        健康检查：发送轻量级查询验证数据库连通性。

        不同数据库的检查 SQL：
          - SQLite:     SELECT 1
          - MySQL:      SELECT 1
          - PostgreSQL: SELECT 1
        """
        if self._connection is None:
            logger.warning(
                "[%s] 健康检查失败: 数据库连接未建立",
                self.config.adapter_id,
            )
            return False

        with self._connection_lock:
            try:
                cursor = self._connection.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                cursor.close()
                logger.info(
                    "[%s] 数据库健康检查通过 (type=%s)",
                    self.config.adapter_id,
                    self._db_type,
                )
                return True
            except Exception as exc:
                logger.warning(
                    "[%s] 数据库健康检查失败: %s",
                    self.config.adapter_id,
                    exc,
                )
                # 尝试重连（对于断开的连接）
                try:
                    self._connection.close()
                except Exception:
                    pass
                self._connection = None
                return False

    # ------------------------------------------------------------------
    # _do_shutdown
    # ------------------------------------------------------------------

    def _do_shutdown(self) -> None:
        """关闭数据库连接。"""
        with self._connection_lock:
            if self._connection is not None:
                try:
                    self._connection.close()
                    logger.info(
                        "[%s] 数据库连接已关闭 (type=%s)",
                        self.config.adapter_id,
                        self._db_type,
                    )
                except Exception as exc:
                    logger.warning(
                        "[%s] 关闭数据库连接时出错: %s",
                        self.config.adapter_id,
                        exc,
                    )
                finally:
                    self._connection = None

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_db_type(connection_string: str) -> str:
        """
        解析连接字符串中的数据库类型。

        示例：
          sqlite:///db.sqlite → sqlite
          mysql+pymysql://... → mysql
          postgresql://... → postgresql
        """
        cs = connection_string.lower()
        if cs.startswith("sqlite"):
            return "sqlite"
        elif "mysql" in cs:
            return "mysql"
        elif "postgresql" in cs or "postgres" in cs:
            return "postgresql"
        return "unknown"

    @staticmethod
    def _parse_dsn(connection_string: str) -> Dict[str, str]:
        """
        解析数据库连接字符串为标准字典。

        格式: scheme://user:password@host:port/database

        返回：
          {"host": "...", "port": "...", "user": "...", "password": "...", "database": "..."}
        """
        result: Dict[str, str] = {}
        try:
            # 处理 "scheme://" 前缀
            if "://" in connection_string:
                # 分离 scheme: mysql+pymysql://user:pass@host:port/db
                parts = connection_string.split("://", 1)
                dsn_part = parts[1] if len(parts) > 1 else connection_string

                # 分离 user:pass@host:port/db
                if "@" in dsn_part:
                    auth, host_db = dsn_part.split("@", 1)
                    if ":" in auth:
                        result["user"], result["password"] = auth.split(":", 1)
                    else:
                        result["user"] = auth

                    # 分离 host:port/db
                    if "/" in host_db:
                        host_port, db = host_db.split("/", 1)
                        result["database"] = db
                    else:
                        host_port = host_db

                    if ":" in host_port:
                        result["host"], result["port"] = host_port.split(":", 1)
                    else:
                        result["host"] = host_port
        except Exception:
            pass
        return result


# ============================================================================
# 6. FileAdapter — 本地文件数据源适配器
# ============================================================================

class FileAdapter(BaseAdapter):
    """
    适配本地文件数据源 — 支持 CSV / JSON / JSONL / Parquet / TXT。

    特性：
      - 自动检测文件类型（基于扩展名和内容嗅探）
      - 支持目录遍历（递归扫描匹配模式的文件）
      - 支持字段筛选和行过滤
      - 支持大文件分块读取（chunked reading）

    配置项（通过 AdapterConfig.extra 传递）：
      file_path      : 文件或目录路径（必需）
      file_pattern   : 文件匹配模式（如 "*.csv" "*.json"，目录模式时使用）
      recursive      : 是否递归扫描子目录（默认 True）
      encoding       : 文件编码（默认 utf-8）
      chunk_size     : 分块读取大小（行数，默认 10000；0 表示不分块）

    类比：
      - Python 的 pandas.read_csv / read_json
      - Node.js 的 fs.createReadStream
      - LangChain 的 DirectoryLoader
      - Apache Spark 的 spark.read
    """

    # 已知文件扩展名 → 类型映射
    _EXT_TO_TYPE: Dict[str, str] = {
        ".csv": "csv",
        ".tsv": "tsv",
        ".json": "json",
        ".jsonl": "jsonl",
        ".parquet": "parquet",
        ".txt": "text",
        ".md": "text",
        ".log": "text",
        ".xml": "xml",
        ".yaml": "yaml",
        ".yml": "yaml",
    }

    def __init__(self, config: Optional[AdapterConfig] = None):
        """初始化文件适配器。"""
        super().__init__(config)
        self._file_path: str = ""
        self._file_pattern: str = "*"
        self._encoding: str = "utf-8"
        # 文件索引缓存（目录模式下缓存文件列表）
        self._file_index: List[str] = []

    # ------------------------------------------------------------------
    # _do_initialize
    # ------------------------------------------------------------------

    def _do_initialize(self) -> bool:
        """
        初始化文件适配器。

        步骤：
          1. 验证文件路径存在
          2. 自动检测文件类型
          3. 如果是目录，构建文件索引
          4. 预读文件头（验证可用性）

        返回：
          True 表示初始化成功
        """
        self._file_path = self.config.extra.get("file_path", "")
        self._file_pattern = self.config.extra.get("file_pattern", "*")
        self._encoding = self.config.extra.get("encoding", "utf-8")

        if not self._file_path:
            logger.error(
                "[%s] 未提供文件路径。请在 AdapterConfig.extra['file_path'] 中设置",
                self.config.adapter_id,
            )
            return False

        if not os.path.exists(self._file_path):
            logger.error(
                "[%s] 文件路径不存在: %s",
                self.config.adapter_id,
                self._file_path,
            )
            return False

        # 目录模式：构建文件索引
        if os.path.isdir(self._file_path):
            recursive = self.config.extra.get("recursive", True)
            self._file_index = self._scan_directory(
                self._file_path,
                self._file_pattern,
                recursive,
            )
            logger.info(
                "[%s] 目录扫描完成 (path=%s, 匹配文件: %d)",
                self.config.adapter_id,
                self._file_path,
                len(self._file_index),
            )
            if len(self._file_index) == 0:
                logger.warning(
                    "[%s] 未找到匹配的文件 (pattern=%s)",
                    self.config.adapter_id,
                    self._file_pattern,
                )
        else:
            # 单文件模式
            self._file_index = [self._file_path]

        logger.info(
            "[%s] 文件适配器已初始化 (path=%s, files=%d)",
            self.config.adapter_id,
            self._file_path,
            len(self._file_index),
        )
        return True

    # ------------------------------------------------------------------
    # _do_execute
    # ------------------------------------------------------------------

    def _do_execute(self, messages: List[Dict[str, str]], **kwargs: Any) -> AdapterResponse:
        """
        读取文件内容并返回。

        参数（通过 kwargs）：
          query_text : 可选的搜索关键词（用于文本过滤）
          filters    : 字段过滤条件（如 {"category": "finance"}）
          fields     : 要返回的字段列表（为空则返回全部）
          limit      : 返回的最大行数（默认 1000）
          offset     : 偏移量（默认 0）

        从 messages 中提取搜索关键词（最后一条 user 消息）。
        """
        # 提取搜索关键词
        search_text = kwargs.get("query_text", "")
        if not search_text:
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    search_text = msg.get("content", "")
                    break

        filters = kwargs.get("filters", {})
        fields = kwargs.get("fields", [])
        limit = kwargs.get("limit", 1000)
        offset = kwargs.get("offset", 0)

        start_time = time.time()
        all_rows: List[Dict[str, Any]] = []

        try:
            # 确定要读取的文件列表
            specific_file = kwargs.get("file_path", "")
            if specific_file:
                target_files = [specific_file]
            else:
                target_files = self._file_index

            for file_path in target_files:
                if not os.path.isfile(file_path):
                    continue

                file_type = self._detect_file_type(file_path)
                rows = self._read_file(file_path, file_type, search_text, filters, fields)

                # 如果指定了 limit，累计达到限制则停止
                remaining = limit - len(all_rows) if limit > 0 else None
                if remaining is not None and remaining <= 0:
                    break
                if remaining is not None:
                    all_rows.extend(rows[:remaining])
                else:
                    all_rows.extend(rows)

            # 应用 offset
            if offset > 0:
                all_rows = all_rows[offset:]

            elapsed = (time.time() - start_time) * 1000
            return AdapterResponse(
                content=json.dumps({
                    "results": all_rows,
                    "total_count": len(all_rows),
                    "source_files": len(target_files),
                }, ensure_ascii=False, default=str),
                finish_reason="stop",
                latency_ms=elapsed,
                metadata={
                    "total_count": len(all_rows),
                    "files_read": len(target_files),
                    "file_path": self._file_path,
                },
            )
        except Exception as exc:
            logger.exception("[%s] 文件读取失败: %s", self.config.adapter_id, exc)
            return AdapterResponse(
                content=json.dumps({"error": str(exc), "results": []}),
                finish_reason="error",
                latency_ms=(time.time() - start_time) * 1000,
                metadata={"error": str(exc)},
            )

    # ------------------------------------------------------------------
    # _do_health_check
    # ------------------------------------------------------------------

    def _do_health_check(self) -> bool:
        """
        健康检查：验证文件路径是否仍然可访问。

        检查项：
          - 文件/目录是否存在
          - 文件是否可读
          - 索引是否仍有效（文件数量未减少）
        """
        if not self._file_path:
            logger.warning("[%s] 健康检查失败: 未设置文件路径", self.config.adapter_id)
            return False

        if not os.path.exists(self._file_path):
            logger.warning(
                "[%s] 健康检查失败: 路径不存在 (%s)",
                self.config.adapter_id,
                self._file_path,
            )
            return False

        # 检查是否可读
        if not os.access(self._file_path, os.R_OK):
            logger.warning(
                "[%s] 健康检查失败: 路径不可读 (%s)",
                self.config.adapter_id,
                self._file_path,
            )
            return False

        logger.info(
            "[%s] 文件适配器健康检查通过 (path=%s, files=%d)",
            self.config.adapter_id,
            self._file_path,
            len(self._file_index),
        )
        return True

    # ------------------------------------------------------------------
    # _do_shutdown
    # ------------------------------------------------------------------

    def _do_shutdown(self) -> None:
        """关闭文件适配器 — 清理索引缓存。"""
        count = len(self._file_index)
        self._file_index.clear()
        logger.info(
            "[%s] 文件适配器已关闭 (清除了 %d 条文件索引)",
            self.config.adapter_id,
            count,
        )

    # ------------------------------------------------------------------
    # 核心：文件读取
    # ------------------------------------------------------------------

    def _read_file(
        self,
        file_path: str,
        file_type: str,
        search_text: str,
        filters: Dict[str, Any],
        fields: List[str],
    ) -> List[Dict[str, Any]]:
        """
        读取单个文件并返回行列表。

        参数：
          file_path   : 文件路径
          file_type   : 文件类型（csv/json/jsonl/parquet/text）
          search_text : 搜索关键词（文本过滤）
          filters     : 字段过滤条件
          fields      : 要返回的字段列表

        返回：
          行字典列表
        """
        if file_type == "csv":
            return self._read_csv(file_path, search_text, filters, fields)
        elif file_type == "tsv":
            return self._read_csv(file_path, search_text, filters, fields, delimiter="\t")
        elif file_type == "json":
            return self._read_json(file_path, search_text, filters, fields)
        elif file_type == "jsonl":
            return self._read_jsonl(file_path, search_text, filters, fields)
        elif file_type == "parquet":
            return self._read_parquet(file_path, search_text, filters, fields)
        elif file_type in ("text", "yaml", "xml", "md", "log"):
            return self._read_text(file_path, search_text)
        else:
            logger.warning(
                "[%s] 不支持的文件类型: %s (%s)",
                self.config.adapter_id,
                file_type,
                file_path,
            )
            return []

    def _read_csv(
        self,
        file_path: str,
        search_text: str,
        filters: Dict[str, Any],
        fields: List[str],
        delimiter: str = ",",
    ) -> List[Dict[str, Any]]:
        """
        读取 CSV/TSV 文件。

        参数：
          delimiter : 分隔符（逗号或制表符）
        """
        rows: List[Dict[str, Any]] = []
        chunk_size = self.config.extra.get("chunk_size", 10000)

        try:
            with open(file_path, "r", encoding=self._encoding, errors="replace") as f:
                if chunk_size <= 0:
                    # 全量读取
                    reader = csv.DictReader(f, delimiter=delimiter)
                    for row in reader:
                        if self._match_row(row, search_text, filters, fields):
                            rows.append(self._project_fields(row, fields))
                else:
                    # 分块读取
                    reader = csv.DictReader(f, delimiter=delimiter)
                    chunk: List[Dict[str, Any]] = []
                    for row in reader:
                        chunk.append(row)
                        if len(chunk) >= chunk_size:
                            for r in chunk:
                                if self._match_row(r, search_text, filters, fields):
                                    rows.append(self._project_fields(r, fields))
                            chunk.clear()
                    # 处理剩余行
                    for r in chunk:
                        if self._match_row(r, search_text, filters, fields):
                            rows.append(self._project_fields(r, fields))
        except Exception as exc:
            logger.warning(
                "[%s] 读取 CSV 失败 (%s): %s",
                self.config.adapter_id,
                file_path,
                exc,
            )

        return rows

    def _read_json(
        self,
        file_path: str,
        search_text: str,
        filters: Dict[str, Any],
        fields: List[str],
    ) -> List[Dict[str, Any]]:
        """读取 JSON 文件。支持顶层数组和顶层对象。"""
        try:
            with open(file_path, "r", encoding=self._encoding, errors="replace") as f:
                data = json.load(f)

            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                # 尝试查找包含数组的 key
                for key in ("data", "results", "items", "records", "rows"):
                    if key in data and isinstance(data[key], list):
                        items = data[key]
                        break
                else:
                    # 整个对象当作单行
                    items = [data]
            else:
                items = []

            rows: List[Dict[str, Any]] = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                if self._match_row(item, search_text, filters, fields):
                    rows.append(self._project_fields(item, fields))
            return rows
        except Exception as exc:
            logger.warning(
                "[%s] 读取 JSON 失败 (%s): %s",
                self.config.adapter_id,
                file_path,
                exc,
            )
            return []

    def _read_jsonl(
        self,
        file_path: str,
        search_text: str,
        filters: Dict[str, Any],
        fields: List[str],
    ) -> List[Dict[str, Any]]:
        """读取 JSONL（每行一个 JSON）文件。"""
        rows: List[Dict[str, Any]] = []
        try:
            with open(file_path, "r", encoding=self._encoding, errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            if self._match_row(obj, search_text, filters, fields):
                                rows.append(self._project_fields(obj, fields))
                    except json.JSONDecodeError:
                        logger.debug(
                            "[%s] JSONL 第 %d 行解析失败: %s",
                            self.config.adapter_id,
                            line_num,
                            file_path,
                        )
        except Exception as exc:
            logger.warning(
                "[%s] 读取 JSONL 失败 (%s): %s",
                self.config.adapter_id,
                file_path,
                exc,
            )
        return rows

    def _read_parquet(
        self,
        file_path: str,
        search_text: str,
        filters: Dict[str, Any],
        fields: List[str],
    ) -> List[Dict[str, Any]]:
        """
        读取 Parquet 文件。

        依赖: pip install pyarrow 或 pandas
        """
        try:
            import pandas as pd  # type: ignore[import-untyped]
        except ImportError:
            logger.warning(
                "[%s] pandas 未安装，无法读取 Parquet: %s",
                self.config.adapter_id,
                file_path,
            )
            return []

        try:
            df = pd.read_parquet(file_path)

            # 字段筛选
            if fields:
                existing = [f for f in fields if f in df.columns]
                if existing:
                    df = df[existing]

            rows = df.to_dict(orient="records")

            # 搜索和过滤
            filtered: List[Dict[str, Any]] = []
            for row in rows:
                if self._match_row(row, search_text, filters, fields):
                    filtered.append(row)
            return filtered
        except Exception as exc:
            logger.warning(
                "[%s] 读取 Parquet 失败 (%s): %s",
                self.config.adapter_id,
                file_path,
                exc,
            )
            return []

    def _read_text(
        self,
        file_path: str,
        search_text: str,
    ) -> List[Dict[str, Any]]:
        """读取纯文本文件。"""
        try:
            with open(file_path, "r", encoding=self._encoding, errors="replace") as f:
                content = f.read()

            # 如果指定了搜索文本，按行返回匹配的行
            if search_text:
                lines = content.split("\n")
                matched = [
                    {"line_number": i + 1, "content": line}
                    for i, line in enumerate(lines)
                    if search_text.lower() in line.lower()
                ]
                return matched
            else:
                # 返回整个文件内容
                return [{"file": os.path.basename(file_path), "content": content}]
        except Exception as exc:
            logger.warning(
                "[%s] 读取文本文件失败 (%s): %s",
                self.config.adapter_id,
                file_path,
                exc,
            )
            return []

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_file_type(file_path: str) -> str:
        """
        自动检测文件类型。

        优先级：
          1. 扩展名匹配（最快）
          2. 内容嗅探（magic bytes）
        """
        ext = os.path.splitext(file_path)[1].lower()
        if ext in FileAdapter._EXT_TO_TYPE:
            return FileAdapter._EXT_TO_TYPE[ext]

        # 内容嗅探：尝试读取开头
        try:
            with open(file_path, "rb") as f:
                head = f.read(4)
                if head == b"PAR1":
                    return "parquet"
                if head.startswith(b"{"):
                    return "json"
                if head.startswith(b"PK"):
                    return "zip"  # 可能是 Office 文件或 zip 包
        except Exception:
            pass

        return "text"

    @staticmethod
    def _match_row(
        row: Dict[str, Any],
        search_text: str,
        filters: Dict[str, Any],
        fields: List[str],
    ) -> bool:
        """
        检查一行数据是否匹配搜索条件和过滤条件。

        参数：
          row         : 数据行字典
          search_text : 搜索关键词（在任意字段值中搜索）
          filters     : 精确过滤条件（{字段名: 值}）
          fields      : 要返回的字段（仅用于优化，不影响匹配）

        返回：
          True 表示该行匹配
        """
        # 精确过滤
        if filters:
            for key, value in filters.items():
                row_val = row.get(key)
                if row_val != value:
                    return False

        # 全文搜索
        if search_text:
            search_lower = search_text.lower()
            found = False
            for val in row.values():
                if val is not None and search_lower in str(val).lower():
                    found = True
                    break
            if not found:
                return False

        return True

    @staticmethod
    def _project_fields(
        row: Dict[str, Any],
        fields: List[str],
    ) -> Dict[str, Any]:
        """
        字段投影：只返回指定的字段。

        参数：
          row    : 原始行字典
          fields : 要保留的字段列表（空列表表示全部保留）

        返回：
          筛选后的字典
        """
        if not fields:
            return dict(row)
        return {k: row[k] for k in fields if k in row}

    @staticmethod
    def _scan_directory(
        directory: str,
        pattern: str,
        recursive: bool,
    ) -> List[str]:
        """
        扫描目录，返回匹配文件的路径列表。

        参数：
          directory : 目录路径
          pattern   : 通配符模式（如 "*.csv" "data_*.json"）
          recursive : 是否递归子目录

        返回：
          文件路径列表
        """
        import fnmatch
        files: List[str] = []

        if recursive:
            for root, dirs, filenames in os.walk(directory):
                # 跳过隐藏目录
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in filenames:
                    if fnmatch.fnmatch(fname, pattern):
                        files.append(os.path.join(root, fname))
        else:
            for entry in os.listdir(directory):
                full = os.path.join(directory, entry)
                if os.path.isfile(full) and fnmatch.fnmatch(entry, pattern):
                    files.append(full)

        return sorted(files)


# ============================================================================
# 7. 数据源适配器工厂
# ============================================================================

def create_source_adapter(
    source_type: str,
    config: Optional[AdapterConfig] = None,
) -> BaseAdapter:
    """
    数据源适配器工厂 — 根据类型字符串创建对应的适配器实例。

    参数：
      source_type : 数据源类型标识
                    "vector_db" | "api" | "database" | "file"
      config      : 适配器配置（可选）

    返回：
      对应的 BaseAdapter 子类实例

    引发：
      ValueError — 当 source_type 无效时

    使用示例：
      >>> adapter = create_source_adapter("file", AdapterConfig(
      ...     extra={"file_path": "./data/sample.csv"}
      ... ))
      >>> adapter.initialize()
      >>> resp = adapter.execute([{"role": "user", "content": "查找财务数据"}])
      >>> print(resp.content)
    """
    registry: Dict[str, type] = {
        "vector_db": VectorDBAdapter,
        "api": APIAdapter,
        "database": DatabaseAdapter,
        "file": FileAdapter,
    }

    adapter_cls = registry.get(source_type.lower())
    if adapter_cls is None:
        raise ValueError(
            f"未知的数据源类型: '{source_type}'。"
            f"支持的类型: {list(registry.keys())}"
        )

    logger.info("创建数据源适配器: type=%s", source_type)
    return adapter_cls(config)
