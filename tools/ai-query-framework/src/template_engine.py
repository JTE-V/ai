"""
模板引擎 — Template Engine
==========================
将 AI 查询工作流定义为一个可复用的 YAML/JSON 模板。
模板描述了：输入什么 → 查哪些源 → 输出什么格式 → 算法怎么跑。

类比：
  - Terraform / CloudFormation  — 声明式定义基础设施
  - Docker Compose              — 声明式定义服务编排
  - GitHub Actions Workflow     — YAML 定义 CI/CD 流程
  - SQL VIEW                    — 预定义的查询逻辑

JS 类比：
  - React 的 declarative UI: <Component prop={value} /> ≈ template 定义
  - Next.js 的 route.ts 中的配置对象

模板规范（Template Spec v1.0）：
  1. name           — 模板名称（唯一标识）
  2. version        — 语义化版本
  3. description    — 模板用途说明
  4. inputs         — 输入字段定义（类型、必填、默认值）
  5. query_sources  — 查询源列表（vector_db / api / web / database）
  6. output_schema  — 输出格式定义
  7. algorithm_room — 算法房间配置（如何处理查询结果）
"""

import json
import re
from typing import Any, Callable, Dict, List, Optional, Set, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


# ============================================================================
# 1. 枚举定义
# ============================================================================

class QuerySourceType(Enum):
    """查询源类型 — 类比数据源的 protocol/driver"""
    VECTOR_DB = "vector_db"      # 向量数据库（Milvus / Pinecone / Chroma）
    API = "api"                  # REST / GraphQL API
    WEB = "web"                  # 网页抓取
    DATABASE = "database"        # 传统 SQL 数据库
    FILE = "file"                # 本地文件


class InputType(Enum):
    """输入字段类型"""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    DATE = "date"
    ENUM = "enum"          # 枚举，需提供 options
    LIST = "list"          # 列表
    DICT = "dict"          # 字典


class AlgorithmType(Enum):
    """算法房间中的算法类型"""
    MERGE = "merge"              # 多源结果合并（类似 SQL JOIN / UNION）
    RANK = "rank"                # 结果排序/重排序
    FILTER = "filter"            # 后置过滤
    TRANSFORM = "transform"      # 格式转换
    AGGREGATE = "aggregate"      # 聚合（计数、求和、平均）
    LLM_SUMMARIZE = "llm_summarize"  # LLM 总结


# ============================================================================
# 2. 输入字段定义
# ============================================================================

@dataclass
class InputField:
    """
    模板的单个输入字段。

    类比：
      - GraphQL schema 中的 input type field
      - OpenAPI / Swagger 的 parameter 定义
      - TypeScript interface 的一个属性

    JS 类比：
      interface InputField {
        name: string;
        type: InputType;
        required: boolean;
        default?: any;
        options?: string[];       // for enum
        description?: string;
        validators?: ((v: any) => boolean)[];
      }
    """
    name: str
    type: InputType = InputType.STRING
    required: bool = False
    default: Any = None
    options: Optional[List[str]] = None      # enum 类型的可选值
    description: str = ""
    validators: List[Callable[[Any], bool]] = field(default_factory=list)
    examples: List[Any] = field(default_factory=list)  # 示例值，帮助 AI 理解

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        d = {
            "name": self.name,
            "type": self.type.value,
            "required": self.required,
            "description": self.description,
        }
        if self.default is not None:
            d["default"] = self.default
        if self.options:
            d["options"] = self.options
        if self.examples:
            d["examples"] = self.examples
        return d


# ============================================================================
# 3. 查询源定义
# ============================================================================

@dataclass
class QuerySource:
    """
    查询源 — 描述从哪个数据源获取数据。

    类比：
      - FROM 子句：SELECT ... FROM vector_db.semantic_search(...)
      - Terraform 的 provider 块

    字段：
      name        : str             — 源名称（在模板内唯一）
      type        : QuerySourceType — 源类型
      endpoint    : str             — 连接地址 / URL
      method      : str             — HTTP method（API 类型时使用）
      params      : dict            — 查询参数模板（支持 {{input.xxx}} 占位符）
      headers     : dict            — 请求头模板
      timeout_ms  : int             — 超时毫秒
      retry       : int             — 重试次数
    """
    name: str
    type: QuerySourceType
    endpoint: str = ""
    method: str = "GET"
    params: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_ms: int = 10000
    retry: int = 1
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type.value,
            "endpoint": self.endpoint,
            "method": self.method,
            "params": self.params,
            "headers": self.headers,
            "timeout_ms": self.timeout_ms,
            "retry": self.retry,
            "description": self.description,
        }


# ============================================================================
# 4. 输出 Schema 定义
# ============================================================================

@dataclass
class OutputField:
    """
    输出字段定义 — 类比 SQL SELECT 的列。

    JS 类比：
      interface OutputField {
        name: string;
        type: 'string' | 'number' | 'boolean' | 'array' | 'object';
        source: string;           // 来自哪个查询源的哪个字段，如 "source1.title"
        description?: string;
      }
    """
    name: str                      # 输出字段名
    type: str = "string"           # 输出类型: string / number / boolean / array / object
    source: str = ""               # 映射来源："{source_name}.{field_path}"
    description: str = ""
    fallback: Any = None           # 源缺失时的回退值

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "name": self.name,
            "type": self.type,
            "source": self.source,
            "description": self.description,
        }
        if self.fallback is not None:
            d["fallback"] = self.fallback
        return d


# ============================================================================
# 5. 算法房间配置
# ============================================================================

@dataclass
class AlgorithmStep:
    """
    算法房间中的一个处理步骤。

    类比：
      - Airflow DAG 的一个 task
      - LangChain 的 chain step
      - RxJS 的一个 operator（pipe 中的一环）

    JS 类比：
      { type: 'filter', config: { field: 'score', operator: '>=', value: 0.8 } }
    """
    type: AlgorithmType
    config: Dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "config": self.config,
            "description": self.description,
        }


@dataclass
class AlgorithmRoom:
    """
    算法房间 — 多步骤处理流水线。

    流程：
      query_sources → [原始结果] → step1 → step2 → ... → 最终输出

    类比：
      - Unix pipe: cat data | grep ... | sort | uniq
      - scikit-learn Pipeline
    """
    steps: List[AlgorithmStep] = field(default_factory=list)
    merge_strategy: str = "concat"    # concat / zip / join_by_key
    merge_key: Optional[str] = None   # join_by_key 时的键名

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "steps": [s.to_dict() for s in self.steps],
            "merge_strategy": self.merge_strategy,
        }
        if self.merge_key:
            d["merge_key"] = self.merge_key
        return d


# ============================================================================
# 6. AITemplate — 模板主体
# ============================================================================

@dataclass
class AITemplate:
    """
    AI 查询模板。

    一个模板完整描述了一次 AI 增强查询的全部要素。

    类比：
      - SQL VIEW: CREATE VIEW my_view AS SELECT ...
      - OpenAPI Operation Object
      - GraphQL persisted query
      - Docker Compose 的 service 定义

    JS 类比：
      const template: AITemplate = {
        name: 'product_search',
        version: '1.0.0',
        inputs: [...],
        querySources: [...],
        outputSchema: { fields: [...] },
        algorithmRoom: { steps: [...] },
      };
    """
    name: str
    version: str = "1.0.0"
    description: str = ""
    inputs: List[InputField] = field(default_factory=list)
    query_sources: List[QuerySource] = field(default_factory=list)
    output_schema: List[OutputField] = field(default_factory=list)
    algorithm_room: AlgorithmRoom = field(default_factory=AlgorithmRoom)
    metadata: Dict[str, Any] = field(default_factory=dict)  # 自定义扩展元数据

    # ---- 序列化 ----

    def to_dict(self) -> Dict[str, Any]:
        """模板 → Python dict"""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "inputs": [inp.to_dict() for inp in self.inputs],
            "query_sources": [qs.to_dict() for qs in self.query_sources],
            "output_schema": {
                "fields": [of.to_dict() for of in self.output_schema],
            },
            "algorithm_room": self.algorithm_room.to_dict(),
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """模板 → JSON 字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def to_yaml(self) -> str:
        """
        模板 → YAML 字符串。

        注意：需要 PyYAML 库。如果没有安装则回退到 JSON。
        """
        try:
            import yaml  # type: ignore
            return yaml.dump(
                self.to_dict(),
                allow_unicode=True,
                default_flow_style=False,
                sort_keys=False,
            )
        except ImportError:
            # 没有 PyYAML → 回退到 JSON 并给出提示
            return (
                "# 警告: PyYAML 未安装，输出 JSON 格式。请执行 pip install pyyaml\n"
                + self.to_json()
            )

    # ---- 从文件/字符串加载 ----

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AITemplate":
        """从 Python dict 构建模板"""
        # 解析 inputs
        inputs = []
        for inp in data.get("inputs", []):
            inputs.append(InputField(
                name=inp["name"],
                type=InputType(inp.get("type", "string")),
                required=inp.get("required", False),
                default=inp.get("default"),
                options=inp.get("options"),
                description=inp.get("description", ""),
                examples=inp.get("examples", []),
            ))

        # 解析 query_sources
        query_sources = []
        for qs in data.get("query_sources", []):
            query_sources.append(QuerySource(
                name=qs["name"],
                type=QuerySourceType(qs.get("type", "api")),
                endpoint=qs.get("endpoint", ""),
                method=qs.get("method", "GET"),
                params=qs.get("params", {}),
                headers=qs.get("headers", {}),
                timeout_ms=qs.get("timeout_ms", 10000),
                retry=qs.get("retry", 1),
                description=qs.get("description", ""),
            ))

        # 解析 output_schema
        output_fields = []
        os_data = data.get("output_schema", {})
        for of in os_data.get("fields", []):
            output_fields.append(OutputField(
                name=of["name"],
                type=of.get("type", "string"),
                source=of.get("source", ""),
                description=of.get("description", ""),
                fallback=of.get("fallback"),
            ))

        # 解析 algorithm_room
        algo_data = data.get("algorithm_room", {})
        algo_steps = []
        for step in algo_data.get("steps", []):
            algo_steps.append(AlgorithmStep(
                type=AlgorithmType(step["type"]),
                config=step.get("config", {}),
                description=step.get("description", ""),
            ))
        algorithm_room = AlgorithmRoom(
            steps=algo_steps,
            merge_strategy=algo_data.get("merge_strategy", "concat"),
            merge_key=algo_data.get("merge_key"),
        )

        return cls(
            name=data["name"],
            version=data.get("version", "1.0.0"),
            description=data.get("description", ""),
            inputs=inputs,
            query_sources=query_sources,
            output_schema=output_fields,
            algorithm_room=algorithm_room,
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "AITemplate":
        """从 JSON 字符串加载模板"""
        data = json.loads(json_str)
        return cls.from_dict(data)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "AITemplate":
        """从 YAML 字符串加载模板"""
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(yaml_str)
            return cls.from_dict(data)
        except ImportError:
            raise ImportError(
                "from_yaml 需要 PyYAML。请执行: pip install pyyaml"
            )

    @classmethod
    def from_file(cls, filepath: str) -> "AITemplate":
        """
        从文件加载模板（自动检测 JSON/YAML）。

        参数：
          filepath : str — 文件路径（.json / .yaml / .yml）

        返回：
          AITemplate
        """
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        if filepath.endswith((".yaml", ".yml")):
            return cls.from_yaml(content)
        elif filepath.endswith(".json"):
            return cls.from_json(content)
        else:
            # 尝试 JSON 优先
            try:
                return cls.from_json(content)
            except json.JSONDecodeError:
                return cls.from_yaml(content)

    # ---- 模板变量渲染 ----

    def render_params(self, source: QuerySource, input_values: Dict[str, Any]) -> Dict[str, Any]:
        """
        将查询源中的 {{input.xxx}} 占位符替换为实际值。

        类比：
          - Jinja2 / Mustache 模板渲染
          - JavaScript 模板字面量: `Hello ${name}`

        示例：
          params = {"query": "{{input.keyword}}", "limit": 10}
          input_values = {"keyword": "iPhone"}
          → {"query": "iPhone", "limit": 10}
        """
        rendered: Dict[str, Any] = {}
        # 将 params 先序列化再整体替换，再反序列化（处理嵌套结构）
        raw = json.dumps(source.params)
        for key, value in input_values.items():
            raw = raw.replace(f"{{{{input.{key}}}}}", str(value))
        try:
            rendered = json.loads(raw)
        except json.JSONDecodeError:
            # 如果替换后不是合法 JSON（如字符串中含引号），回退到逐键替换
            for k, v in source.params.items():
                if isinstance(v, str):
                    rendered[k] = v
                    for ik, iv in input_values.items():
                        rendered[k] = rendered[k].replace(f"{{{{input.{ik}}}}}", str(iv))
                else:
                    rendered[k] = v
        return rendered


# ============================================================================
# 7. TemplateValidator — 模板验证器
# ============================================================================

class TemplateValidationError(Exception):
    """模板验证异常"""
    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__(f"模板验证失败: {len(errors)} 个错误")

    def __str__(self):
        return "\n".join([f"  - {e}" for e in self.errors])


class TemplateValidator:
    """
    模板验证器 — 确保模板定义合法。

    类比：
      - JSON Schema validator
      - TypeScript 编译器（tsc --noEmit）
      - Terraform validate
      - SQL linter

    检查项：
      1. name 非空且符合命名规范（字母数字下划线连字符）
      2. version 符合 semver 格式
      3. 至少一个 query_source
      4. 至少一个 output_field
      5. query_source.name 唯一
      6. output_field.source 引用的源名必须存在
      7. algorithm_room 步骤 type/config 一致性
      8. inputs 的 enum 类型必须有 options
      9. params 占位符引用的 input name 必须存在
    """

    # 语义化版本正则：major.minor.patch（可选 pre-release）
    SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$")

    # 模板名正则：字母开头，字母数字下划线连字符
    NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*$")

    def validate(self, template: AITemplate) -> List[str]:
        """
        全面校验模板，返回错误列表。空列表表示通过。

        参数：
          template : AITemplate

        返回：
          List[str] — 错误消息列表
        """
        errors: List[str] = []

        # ---- 1. name ----
        if not template.name or not template.name.strip():
            errors.append("模板名称不能为空")
        elif not self.NAME_RE.match(template.name):
            errors.append(
                f"模板名称 '{template.name}' 不符合规范（字母开头，允许字母数字下划线连字符）"
            )

        # ---- 2. version ----
        if not self.SEMVER_RE.match(template.version):
            errors.append(
                f"版本号 '{template.version}' 不符合语义化版本规范 (如 1.0.0)"
            )

        # ---- 3. 至少一个 query_source ----
        if not template.query_sources:
            errors.append("至少需要一个 query_source")

        # ---- 4. 至少一个 output_field ----
        if not template.output_schema:
            errors.append("至少需要一个 output_schema 字段")

        # ---- 5. query_source 名称唯一 ----
        source_names = [qs.name for qs in template.query_sources]
        duplicates = {n for n in source_names if source_names.count(n) > 1}
        for dup in duplicates:
            errors.append(f"query_source 名称 '{dup}' 重复，名称必须唯一")

        # ---- 6. output_field.source 引用的源必须存在 ----
        for of in template.output_schema:
            if of.source:
                # source 格式: "{source_name}.{field_path}" 或 "{source_name}"
                src_name = of.source.split(".")[0]
                if src_name not in source_names:
                    errors.append(
                        f"output_field '{of.name}' 引用的源 '{src_name}' 不存在。"
                        f"可用源: {source_names}"
                    )

        # ---- 7. algorithm_room 步骤验证 ----
        algo = template.algorithm_room
        for i, step in enumerate(algo.steps):
            err = self._validate_algorithm_step(step, i)
            if err:
                errors.append(err)

        # ---- 8. inputs 的 enum 类型必须有 options ----
        input_names = {inp.name for inp in template.inputs}
        for inp in template.inputs:
            if inp.type == InputType.ENUM and not inp.options:
                errors.append(
                    f"输入字段 '{inp.name}' 类型为 enum，必须提供 options"
                )

        # ---- 9. params 占位符引用的 input name 必须存在 ----
        for qs in template.query_sources:
            raw_params = json.dumps(qs.params)
            placeholder_pattern = re.compile(r"\{\{input\.(\w+)\}\}")
            for match in placeholder_pattern.finditer(raw_params):
                ref_name = match.group(1)
                if ref_name not in input_names:
                    errors.append(
                        f"query_source '{qs.name}' 的 params 引用了未定义的输入 "
                        f"'{ref_name}'。已定义输入: {list(input_names)}"
                    )

        return errors

    def validate_or_raise(self, template: AITemplate) -> None:
        """校验模板，失败时抛出 TemplateValidationError"""
        errors = self.validate(template)
        if errors:
            raise TemplateValidationError(errors)

    def _validate_algorithm_step(self, step: AlgorithmStep, index: int) -> Optional[str]:
        """
        验证单个算法步骤的 type/config 一致性。

        返回：错误消息或 None。
        """
        at = step.type
        cfg = step.config

        if at == AlgorithmType.FILTER:
            # FILTER 必须有 field、operator、value
            if "field" not in cfg:
                return f"algorithm_room step[{index}] FILTER 缺少 'field' 配置"
            if "operator" not in cfg:
                return f"algorithm_room step[{index}] FILTER 缺少 'operator' 配置"

        elif at == AlgorithmType.RANK:
            # RANK 必须有 sort_by
            if "sort_by" not in cfg:
                return f"algorithm_room step[{index}] RANK 缺少 'sort_by' 配置"

        elif at == AlgorithmType.AGGREGATE:
            # AGGREGATE 必须有 function
            if "function" not in cfg:
                return f"algorithm_room step[{index}] AGGREGATE 缺少 'function' 配置"

        elif at == AlgorithmType.LLM_SUMMARIZE:
            # LLM_SUMMARIZE 必须有 prompt_template
            if "prompt_template" not in cfg:
                return f"algorithm_room step[{index}] LLM_SUMMARIZE 缺少 'prompt_template' 配置"

        elif at == AlgorithmType.MERGE:
            # MERGE 必须有 sources
            if "sources" not in cfg:
                return f"algorithm_room step[{index}] MERGE 缺少 'sources' 配置"

        return None  # 通过


# ============================================================================
# 8. 示例模板加载函数
# ============================================================================

def load_example_template(template_name: str) -> AITemplate:
    """
    加载内置示例模板。

    可用模板：
      - "product_search"     : 商品搜索（向量 + API + 网页）
      - "news_digest"        : 新闻摘要（多源网页 + LLM 总结）
      - "data_enrichment"    : 数据补全（数据库 + API）

    参数：
      template_name : str — 模板名称

    返回：
      AITemplate

    JS 类比：
      import { productSearchTemplate } from './templates/product_search';
    """
    templates = {
        "product_search": _build_product_search_template(),
        "news_digest": _build_news_digest_template(),
        "data_enrichment": _build_data_enrichment_template(),
    }

    if template_name not in templates:
        available = list(templates.keys())
        raise ValueError(
            f"未知模板 '{template_name}'。可用: {available}"
        )

    return templates[template_name]


def list_example_templates() -> List[Dict[str, str]]:
    """列出所有内置示例模板的名称和描述"""
    return [
        {"name": "product_search", "description": "商品搜索 — 向量检索 + API 价格 + 网页详情"},
        {"name": "news_digest", "description": "新闻摘要 — 多源抓取 + 排序 + LLM 总结"},
        {"name": "data_enrichment", "description": "数据补全 — 数据库查询 + API 补全字段"},
    ]


# ---- 内置模板构建函数 ----

def _build_product_search_template() -> AITemplate:
    """
    商品搜索模板。

    流程：
      用户输入关键词 → 向量库语义搜索 → API 获取实时价格 → 网页抓取详情
      → 合并排序 → 输出结构化商品卡片
    """
    return AITemplate(
        name="product_search",
        version="1.0.0",
        description="商品搜索：输入关键词，返回带价格的商品卡片列表",

        # ---- 输入字段 ----
        inputs=[
            InputField(
                name="keyword",
                type=InputType.STRING,
                required=True,
                description="搜索关键词",
                examples=["iPhone 15", "蓝牙耳机", "机械键盘"],
            ),
            InputField(
                name="max_results",
                type=InputType.INTEGER,
                required=False,
                default=10,
                description="最大返回结果数",
            ),
            InputField(
                name="min_price",
                type=InputType.FLOAT,
                required=False,
                default=0.0,
                description="最低价格过滤",
            ),
            InputField(
                name="max_price",
                type=InputType.FLOAT,
                required=False,
                default=999999.0,
                description="最高价格过滤",
            ),
        ],

        # ---- 查询源 ----
        query_sources=[
            QuerySource(
                name="vector_search",
                type=QuerySourceType.VECTOR_DB,
                endpoint="chroma://localhost:8000/products",
                params={
                    "query": "{{input.keyword}}",
                    "top_k": "{{input.max_results}}",
                },
                timeout_ms=5000,
                description="向量语义搜索 — 找到语义相似的商品",
            ),
            QuerySource(
                name="price_api",
                type=QuerySourceType.API,
                endpoint="https://api.example.com/v1/prices",
                method="POST",
                params={
                    "product_ids": "{{input.keyword}}",  # 实际会被替换为向量搜索结果中的 ID
                    "currency": "CNY",
                },
                headers={"Authorization": "Bearer {{env.API_KEY}}"},
                timeout_ms=3000,
                retry=2,
                description="实时价格查询 API",
            ),
            QuerySource(
                name="product_detail",
                type=QuerySourceType.WEB,
                endpoint="https://www.example.com/products/",
                method="GET",
                timeout_ms=8000,
                description="商品详情页抓取",
            ),
        ],

        # ---- 输出 Schema ----
        output_schema=[
            OutputField(
                name="product_name",
                type="string",
                source="vector_search.name",
                description="商品名称",
            ),
            OutputField(
                name="price",
                type="number",
                source="price_api.current_price",
                description="当前价格（元）",
                fallback=0.0,
            ),
            OutputField(
                name="currency",
                type="string",
                source="price_api.currency",
                fallback="CNY",
            ),
            OutputField(
                name="description",
                type="string",
                source="product_detail.description",
                description="商品描述",
                fallback="",
            ),
            OutputField(
                name="image_url",
                type="string",
                source="product_detail.image",
                description="商品图片 URL",
            ),
            OutputField(
                name="score",
                type="number",
                source="vector_search.score",
                description="语义相似度分数",
            ),
        ],

        # ---- 算法房间 ----
        algorithm_room=AlgorithmRoom(
            merge_strategy="join_by_key",
            merge_key="product_id",
            steps=[
                AlgorithmStep(
                    type=AlgorithmType.FILTER,
                    config={
                        "field": "price",
                        "operator": "between",
                        "min": "{{input.min_price}}",
                        "max": "{{input.max_price}}",
                    },
                    description="价格区间过滤",
                ),
                AlgorithmStep(
                    type=AlgorithmType.RANK,
                    config={
                        "sort_by": "score",
                        "order": "desc",
                    },
                    description="按语义相似度降序排列",
                ),
                AlgorithmStep(
                    type=AlgorithmType.TRANSFORM,
                    config={
                        "format": "product_card",
                        "include_fields": [
                            "product_name", "price", "currency",
                            "description", "image_url", "score",
                        ],
                    },
                    description="格式化为产品卡片",
                ),
            ],
        ),

        metadata={
            "author": "ai-query-framework",
            "tags": ["e-commerce", "search", "vector"],
            "created_at": "2025-01-15",
        },
    )


def _build_news_digest_template() -> AITemplate:
    """
    新闻摘要模板。

    流程：
      多个新闻源抓取 → 合并去重 → 排序 → LLM 生成摘要
    """
    return AITemplate(
        name="news_digest",
        version="1.0.0",
        description="新闻摘要：从多个新闻源抓取，去重排序，LLM 生成摘要",

        inputs=[
            InputField(
                name="topic",
                type=InputType.STRING,
                required=True,
                description="新闻主题",
                examples=["人工智能", "气候变化", "芯片"],
            ),
            InputField(
                name="max_articles",
                type=InputType.INTEGER,
                required=False,
                default=5,
                description="最多返回文章数",
            ),
            InputField(
                name="language",
                type=InputType.ENUM,
                required=False,
                default="zh",
                options=["zh", "en", "ja"],
                description="语言偏好",
            ),
        ],

        query_sources=[
            QuerySource(
                name="source_a",
                type=QuerySourceType.WEB,
                endpoint="https://news.example-a.com/search",
                params={"q": "{{input.topic}}", "lang": "{{input.language}}"},
                description="新闻源 A",
            ),
            QuerySource(
                name="source_b",
                type=QuerySourceType.WEB,
                endpoint="https://news.example-b.com/search",
                params={"keyword": "{{input.topic}}"},
                description="新闻源 B",
            ),
        ],

        output_schema=[
            OutputField(name="title", type="string", source="merged.title"),
            OutputField(name="url", type="string", source="merged.url"),
            OutputField(name="source", type="string", source="merged.source_name"),
            OutputField(name="published_at", type="string", source="merged.pub_date"),
            OutputField(name="summary", type="string", source="llm.summary",
                        description="LLM 生成的摘要"),
        ],

        algorithm_room=AlgorithmRoom(
            merge_strategy="concat",
            steps=[
                AlgorithmStep(
                    type=AlgorithmType.MERGE,
                    config={"sources": ["source_a", "source_b"], "dedup_by": "url"},
                    description="合并去重",
                ),
                AlgorithmStep(
                    type=AlgorithmType.RANK,
                    config={"sort_by": "published_at", "order": "desc"},
                    description="按发布时间降序",
                ),
                AlgorithmStep(
                    type=AlgorithmType.FILTER,
                    config={"field": "index", "operator": "<", "value": "{{input.max_articles}}"},
                    description="取前 N 篇",
                ),
                AlgorithmStep(
                    type=AlgorithmType.LLM_SUMMARIZE,
                    config={
                        "prompt_template": (
                            "请用{{input.language}}为以下新闻生成一句话摘要：\n"
                            "标题：{title}\n内容：{content}"
                        ),
                        "model": "gpt-4",
                        "max_tokens": 150,
                    },
                    description="LLM 逐篇生成摘要",
                ),
            ],
        ),

        metadata={
            "author": "ai-query-framework",
            "tags": ["news", "digest", "llm"],
        },
    )


def _build_data_enrichment_template() -> AITemplate:
    """
    数据补全模板。

    流程：
      数据库查询基础数据 → API 补全缺失字段 → 输出完整记录
    """
    return AITemplate(
        name="data_enrichment",
        version="1.0.0",
        description="数据补全：从数据库查基础数据，通过 API 补全缺失字段",

        inputs=[
            InputField(
                name="entity_id",
                type=InputType.STRING,
                required=True,
                description="实体 ID",
                examples=["COMP_001", "USER_42"],
            ),
            InputField(
                name="entity_type",
                type=InputType.ENUM,
                required=True,
                options=["company", "user", "product"],
                description="实体类型",
            ),
        ],

        query_sources=[
            QuerySource(
                name="local_db",
                type=QuerySourceType.DATABASE,
                endpoint="postgresql://localhost:5432/data",
                params={
                    "table": "{{input.entity_type}}s",
                    "where": {"id": "{{input.entity_id}}"},
                },
                description="本地数据库 — 基础字段",
            ),
            QuerySource(
                name="enrichment_api",
                type=QuerySourceType.API,
                endpoint="https://api.enrichment-service.com/v2/lookup",
                method="POST",
                params={
                    "entity_id": "{{input.entity_id}}",
                    "entity_type": "{{input.entity_type}}",
                    "fields": ["industry", "revenue", "employees", "social_media"],
                },
                timeout_ms=5000,
                retry=3,
                description="第三方数据补全 API",
            ),
        ],

        output_schema=[
            OutputField(name="id", type="string", source="local_db.id"),
            OutputField(name="name", type="string", source="local_db.name"),
            OutputField(name="industry", type="string", source="enrichment_api.industry",
                        fallback="未知"),
            OutputField(name="revenue", type="number", source="enrichment_api.revenue"),
            OutputField(name="employees", type="number", source="enrichment_api.employees"),
            OutputField(name="social_media", type="object",
                        source="enrichment_api.social_media"),
        ],

        algorithm_room=AlgorithmRoom(
            merge_strategy="join_by_key",
            merge_key="entity_id",
            steps=[
                AlgorithmStep(
                    type=AlgorithmType.MERGE,
                    config={"sources": ["local_db", "enrichment_api"], "how": "left"},
                    description="左连接：保留所有本地记录，补全 API 字段",
                ),
                AlgorithmStep(
                    type=AlgorithmType.TRANSFORM,
                    config={"format": "entity_card"},
                    description="格式化为实体卡片",
                ),
            ],
        ),

        metadata={
            "author": "ai-query-framework",
            "tags": ["enrichment", "data", "api"],
        },
    )


# ============================================================================
# 9. 自测入口
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("TemplateEngine 自测")
    print("=" * 60)

    validator = TemplateValidator()

    # ---- 测试1：加载示例模板 ----
    print("\n[测试1] 加载示例模板")
    for info in list_example_templates():
        tmpl = load_example_template(info["name"])
        print(f"  ✓ {info['name']}: v{tmpl.version} — {tmpl.description}")

    # ---- 测试2：模板验证 ----
    print("\n[测试2] 验证所有示例模板")
    for info in list_example_templates():
        tmpl = load_example_template(info["name"])
        errors = validator.validate(tmpl)
        status = "✓ 通过" if not errors else f"✗ {len(errors)} 个错误"
        print(f"  {info['name']}: {status}")
        for e in errors:
            print(f"    - {e}")

    # ---- 测试3：JSON 序列化/反序列化 ----
    print("\n[测试3] JSON 往返序列化")
    original = load_example_template("product_search")
    json_str = original.to_json()
    restored = AITemplate.from_json(json_str)
    assert restored.name == original.name, "名称不一致"
    assert restored.version == original.version, "版本不一致"
    assert len(restored.query_sources) == len(original.query_sources), "查询源数量不一致"
    print(f"  ✓ 序列化/反序列化一致: {original.name} v{original.version}")
    print(f"  JSON 长度: {len(json_str)} 字符")

    # ---- 测试4：params 模板渲染 ----
    print("\n[测试4] Params 模板渲染")
    tmpl = load_example_template("product_search")
    source = tmpl.query_sources[0]  # vector_search
    rendered = tmpl.render_params(source, {"keyword": "机械键盘", "max_results": 5})
    print(f"  原始 params: {source.params}")
    print(f"  渲染后     : {rendered}")

    # ---- 测试5：验证失败场景 ----
    print("\n[测试5] 验证失败场景")
    # 构造一个不合法的模板
    bad_template = AITemplate(
        name="123bad",           # 数字开头 → 不合法
        version="not-a-version", # 不符合 semver
        query_sources=[],        # 空
        output_schema=[],        # 空
    )
    errors = validator.validate(bad_template)
    print(f"  错误数量: {len(errors)}")
    for e in errors:
        print(f"  - {e}")

    # ---- 测试6：TemplateValidationError 异常 ----
    print("\n[测试6] validate_or_raise 异常")
    try:
        validator.validate_or_raise(bad_template)
        print("  ✗ 应该抛出异常但没有")
    except TemplateValidationError as e:
        print(f"  ✓ 正确抛出异常: {e}")

    # ---- 测试7：to_dict 与 metadata ----
    print("\n[测试7] 模板元数据")
    tmpl = load_example_template("news_digest")
    d = tmpl.to_dict()
    print(f"  metadata: {d['metadata']}")
    print(f"  inputs: {len(d['inputs'])} 个")
    print(f"  query_sources: {len(d['query_sources'])} 个")
    print(f"  output_fields: {len(d['output_schema']['fields'])} 个")
    print(f"  algorithm_steps: {len(d['algorithm_room']['steps'])} 个")

    print("\n" + "=" * 60)
    print("全部测试完成 ✓")
    print("=" * 60)
