"""
Schema-based 精准采集器 — Precision Collector
==============================================
类比：SQL 的 SELECT column FROM table — 只取 schema 定义的字段，不做全文提取。

JS 类比：
  - FieldSchema   ≈  column schema in a TypeScript interface
  - PrecisionCollector ≈  a query planner that projects only the requested columns onto raw data

使用场景：
  1. HTML 页面 → 只需标题、价格、日期三个字段
  2. JSON API 响应 → 只需嵌套的 user.name、user.email
  3. 任何数据源 → schema 定义什么就取什么，绝不多取

设计原则：
  - 声明式：用 schema 描述想要什么，不写过程式解析代码
  - 隔离：sandbox_test() 在新数据上先验证再上线
  - 可组合：多个 collector 可以拼接成 pipeline
"""

import json
import os
import re
from typing import Any, Callable, Dict, List, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# ============================================================================
# 1. FieldSchema — 字段抽取规则
# ============================================================================
# 类比 SQL：
#   CREATE TABLE 中定义列的类型、约束 → FieldSchema 定义字段的类型、验证器
#
# JS 类比：
#   interface FieldSchema {
#     field_name: string;
#     selector: string;      // CSS / XPath / JSONPath
#     type: 'str' | 'int' | 'float' | 'date';
#     validators: Validator[];
#   }
# ============================================================================

class FieldType(Enum):
    """字段数据类型枚举 — 对应 SQL 的 column type"""
    STR = "str"        # 字符串 — SQL VARCHAR / TEXT
    INT = "int"        # 整数   — SQL INTEGER
    FLOAT = "float"    # 浮点数 — SQL REAL / DOUBLE
    DATE = "date"      # 日期   — SQL DATE / TIMESTAMP


@dataclass
class FieldSchema:
    """
    单个字段的抽取规则定义。

    属性（逐行解释）：
      field_name : str         — 输出 JSON 中的 key 名，类比 SQL 的 column alias
      selector   : str         — 定位表达式：CSS 选择器 / XPath / JSONPath
      type       : FieldType   — 目标数据类型，抽取后做类型转换
      validators : list        — 验证函数列表，每个签名为 (value) -> bool
      default    : Any         — 抽取失败时的默认值（None 表示必须成功）
      description: str         — 字段说明，用于文档生成和调试
    """
    field_name: str
    selector: str
    type: FieldType = FieldType.STR
    validators: List[Callable[[Any], bool]] = field(default_factory=list)
    default: Any = None
    description: str = ""
    allow_html: bool = False

    # JS 类比：TypeScript 的 type guard 函数
    # function isNonEmpty(v: unknown): v is string { return typeof v === 'string' && v.length > 0; }

    @staticmethod
    def validator_not_empty() -> Callable[[Any], bool]:
        """内置验证器：值不能为空字符串或 None"""
        return lambda v: v is not None and str(v).strip() != ""

    @staticmethod
    def validator_min_length(n: int) -> Callable[[Any], bool]:
        """内置验证器：字符串最小长度"""
        return lambda v: v is not None and len(str(v)) >= n

    @staticmethod
    def validator_range(lo: float, hi: float) -> Callable[[Any], bool]:
        """内置验证器：数值范围 [lo, hi]"""
        return lambda v: v is not None and lo <= float(v) <= hi

    @staticmethod
    def validator_regex(pattern: str) -> Callable[[Any], bool]:
        """内置验证器：正则匹配"""
        return lambda v: v is not None and bool(re.match(pattern, str(v)))


# ============================================================================
# 2. PrecisionCollector — 精准采集器
# ============================================================================
# 类比 SQL 引擎：
#   SELECT name, price FROM raw_data  →  collector.collect(raw_data, schema)
#   sandbox_test ≈ EXPLAIN / dry-run   →  先跑一遍看看结果，再决定是否上线
#
# JS 类比：
#   class PrecisionCollector {
#     collectFromHTML(html, schema): Record<string, any>
#     collectFromJSON(json, schema): Record<string, any>
#     sandboxTest(schema, sample): TestResult
#   }
# ============================================================================

class PrecisionCollector:
    """
    精准采集器：根据 FieldSchema 列表从各种数据源中抽取字段。

    核心方法（三个 collect_* + 一个 sandbox）：
      collect(input, schema)              — 自动检测数据源类型并采集
      collect_from_html(html, schema)  — HTML → 结构化 JSON
      collect_from_json(json_data, schema) — JSON → 结构化 JSON（裁剪）
      collect_from_api(response, schema)   — API Response → 结构化 JSON
      sandbox_test(schema, sample_data)    — 隔离验证新采集逻辑
    """

    # ------------------------------------------------------------------
    # 类级别常量：全局 HTML 开关
    # 类比：浏览器的 Content-Security-Policy — 默认禁止加载 HTML，
    #       只有明确声明 allow_html=True 的 schema 才放行。
    # 可通过环境变量 AIQUERY_DEFAULT_ALLOW_HTML=true 全局启用。
    # ------------------------------------------------------------------
    DEFAULT_ALLOW_HTML: bool = os.environ.get(
        "AIQUERY_DEFAULT_ALLOW_HTML", "false"
    ).strip().lower() in ("1", "true", "yes", "on")

    def __init__(self):
        """初始化采集器。当前无状态，未来可注入缓存或连接池。"""
        # JS 类比：this.cache = new Map()
        self._collected_count: int = 0  # 采集计数，用于监控

    # ------------------------------------------------------------------
    # 2a. 通用采集入口（自动检测数据源）
    # ------------------------------------------------------------------
    def collect(
        self,
        source: Any,
        schema: List[FieldSchema],
        *,
        source_type: str = "auto"
    ) -> Dict[str, Any]:
        """
        自动检测数据源类型并采集。

        参数：
          source      : Any              — 数据源（HTML 字符串 / JSON dict / Response）
          schema      : List[FieldSchema] — 字段定义列表
          source_type : str              — "html" / "json" / "api" / "auto"

        返回：
          Dict[str, Any]

        HTML 安全策略（类比 Content-Security-Policy）：
          - 如果 source 是 HTML 且全局 DEFAULT_ALLOW_HTML=False，
            则检查 schema 中是否有任一字段设置了 allow_html=True
          - 只有当全局开关开启 OR 至少一个字段允许时，才解析 HTML
          - 否则抛出 ValueError
        """
        # ---- 自动检测数据源类型 ----
        if source_type == "auto":
            if isinstance(source, str) and source.strip().startswith("<"):
                source_type = "html"
            elif isinstance(source, str):
                source_type = "json"
            else:
                source_type = "json"

        # ---- HTML 安全开关检查（Content-Security-Policy 类比）----
        if source_type == "html":
            has_any_allow = any(
                getattr(f, "allow_html", False) for f in schema
            )
            if not self.DEFAULT_ALLOW_HTML and not has_any_allow:
                raise ValueError(
                    "HTML 采集被拒绝：全局 DEFAULT_ALLOW_HTML=False，"
                    "且 schema 中没有字段设置 allow_html=True。"
                    "要允许 HTML 采集，请至少在一个 FieldSchema 中设置 allow_html=True，"
                    "或设置环境变量 AIQUERY_DEFAULT_ALLOW_HTML=true。"
                )

        # ---- 按类型分派 ----
        if source_type == "html":
            return self.collect_from_html(source, schema)
        elif source_type == "api":
            return self.collect_from_api(source, schema)
        else:
            if isinstance(source, str):
                source = json.loads(source)
            return self.collect_from_json(source, schema)

    # ------------------------------------------------------------------
    # 2b. 从 HTML 采集
    # ------------------------------------------------------------------
    def collect_from_html(
        self,
        html: str,
        schema: List[FieldSchema],
        *,
        parser: str = "html.parser"
    ) -> Dict[str, Any]:
        """
        从 HTML 文本中按 schema 抽取字段。

        参数：
          html   : str               — 原始 HTML 文本（可以是完整的 <html>...</html>）
          schema : List[FieldSchema] — 字段定义列表
          parser : str               — BeautifulSoup 解析器（默认 html.parser）

        返回：
          Dict[str, Any] — {field_name: extracted_value, ...}

        JS 类比：
          const result = schema.reduce((acc, field) => {
            acc[field.field_name] = document.querySelector(field.selector)?.textContent;
            return acc;
          }, {});

        安全说明：
          调用前应先通过 collect() 入口（会检查 allow_html 开关），
          直接调用本方法将跳过 Content-Security-Policy 级别的检查。
        """
        try:
            from bs4 import BeautifulSoup  # 延迟导入，避免强依赖
        except ImportError:
            raise ImportError(
                "collect_from_html 需要 beautifulsoup4。请执行: pip install beautifulsoup4"
            )

        soup = BeautifulSoup(html, parser)
        result: Dict[str, Any] = {}

        for field in schema:
            # ---- 步骤1：用 CSS 选择器定位元素 ----
            # JS 类比：element = document.querySelector(field.selector)
            element = soup.select_one(field.selector)

            if element is None:
                # 选择器没有匹配到任何元素
                if field.default is not None:
                    result[field.field_name] = field.default
                else:
                    result[field.field_name] = None
                continue

            # ---- 步骤2：提取文本并清理 ----
            # JS 类比：element.textContent.trim()
            raw_value = element.get_text(strip=True)

            # ---- 步骤3：类型转换 ----
            # JS 类比：parseInt(raw_value) / parseFloat(raw_value)
            typed_value = self._cast_value(raw_value, field.type)

            # ---- 步骤4：运行验证器 ----
            if not self._run_validators(typed_value, field.validators):
                if field.default is not None:
                    result[field.field_name] = field.default
                else:
                    result[field.field_name] = None
                continue

            result[field.field_name] = typed_value

        self._collected_count += 1
        return result

    # ------------------------------------------------------------------
    # 2c. 从 JSON 采集（裁剪）
    # ------------------------------------------------------------------
    def collect_from_json(
        self,
        json_data: Union[Dict, List],
        schema: List[FieldSchema]
    ) -> Dict[str, Any]:
        """
        从 JSON 数据中按 schema 裁剪字段。

        selector 此时是 JSONPath 简化版（点号分隔的路径）：
          - "user.name"       → json_data["user"]["name"]
          - "items.0.title"   → json_data["items"][0]["title"]
          - "data"            → json_data["data"]

        JS 类比（lodash）：
          _.get(json_data, 'user.name', null)

        参数：
          json_data : dict | list     — 已解析的 JSON 对象
          schema    : List[FieldSchema]

        返回：
          Dict[str, Any] — 裁剪后的结果
        """
        result: Dict[str, Any] = {}

        for field in schema:
            # ---- 步骤1：沿路径 drill-down ----
            # JS 类比：R.path(field.selector.split('.'), json_data)
            raw_value = self._jsonpath_get(json_data, field.selector)

            if raw_value is None:
                if field.default is not None:
                    result[field.field_name] = field.default
                else:
                    result[field.field_name] = None
                continue

            # ---- 步骤2：类型转换 ----
            typed_value = self._cast_value(raw_value, field.type)

            # ---- 步骤3：验证器 ----
            if not self._run_validators(typed_value, field.validators):
                if field.default is not None:
                    result[field.field_name] = field.default
                else:
                    result[field.field_name] = None
                continue

            result[field.field_name] = typed_value

        self._collected_count += 1
        return result

    # ------------------------------------------------------------------
    # 2d. 从 API Response 采集
    # ------------------------------------------------------------------
    def collect_from_api(
        self,
        response: Any,
        schema: List[FieldSchema]
    ) -> Dict[str, Any]:
        """
        从 API 响应对象中采集字段。

        支持：
          - requests.Response 对象（自动 .json()）
          - httpx.Response 对象
          - 已解析的 dict / list
          - JSON 字符串

        JS 类比：
          async function collectFromAPI(response, schema) {
            const json = await response.json();
            return collectFromJSON(json, schema);
          }

        参数：
          response : Any              — API 响应（Response 对象 / dict / str）
          schema   : List[FieldSchema]

        返回：
          Dict[str, Any]
        """
        # ---- 自动检测响应类型并提取 JSON ----
        # JS 类比：const data = response instanceof Response ? await response.json() : response;
        if hasattr(response, "json") and callable(response.json):
            # requests.Response / httpx.Response
            json_data = response.json()
        elif isinstance(response, str):
            # 原始 JSON 字符串
            json_data = json.loads(response)
        elif isinstance(response, (dict, list)):
            # 已经是解析好的 JSON
            json_data = response
        else:
            raise TypeError(
                f"不支持的响应类型: {type(response)}。"
                f"需要 Response 对象、dict、list 或 JSON 字符串。"
            )

        # ---- 委托给 collect_from_json ----
        return self.collect_from_json(json_data, schema)

    # ------------------------------------------------------------------
    # 2e. 沙箱隔离验证
    # ------------------------------------------------------------------
    def sandbox_test(
        self,
        schema: List[FieldSchema],
        sample_data: Union[str, Dict, List]
    ) -> Dict[str, Any]:
        """
        在隔离环境中测试新采集逻辑，不影响线上数据。

        类比：
          SQL EXPLAIN / dry-run   — 先看看查询计划，不真正执行写入
          JS unit test            — 用 mock data 跑一遍看输出

        返回结构：
          {
            "success": True/False,
            "result": {...},           # 采集到的数据
            "errors": [...],           # 每个字段的错误详情
            "coverage": "3/4",         # 成功字段 / 总字段
            "timestamp": "2025-..."
          }

        参数：
          schema      : List[FieldSchema]
          sample_data : str | dict | list — 样本数据

        返回：
          Dict[str, Any] — 包含 success、result、errors、coverage、timestamp
        """
        errors: List[Dict[str, str]] = []
        success_count = 0
        result: Dict[str, Any] = {}

        # ---- 根据样本数据类型选择采集方法 ----
        # 通过 collect() 入口统一处理（含 HTML 安全开关检查）
        try:
            raw_result = self.collect(sample_data, schema)
        except ValueError:
            # HTML 被拒绝 → 记录错误并返回空结果
            raw_result = {}
            for field in schema:
                errors.append({
                    "field": field.field_name,
                    "selector": field.selector,
                    "reason": "HTML 采集被 Content-Security-Policy 拒绝（allow_html=False）",
                })

        # ---- 按 schema 逐字段检查结果 ----
        for field in schema:
            value = raw_result.get(field.field_name)
            if value is not None:
                success_count += 1
            else:
                errors.append({
                    "field": field.field_name,
                    "selector": field.selector,
                    "reason": (
                        f"选择器 '{field.selector}' 未匹配到数据，"
                        f"且未设置默认值"
                    ),
                })

        result = raw_result
        total = len(schema)
        is_success = success_count == total

        return {
            "success": is_success,
            "result": result,
            "errors": errors,
            "coverage": f"{success_count}/{total}",
            "timestamp": datetime.now().isoformat(),
        }

    # ==================================================================
    # 内部辅助方法
    # ==================================================================

    def _cast_value(self, raw: Any, target_type: FieldType) -> Any:
        """
        类型转换器。

        JS 类比：
          function cast(raw, type) {
            switch(type) {
              case 'int': return parseInt(raw);
              case 'float': return parseFloat(raw);
              ...
            }
          }
        """
        if raw is None:
            return None

        try:
            if target_type == FieldType.STR:
                return str(raw).strip()
            elif target_type == FieldType.INT:
                # 处理 "1,234" 这种千分位格式
                cleaned = str(raw).replace(",", "").strip()
                return int(float(cleaned))  # float 中转处理 "1.0" → 1
            elif target_type == FieldType.FLOAT:
                cleaned = str(raw).replace(",", "").strip()
                return float(cleaned)
            elif target_type == FieldType.DATE:
                # 尝试多种日期格式
                return self._parse_date(str(raw))
            else:
                return str(raw)
        except (ValueError, TypeError):
            # 类型转换失败 → 返回 None，由调用方处理
            return None

    def _parse_date(self, raw: str) -> Optional[str]:
        """
        日期解析器，支持常见格式。

        尝试顺序：
          1. ISO 8601: 2025-01-15T10:30:00
          2. 标准日期: 2025-01-15
          3. 中文日期: 2025年1月15日
          4. 斜杠格式: 01/15/2025
        """
        formats = [
            "%Y-%m-%dT%H:%M:%S",   # ISO 8601
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d",            # 标准日期
            "%Y/%m/%d",            # 斜杠
            "%Y年%m月%d日",         # 中文
            "%m/%d/%Y",            # 美式
            "%d/%m/%Y",            # 欧式
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(raw.strip(), fmt)
                return dt.strftime("%Y-%m-%d")  # 统一输出 ISO 日期
            except ValueError:
                continue
        return raw  # 都不匹配 → 返回原值

    def _jsonpath_get(self, obj: Any, path: str) -> Any:
        """
        简化版 JSONPath getter。

        支持：
          - "key"              → obj["key"]
          - "a.b.c"            → obj["a"]["b"]["c"]
          - "items.0.name"     → obj["items"][0]["name"]
          - "data.0"           → obj["data"][0]

        JS 类比：lodash _.get(obj, path)
        """
        if obj is None:
            return None

        parts = path.split(".")
        current = obj

        for part in parts:
            if current is None:
                return None

            # 尝试数字索引（数组）
            if isinstance(current, list):
                try:
                    idx = int(part)
                    if 0 <= idx < len(current):
                        current = current[idx]
                    else:
                        return None
                except (ValueError, IndexError):
                    return None
            # 尝试字典键
            elif isinstance(current, dict):
                current = current.get(part)
            else:
                # 不是集合类型 → 无法继续 drill-down
                return None

        return current

    def _run_validators(
        self,
        value: Any,
        validators: List[Callable[[Any], bool]]
    ) -> bool:
        """
        依次运行所有验证器，全部通过才返回 True。

        JS 类比：
          validators.every(fn => fn(value))
        """
        for validator in validators:
            try:
                if not validator(value):
                    return False
            except Exception:
                return False
        return True


# ============================================================================
# 3. 便捷函数 — 快速使用
# ============================================================================

def quick_collect(
    source: Any,
    fields: List[Dict[str, Any]],
    *,
    source_type: str = "auto"
) -> Dict[str, Any]:
    """
    一行代码完成采集。

    参数：
      source      : Any                 — 数据源
      fields      : List[dict]          — 简化的字段定义，如：
                    [{"field_name": "title", "selector": "h1", "type": "str"}]
      source_type : str                 — "html" / "json" / "api" / "auto"

    返回：
      Dict[str, Any]

    JS 类比：
      quickCollect(document.body.innerHTML, [
        { fieldName: 'title', selector: 'h1', type: 'str' }
      ])
    """
    # 将简化的 dict 列表转为 FieldSchema 列表
    schema = [
        FieldSchema(
            field_name=f["field_name"],
            selector=f.get("selector", f["field_name"]),
            type=FieldType(f.get("type", "str")),
            validators=f.get("validators", []),
            default=f.get("default"),
            description=f.get("description", ""),
        )
        for f in fields
    ]

    collector = PrecisionCollector()

    if source_type == "html":
        return collector.collect(source, schema, source_type="html")
    elif source_type == "json":
        return collector.collect_from_json(source, schema)
    elif source_type == "api":
        return collector.collect_from_api(source, schema)
    else:
        # auto 模式：使用 collect() 统一入口
        return collector.collect(source, schema)


# ============================================================================
# 4. 自测入口 — 直接运行 python precision_collector.py 可验证
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("PrecisionCollector 自测")
    print("=" * 60)

    # ---- 测试1：从模拟 HTML 中采集 ----
    print("\n[测试1] collect_from_html")
    sample_html = """
    <html>
      <body>
        <h1 class="title">iPhone 15 Pro</h1>
        <span class="price">¥7,999</span>
        <time class="date">2025-01-15</time>
        <div class="rating">4.8</div>
      </body>
    </html>
    """

    html_schema = [
        FieldSchema("product_name", "h1.title", FieldType.STR,
                    validators=[FieldSchema.validator_not_empty()],
                    description="商品名称"),
        FieldSchema("price", "span.price", FieldType.FLOAT,
                    validators=[FieldSchema.validator_range(0, 100000)],
                    description="价格"),
        FieldSchema("listing_date", "time.date", FieldType.DATE,
                    description="上架日期"),
        FieldSchema("rating", "div.rating", FieldType.FLOAT,
                    description="评分"),
    ]

    collector = PrecisionCollector()
    html_result = collector.collect_from_html(sample_html, html_schema)
    print(f"  结果: {json.dumps(html_result, ensure_ascii=False, indent=2)}")

    # ---- 测试2：从 JSON 裁剪 ----
    print("\n[测试2] collect_from_json")
    sample_json = {
        "user": {
            "name": "张三",
            "email": "zhangsan@example.com",
            "profile": {
                "age": 28,
                "city": "北京"
            }
        },
        "orders": [
            {"id": "A001", "total": 150.5},
            {"id": "A002", "total": 299.0},
        ]
    }

    json_schema = [
        FieldSchema("username", "user.name", FieldType.STR),
        FieldSchema("email", "user.email", FieldType.STR),
        FieldSchema("city", "user.profile.city", FieldType.STR),
        FieldSchema("first_order", "orders.0.id", FieldType.STR),
    ]

    json_result = collector.collect_from_json(sample_json, json_schema)
    print(f"  结果: {json.dumps(json_result, ensure_ascii=False, indent=2)}")

    # ---- 测试3：沙箱验证 ----
    print("\n[测试3] sandbox_test")
    sandbox_result = collector.sandbox_test(html_schema, sample_html)
    print(f"  成功: {sandbox_result['success']}")
    print(f"  覆盖率: {sandbox_result['coverage']}")
    if sandbox_result["errors"]:
        for err in sandbox_result["errors"]:
            print(f"  错误字段: {err['field']} — {err['reason']}")

    # ---- 测试4：quick_collect ----
    print("\n[测试4] quick_collect")
    quick_result = quick_collect(sample_json, [
        {"field_name": "name", "selector": "user.name", "type": "str"},
        {"field_name": "age", "selector": "user.profile.age", "type": "int"},
    ])
    print(f"  结果: {json.dumps(quick_result, ensure_ascii=False, indent=2)}")

    print("\n" + "=" * 60)
    print("全部测试完成 ✓")
    print("=" * 60)
