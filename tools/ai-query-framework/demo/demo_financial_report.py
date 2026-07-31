#!/usr/bin/env python3
"""
================================================================================
  公司财报查询与简报生成 Demo
================================================================================

  场景：查公司财报并生成简报
  流程严格按照：模板 → 白名单 → 采集 → 算法 → 监控

  核心演示：
    ✅ 正常查询   — 白名单内、限流内，顺利产出简报
    ❌ 超限查询   — 触发 QueryBackpressure 限流，返回降级回答
    ❌ 未授权查询 — 白名单拒绝，AuthProxy 直接拦截

  数据规模：3 家公司 × 3 年 = 9 条模拟财报记录

  使用方法：
      cd ai-query-framework/demo
      python3 demo_financial_report.py

  依赖（项目已有）：
      ai-query-framework/src/template_engine.py
      ai-query-framework/src/auth_proxy.py
      ai-query-framework/src/precision_collector.py
      ai-query-framework/src/query_guardian.py
================================================================================
"""

import sys
import os
import time
import json
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime

# ---- Windows 控制台默认 GBK,强制 UTF-8 输出避免 emoji/中文乱码报错 ----
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# ============================================================================
# 0. 路径处理：把 src 目录加入 sys.path，以便导入框架模块
# ============================================================================
# demo/demo_financial_report.py → src/ 在上一级的 src 下
_demo_dir = os.path.dirname(os.path.abspath(__file__))          # demo/
_framework_dir = os.path.dirname(_demo_dir)                     # ai-query-framework/
_src_dir = os.path.join(_framework_dir, "src")                  # src/
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

# ---- 框架模块导入 ----
from template_engine import (                                      # 模板引擎
    AITemplate, InputField, InputType,
    QuerySource, QuerySourceType,
    OutputField,
    AlgorithmRoom, AlgorithmStep, AlgorithmType,
    TemplateValidator,
)
from auth_proxy import (                                           # 权限代理
    AuthProxy, WhitelistRule, WhitelistConfig, Permission,
    QueryAction, AuditEvent, AuditEntry,
)
from precision_collector import (                                  # 精准采集器
    PrecisionCollector, FieldSchema, FieldType,
)
from query_guardian import (                                       # 查询卫士（五层防护）
    QueryGuardian, QueryLayer, DegradationLevel,
    QueryContext, DegradedResponse,
)


# ============================================================================
# 1. 模拟财报数据 — 3 家公司 × 3 年（2022 / 2023 / 2024）
# ============================================================================
# 这些数据模拟了一个「财报 API」的返回值。每条记录包含：
#   company     : 公司名称
#   year        : 财年
#   revenue     : 营收（亿元）
#   profit      : 净利润（亿元）
#   growth_rate : 同比增长率（%）
#   industry    : 所属行业
#   report_url  : 公告链接

MOCK_FINANCIAL_DB: List[Dict[str, Any]] = [
    # ======================== 腾讯控股 ========================
    {
        "company": "腾讯控股",
        "year": 2022,
        "revenue": 5545.52,          # 亿元
        "profit": 1156.49,           # 亿元
        "growth_rate": -1.0,         # %
        "industry": "互联网",
        "report_url": "https://example.com/reports/tencent/2022.pdf",
    },
    {
        "company": "腾讯控股",
        "year": 2023,
        "revenue": 6090.15,
        "profit": 1576.88,
        "growth_rate": 10.0,
        "industry": "互联网",
        "report_url": "https://example.com/reports/tencent/2023.pdf",
    },
    {
        "company": "腾讯控股",
        "year": 2024,
        "revenue": 6600.80,
        "profit": 1780.30,
        "growth_rate": 12.9,
        "industry": "互联网",
        "report_url": "https://example.com/reports/tencent/2024.pdf",
    },
    # ======================== 比亚迪 ========================
    {
        "company": "比亚迪",
        "year": 2022,
        "revenue": 4240.61,
        "profit": 166.22,
        "growth_rate": 96.2,
        "industry": "新能源汽车",
        "report_url": "https://example.com/reports/byd/2022.pdf",
    },
    {
        "company": "比亚迪",
        "year": 2023,
        "revenue": 6023.15,
        "profit": 300.41,
        "growth_rate": 80.7,
        "industry": "新能源汽车",
        "report_url": "https://example.com/reports/byd/2023.pdf",
    },
    {
        "company": "比亚迪",
        "year": 2024,
        "revenue": 7200.00,
        "profit": 420.00,
        "growth_rate": 39.8,
        "industry": "新能源汽车",
        "report_url": "https://example.com/reports/byd/2024.pdf",
    },
    # ======================== 宁德时代 ========================
    {
        "company": "宁德时代",
        "year": 2022,
        "revenue": 3285.94,
        "profit": 307.29,
        "growth_rate": 152.1,
        "industry": "动力电池",
        "report_url": "https://example.com/reports/catl/2022.pdf",
    },
    {
        "company": "宁德时代",
        "year": 2023,
        "revenue": 4009.17,
        "profit": 441.21,
        "growth_rate": 43.6,
        "industry": "动力电池",
        "report_url": "https://example.com/reports/catl/2023.pdf",
    },
    {
        "company": "宁德时代",
        "year": 2024,
        "revenue": 4300.00,
        "profit": 500.00,
        "growth_rate": 13.3,
        "industry": "动力电池",
        "report_url": "https://example.com/reports/catl/2024.pdf",
    },
]


# ============================================================================
# 2. 辅助函数：模拟财报 API 调用
# ============================================================================
def mock_financial_api(company: str, year: int) -> Optional[Dict[str, Any]]:
    """
    模拟财报 API：从本地 MOCK_FINANCIAL_DB 中查数据。

    参数：
      company : str — 公司名称（精确匹配）
      year    : int — 财年

    返回：
      匹配的财报记录 dict，若未找到则返回 None。
    """
    for record in MOCK_FINANCIAL_DB:
        if record["company"] == company and record["year"] == year:
            # 模拟网络延迟 50ms ~ 150ms
            time.sleep(0.06)
            return dict(record)  # 返回副本，避免外部修改
    return None


# ============================================================================
# 3. 辅助函数：模拟算法房间 — 财报简报生成
# ============================================================================
def algorithm_generate_brief(
    company: str, year: int, collected: Dict[str, Any]
) -> str:
    """
    模拟「算法房间」处理：根据采集到的财报数据，生成简报文本。

    参数：
      company   : 公司名称
      year      : 财年
      collected : 精准采集后的 dict，含有 revenue / profit / growth_rate

    返回：
      简报文本（str）
    """
    # 模拟算法推理耗时
    time.sleep(0.08)

    revenue = collected.get("revenue", 0)
    profit = collected.get("profit", 0)
    growth = collected.get("growth_rate", 0)

    # 根据增长率给出评级
    if growth >= 50:
        rating = "⭐⭐⭐⭐⭐ 爆发增长"
    elif growth >= 20:
        rating = "⭐⭐⭐⭐   高速增长"
    elif growth >= 0:
        rating = "⭐⭐⭐     稳健增长"
    else:
        rating = "⭐⭐       增速放缓"

    brief = (
        f"📊 【{company} {year} 年度财报简报】\n"
        f"   ├─ 营收：{revenue:.2f} 亿元\n"
        f"   ├─ 净利润：{profit:.2f} 亿元\n"
        f"   ├─ 同比增长率：{growth:+.1f}%\n"
        f"   └─ 综合评级：{rating}\n"
    )
    return brief


# ============================================================================
# 4. 构建「公司财报查询模板」
# ============================================================================
def build_financial_report_template() -> AITemplate:
    """
    构建一个"公司财报查询"的 AI 模板。

    流程定义：
      输入(公司名+年份) → 查询源(财报API) → 输出(收入/利润/增长率)
      → 算法房间(LLM 总结生成简报)
    """
    template = AITemplate(
        name="financial_report_query",              # 模板唯一标识
        version="1.0.0",                            # 语义化版本
        description="公司财报查询：输入公司名和年份，返回收入/利润/增长率并生成简报",

        # ---- 输入字段定义 ----
        inputs=[
            InputField(
                name="company",
                type=InputType.STRING,
                required=True,                      # 必填
                description="公司名称（如：腾讯控股、比亚迪）",
                examples=["腾讯控股", "比亚迪", "宁德时代"],
            ),
            InputField(
                name="year",
                type=InputType.INTEGER,
                required=True,
                description="查询财年（如 2024）",
                examples=[2022, 2023, 2024],
                validators=[lambda v: 2000 <= int(v) <= 2030],  # 年份范围验证
            ),
        ],

        # ---- 查询源定义 ----
        query_sources=[
            QuerySource(
                name="financial_api",               # 源名称
                type=QuerySourceType.API,           # API 类型
                endpoint="https://api.finance.example.com/v1/reports",
                method="GET",
                params={
                    "company": "{{input.company}}",  # 占位符，运行时替换
                    "year": "{{input.year}}",
                },
                timeout_ms=5000,                    # 5 秒超时
                retry=2,                            # 最多重试 2 次
                description="财报查询 API — 返回营收、利润、增长率",
            ),
        ],

        # ---- 输出 Schema 定义 ----
        output_schema=[
            OutputField(
                name="revenue",
                type="number",
                source="financial_api.revenue",     # 来自财报 API 的 revenue 字段
                description="营业收入（亿元）",
                fallback=0.0,                       # 缺失时回退为 0
            ),
            OutputField(
                name="profit",
                type="number",
                source="financial_api.profit",
                description="净利润（亿元）",
                fallback=0.0,
            ),
            OutputField(
                name="growth_rate",
                type="number",
                source="financial_api.growth_rate",
                description="同比增长率（%）",
                fallback=0.0,
            ),
        ],

        # ---- 算法房间配置 ----
        algorithm_room=AlgorithmRoom(
            steps=[
                AlgorithmStep(
                    type=AlgorithmType.FILTER,
                    config={"field": "revenue", "operator": ">=", "value": 0},
                    description="过滤无效记录（营收不能为负）",
                ),
                AlgorithmStep(
                    type=AlgorithmType.TRANSFORM,
                    config={"format": "brief_text"},
                    description="将结构化数据转为简报文本",
                ),
                AlgorithmStep(
                    type=AlgorithmType.LLM_SUMMARIZE,
                    config={
                        "model": "gpt-4o-mini",
                        "max_tokens": 500,
                        "prompt_template": "请根据以下财报数据生成一份简洁的投资简报："
                                          "营收{{revenue}}亿元，净利润{{profit}}亿元，"
                                          "同比增长{{growth_rate}}%。",
                    },
                    description="LLM 总结生成最终简报",
                ),
            ],
            merge_strategy="concat",                # 多源结果拼接
        ),
    )
    return template


# ============================================================================
# 5. 核心流程函数：执行一次完整的"模板→白名单→采集→算法→监控"流水线
# ============================================================================
def execute_query_pipeline(
    company: str,
    year: int,
    auth_proxy: AuthProxy,
    collector: PrecisionCollector,
    guardian: QueryGuardian,
    scenario_label: str = "正常查询",
) -> Dict[str, Any]:
    """
    执行一条完整的查询流水线，严格按五大步骤推进。

    返回一个 dict，包含每步的状态和结果，供上层展示。
    """
    result_log: Dict[str, Any] = {
        "scenario": scenario_label,
        "company": company,
        "year": year,
        "steps": {},
    }

    # ────────────────────────────────────────────────────────────
    # Step 1: 加载模板
    # ────────────────────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print(f"📋 Step 1/5: 加载模板 —「公司财报查询模板 v1.0.0」")
    print(f"{'─' * 60}")
    template = build_financial_report_template()

    # 验证模板合法性
    validator = TemplateValidator()
    errors = validator.validate(template)
    if errors:
        print(f"  ❌ 模板验证失败: {errors}")
        result_log["steps"]["template"] = {"status": "FAIL", "errors": errors}
        return result_log
    print(f"  ✅ 模板验证通过")
    print(f"     模板名: {template.name}")
    print(f"     输入字段: {[f.name for f in template.inputs]}")
    print(f"     查询源: {[s.name for s in template.query_sources]}")
    print(f"     输出字段: {[o.name for o in template.output_schema]}")
    result_log["steps"]["template"] = {"status": "OK", "name": template.name}

    # ────────────────────────────────────────────────────────────
    # Step 2: 白名单校验
    # ────────────────────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print(f"🔐 Step 2/5: 白名单校验 — AuthProxy.check_permission()")
    print(f"{'─' * 60}")

    # 构造查询上下文（模拟一次发往财报 API 的请求）
    query_context = {
        "domain": "api.finance.example.com",        # 目标域名
        "api_endpoint": "/v1/reports",              # API 端点
        "action": QueryAction.API_CALL.value,       # 动作类型
        "scope": "read:financial_reports",          # 请求 scope
        "subject": f"user_{company}",               # 操作主体
        "request_id": f"req_{company}_{year}",      # 请求追踪 ID
    }

    allowed, reason = auth_proxy.check_permission(
        query_context,
        required_permission=Permission.READ,
    )

    if not allowed:
        print(f"  ❌ 白名单拒绝: {reason}")
        result_log["steps"]["whitelist"] = {
            "status": "DENIED", "reason": reason,
        }
        return result_log

    print(f"  ✅ 白名单通过: {reason}")
    # 打印匹配到的规则
    matching = auth_proxy.whitelist.find_matching_rules(
        domain="api.finance.example.com",
        api_endpoint="/v1/reports",
        scope="read:financial_reports",
    )
    for rule in matching:
        print(f"     匹配规则: {rule.description}")
    result_log["steps"]["whitelist"] = {"status": "OK", "reason": reason}

    # ────────────────────────────────────────────────────────────
    # Step 3: 精准采集
    # ────────────────────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print(f"🎯 Step 3/5: 精准采集 — PrecisionCollector.collect_from_json()")
    print(f"{'─' * 60}")

    # 3a. 调用模拟财报 API
    api_response = mock_financial_api(company, year)
    if api_response is None:
        print(f"  ❌ API 未返回数据（公司={company}, 年={year}）")
        result_log["steps"]["collect"] = {"status": "NO_DATA"}
        return result_log
    print(f"  📡 API 原始响应: {json.dumps(api_response, ensure_ascii=False, indent=4)}")

    # 3b. 定义采集 schema — 只取我们需要的 3 个字段
    collection_schema = [
        FieldSchema(
            field_name="revenue",
            selector="revenue",                     # JSONPath 简写：直接取 key
            type=FieldType.FLOAT,
            validators=[FieldSchema.validator_range(0, 100000)],
            description="营业收入（亿元）",
        ),
        FieldSchema(
            field_name="profit",
            selector="profit",
            type=FieldType.FLOAT,
            validators=[FieldSchema.validator_range(-10000, 100000)],
            description="净利润（亿元）",
        ),
        FieldSchema(
            field_name="growth_rate",
            selector="growth_rate",
            type=FieldType.FLOAT,
            validators=[FieldSchema.validator_range(-100, 1000)],
            description="同比增长率（%）",
        ),
    ]

    # 3c. 执行精准采集
    collected = collector.collect_from_json(api_response, collection_schema)
    print(f"  📊 采集结果: {json.dumps(collected, ensure_ascii=False, indent=4)}")

    # 验证采集完整性
    missing = [k for k, v in collected.items() if v is None]
    if missing:
        print(f"  ⚠️ 部分字段采集失败: {missing}")
        result_log["steps"]["collect"] = {
            "status": "PARTIAL", "collected": collected, "missing": missing,
        }
    else:
        print(f"  ✅ 全部字段采集成功")
        result_log["steps"]["collect"] = {"status": "OK", "collected": collected}

    # ────────────────────────────────────────────────────────────
    # Step 4: 模拟算法调用（算法房间）
    # ────────────────────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print(f"🧠 Step 4/5: 算法房间 — 生成财报简报")
    print(f"{'─' * 60}")

    if collected.get("revenue") is None:
        print(f"  ❌ 采集数据不完整，无法生成简报")
        result_log["steps"]["algorithm"] = {"status": "SKIPPED"}
        return result_log

    # 模拟进入算法房间（展示算法步骤）
    for step in template.algorithm_room.steps:
        print(f"  🔹 执行算法步骤: [{step.type.value}] {step.description}")
        time.sleep(0.03)  # 模拟计算耗时

    # 调用简报生成算法
    brief = algorithm_generate_brief(company, year, collected)
    print(f"  📝 简报生成完成:\n{brief}")
    result_log["steps"]["algorithm"] = {"status": "OK", "brief": brief}

    # ────────────────────────────────────────────────────────────
    # Step 5: QueryGuardian 五层防护状态检查
    # ────────────────────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print(f"🛡️  Step 5/5: QueryGuardian 监控 — 五层防护实时状态")
    print(f"{'─' * 60}")

    # 获取各层统计数据
    engine_stats = guardian.engine.get_stats()
    bp_stats = guardian.backpressure.get_stats()
    mem_stats = guardian.memory_gc.get_stats()

    print(f"  🔹 第1层 - 渐进查询引擎: 总查询={engine_stats['total_queries']}, "
          f"缓存命中率={engine_stats['cache_hit_rate']:.1%}")
    print(f"  🔹 第2层 - 查询背压: 队列深度={bp_stats['queue_depth']}, "
          f"P99延迟={bp_stats['p99_latency_ms']}ms, "
          f"限流={bp_stats['throttled_count']}次")
    print(f"  🔹 第3层 - 内存GC: 用={mem_stats['total_memory_mb']:.1f}MB, "
          f"压缩={mem_stats['compressed_count']}次, "
          f"淘汰={mem_stats['total_evictions']}次")

    result_log["steps"]["guardian"] = {
        "status": "OK",
        "engine": engine_stats,
        "backpressure": bp_stats,
        "memory": mem_stats,
    }

    return result_log


# ============================================================================
# 6. 辅助函数：打印分隔线
# ============================================================================
def print_section(title: str, char: str = "=", width: int = 70):
    """打印带标题的分隔线区域。"""
    print(f"\n{char * width}")
    print(f"  {title}")
    print(f"{char * width}")


# ============================================================================
# 7. 辅助函数：打印 QueryGuardian 健康报告
# ============================================================================
def print_guardian_health_report(guardian: QueryGuardian):
    """
    以美观格式打印 QueryGuardian 的五层健康报告。
    """
    report = guardian.get_health_report()

    print_section("📊 Query Guardian — 五层防护健康报告", "═")

    layers = report.get("layers", {})
    for layer_key in [
        "1_progressive_engine",
        "2_backpressure",
        "3_memory_gc",
        "4_watchdog",
        "5_response_degrader",
    ]:
        stats = layers.get(layer_key, {})
        layer_label = layer_key.split("_", 1)[1].replace("_", " ").title()
        print(f"\n  🛡️  {layer_key}")
        # 选择性地展示关键指标
        key_fields = {
            "1_progressive_engine": ["total_queries", "cache_hits", "cache_hit_rate",
                                      "coarse_discarded", "generate_rate", "cache_size"],
            "2_backpressure": ["queue_depth", "avg_latency_ms", "p99_latency_ms",
                                "throttled_count", "throttle_rate", "is_under_pressure"],
            "3_memory_gc": ["total_memory_mb", "context_count", "compressed_count",
                             "total_evictions", "freed_mb"],
            "4_watchdog": ["total_registered", "timeout_count", "active_queries",
                            "timeout_rate", "timeout_seconds"],
            "5_response_degrader": ["total_responses", "degradation_rate",
                                     "current_level", "available_templates"],
        }
        for field in key_fields.get(layer_key, []):
            val = stats.get(field, "N/A")
            if isinstance(val, float):
                print(f"     {field}: {val:.4f}")
            elif isinstance(val, dict):
                # 嵌套 dict（如 response_counts）展开打印
                print(f"     {field}:")
                for sub_k, sub_v in val.items():
                    print(f"       {sub_k}: {sub_v}")
            elif isinstance(val, list):
                print(f"     {field}: {val}")
            else:
                print(f"     {field}: {val}")

    # 资源快照（如果有 psutil）
    if "resource" in report:
        res = report["resource"]
        print(f"\n  💻 系统资源:")
        print(f"     cpu_pct: {res.get('cpu_pct', 'N/A')}%")
        print(f"     mem_mb: {res.get('mem_mb', 'N/A'):.1f}MB" if isinstance(res.get('mem_mb'), float) else f"     mem_mb: {res.get('mem_mb', 'N/A')}")

    print(f"\n{'═' * 70}")


# ============================================================================
# 8. 主程序入口
# ============================================================================
def main():
    """
    Demo 主流程：依次演示三种场景。

    场景 A — 正常查询：腾讯控股 2023 年（白名单内，正常限流内）
    场景 B — 超限查询：比亚迪连续快速请求（触发 QueryBackpressure 限流）
    场景 C — 未授权查询：恒大集团（白名单外，AuthProxy 直接拒绝）
    """
    print_section("🏢 公司财报查询与简报生成 Demo", "█")
    print(f"  启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  框架版本: template_engine v1.0 | auth_proxy v1.0 | "
          f"precision_collector v1.0 | query_guardian v1.0")
    print(f"  模拟数据: {len(MOCK_FINANCIAL_DB)} 条记录 "
          f"({len(set(r['company'] for r in MOCK_FINANCIAL_DB))} 家公司 × 3 年)")

    # ========================================================================
    # 初始化全局组件
    # ========================================================================
    print_section("🔧 初始化全局组件", "─")

    # ---- AuthProxy：配置白名单 ----
    # 只有白名单内的 API 端点才能被查询
    # 使用静默审计处理器避免 stdout 杂乱，审计记录事后手动查看
    auth_proxy = AuthProxy(api_secret="demo-secret-key-2024")
    auth_proxy.audit_logger._handler = lambda line: None  # 静默模式

    # 添加白名单规则：允许财报 API
    auth_proxy.whitelist.add_rule(WhitelistRule(
        permission=Permission.READ,
        domain="api.finance.example.com",
        api_endpoint="/v1/reports",
        api_key_scopes=["read:financial_reports"],
        description="✅ 财报查询 API — 允许 READ 访问",
    ))
    # 添加一条低权限规则（故意不覆盖所有 scope）
    auth_proxy.whitelist.add_rule(WhitelistRule(
        permission=Permission.READ,
        domain="api.finance.example.com",
        api_endpoint="/v1/reports",
        api_key_scopes=["read:public_only"],          # 只能读公开数据
        description="⚠️ 公开财报 API — 仅限公开数据",
    ))
    print(f"  ✅ AuthProxy 已初始化，白名单规则数: {len(auth_proxy.whitelist.list_rules())}")
    for rule in auth_proxy.whitelist.list_rules():
        print(f"     [{rule['index']}] {rule['description']} "
              f"(domain={rule['domain']}, scope={rule['api_key_scopes']})")

    # ---- PrecisionCollector：初始化采集器 ----
    collector = PrecisionCollector()
    print(f"  ✅ PrecisionCollector 已初始化")

    # ---- QueryGuardian：启动五层防护 ----
    guardian = QueryGuardian(
        coarse_max_items=500,
        fine_max_items=30,
        generate_max_items=3,
        backpressure_max_queue=10,            # 演示用小阈值，便于触发限流
        backpressure_warn_queue=5,            # 队列 > 5 就开始预警
        backpressure_p99_threshold_ms=300.0,  # P99 阈值 300ms
        memory_soft_limit_mb=200.0,
        memory_hard_limit_mb=500.0,
        watchdog_timeout_seconds=5.0,
    )
    guardian.start()
    # 设置财报 API 来源限流：每秒最多 2 次请求
    guardian.backpressure.set_source_limit("financial_api", 2.0)
    print(f"  ✅ QueryGuardian 已启动（五层防护全部就绪）")
    print(f"     per-source 限流: financial_api = 2 QPS")

    # ========================================================================
    # 场景 A：正常查询
    # ========================================================================
    print_section("🟢 场景 A: 正常查询 — 腾讯控股 2023 年财报", "█")

    result_a = execute_query_pipeline(
        company="腾讯控股",
        year=2023,
        auth_proxy=auth_proxy,
        collector=collector,
        guardian=guardian,
        scenario_label="正常查询",
    )

    # 通过 guardian.ask() 再跑一次，让 guardian 的五层防护记录统计数据
    resp_a = guardian.ask("腾讯控股 2023 年财报查询", source="financial_api")
    print(f"\n  🛡️ Guardian.ask() 返回:")
    print(f"     降级级别: {resp_a.level.name} ({resp_a.level.value})")
    print(f"     是否降级: {resp_a.is_degraded}")
    print(f"     回答摘要: {resp_a.answer[:100]}..." if len(resp_a.answer) > 100 else f"     回答: {resp_a.answer}")

    # ========================================================================
    # 场景 B：超限查询
    # ========================================================================
    print_section("🟡 场景 B: 超限查询 — 比亚迪连续 8 次快速请求", "█")

    # 先手动给队列加压 + 消费令牌以触发限流
    print(f"  💥 模拟高频请求（financial_api 限流 2 QPS，连续发 8 次）...")
    result_b_list = []
    for i in range(8):
        # 通过 guardian.ask() 触发背压检查
        resp = guardian.ask(
            f"比亚迪财报查询 第{i+1}次",
            source="financial_api",              # 走 financial_api 限流通道
        )
        status_icon = "✅" if not resp.is_degraded else "⚠️ 降级"
        print(f"  第{i+1}次: 级别={resp.level.name:10s} | "
              f"降级={str(resp.is_degraded):5s} | {status_icon} | "
              f"原因={resp.degrade_reason or '正常'}")
        result_b_list.append({
            "seq": i + 1,
            "level": resp.level.name,
            "degraded": resp.is_degraded,
        })

    # 再跑一次完整的 pipeline 对比（正常数据查询）
    result_b = execute_query_pipeline(
        company="比亚迪",
        year=2024,
        auth_proxy=auth_proxy,
        collector=collector,
        guardian=guardian,
        scenario_label="超限查询后",
    )

    # ========================================================================
    # 场景 C：未授权查询
    # ========================================================================
    print_section("🔴 场景 C: 未授权查询 — 恒大集团（不在白名单内）", "█")

    # 构造一个不在白名单范围内的查询上下文
    unauthorized_context = {
        "domain": "api.unauthorized-finance.com",   # ❌ 不在白名单
        "api_endpoint": "/v2/secret_reports",       # ❌ 不在白名单
        "action": QueryAction.API_CALL.value,
        "scope": "read:secret_data",                # ❌ 不在白名单 scope
        "subject": "unknown_user",
        "request_id": "req_evergrande_2023",
    }

    allowed, reason = auth_proxy.check_permission(
        unauthorized_context,
        required_permission=Permission.READ,
    )

    print(f"\n  查询上下文:")
    print(f"    domain      = {unauthorized_context['domain']}")
    print(f"    api_endpoint= {unauthorized_context['api_endpoint']}")
    print(f"    scope       = {unauthorized_context['scope']}")
    print(f"\n  白名单校验结果:")
    print(f"    ✅/❌ allowed: {allowed}")
    print(f"    原因: {reason}")

    # 同时展示审计日志（最近 5 条）
    print(f"\n  📜 审计日志（最近 5 条）:")
    for entry in auth_proxy.audit_logger.recent_entries(5):
        event = entry.get("event", "?")
        result = entry.get("result", "?")
        resource = entry.get("resource", "?")
        ts = entry.get("timestamp", "?")
        print(f"    [{ts}] {event:20s} → {result:7s} | {resource}")

    # ========================================================================
    # 最终展示：QueryGuardian 健康报告
    # ========================================================================
    print_guardian_health_report(guardian)

    # ========================================================================
    # 汇总
    # ========================================================================
    print_section("📋 Demo 总结", "█")
    print(f"""
  场景 A（正常查询）:
    模板加载 → ✅ | 白名单 → ✅ | 采集 → ✅ | 算法 → ✅ | 监控 → ✅
    腾讯控股 2023 年年报正常产出简报。

  场景 B（超限查询）:
    模板加载 → ✅ | 白名单 → ✅ | 采集 → ✅ | 算法 → ✅ | 监控 → ⚠️
    比亚迪连续 8 次请求触发 Backpressure 限流，部分请求被降级。

  场景 C（未授权查询）:
    模板加载 → ✅ | 白名单 → ❌ (拒绝) | 采集 → ⛔ | 算法 → ⛔ | 监控 → ⛔
    恒大集团不在白名单，AuthProxy 直接拦截，后续流程不执行。

  五层防护总结:
    第1层 渐进查询引擎 — 正常运作
    第2层 查询背压       — 已触发限流（场景B）
    第3层 内存GC         — 正常回收
    第4层 查询看门狗     — 无超时
    第5层 回答降级       — 已触发降级（场景B）
""")

    # ---- 清理 ----
    guardian.stop()
    print(f"  ✅ QueryGuardian 已停止，Demo 完成。")
    print(f"{'█' * 70}")


# ============================================================================
# 入口
# ============================================================================
if __name__ == "__main__":
    main()
