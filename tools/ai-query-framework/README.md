# AIQuery — 模板化 AI 查询编排框架

> **AI = Query + Call，不是"思考"**

AIQuery 是一个轻量级、模板驱动的 AI 查询编排框架。它将"调用 AI"重新定义为两个正交的操作——**构建查询（Query）** 与**发起调用（Call）**——并用可组合的模板将二者解耦。你不写 prompt 字符串，你组装查询管道。

---

## 核心架构

六层流水线架构，每一层只做一件事，层与层之间通过不可变数据载体（QueryContext）传递，就像 Python 的 `contextvars` 那样贯穿整个调用链，但它是显式的。

```
                        ┌──────────────────────────────────────────┐
                        │          QueryGuardian 监控层             │
                        │  日志 · 指标 · 追踪 · 告警 · 审计        │
                        │  (类比: Python logging + OpenTelemetry)  │
                        └────┬─────┬─────┬─────┬─────┬─────────────┘
                             │     │     │     │     │
                             ▼     ▼     ▼     ▼     ▼
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│  模板层   │──▶│ 查询编排层 │──▶│ 权限代理层 │──▶│ 精准采集层 │──▶│ 算法黑箱层 │
│          │   │          │   │          │   │          │   │          │
│ Jinja2-  │   │ 管道组合  │   │ 沙箱代理  │   │ 多源归集  │   │ 策略屏蔽  │
│ 风格模板  │   │ 条件分支  │   │ 权限裁剪  │   │ 缓存分层  │   │ 黑箱替换  │
│ 变量注入  │   │ 重试/降级 │   │ 审计透传  │   │ 去重归并  │   │ 实现无关  │
│          │   │          │   │          │   │          │   │          │
│ 类比:    │   │ 类比:    │   │ 类比:    │   │ 类比:    │   │ 类比:    │
│ Python   │   │ JS       │   │ Python  │   │ JS       │   │ Python   │
│ Jinja2   │   │ RxJS     │   │ Proxy   │   │ Promise  │   │ abc.ABC  │
│          │   │ pipe()   │   │ 对象     │   │ .all()   │   │          │
└──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘
     │              │              │              │              │
     ▼              ▼              ▼              ▼              ▼
  模板编译      执行计划        Capability      数据源          模型
  变量解析      节点调度        Context         适配器          Adapter
                                                           
  ─────────────────────────────────────────────────────────────────
                     QueryContext（不可变数据载体）
  ─────────────────────────────────────────────────────────────────
```

### 各层职责

| 层 | 职责 | Python 类比 | JavaScript 类比 |
|---|---|---|---|
| **模板层** | 将提示词抽象为可复用模板，支持变量插值、条件块、循环。模板编译一次，多次渲染。 | Jinja2 `Template.render()` | Handlebars / Mustache |
| **查询编排层** | 将多个查询模板组装成有向无环图（DAG），定义执行顺序、条件分支、重试策略。 | Airflow DAG | RxJS `pipe()` |
| **权限代理层** | 在每个查询节点前插入沙箱检查，裁剪 capability、注入审计水印、记录调用链。 | `Proxy` 对象拦截 | `Proxy` + `Reflect` |
| **精准采集层** | 多数据源并行采集、去重、归并，L1→L2→L3 三级缓存策略。 | `asyncio.gather()` | `Promise.all()` |
| **算法黑箱层** | 将具体模型实现封装在 Adapter 之后，允许无感切换 provider。 | `abc.ABC` / `Protocol` | Duck typing / Interface |
| **QueryGuardian** | 贯穿全部五层的横切监控：日志、指标、追踪、告警、审计日志。 | `logging` + OpenTelemetry | `winston` + OpenTelemetry |

---

## 五层查询防护对照

AIQuery 的防护体系直接对应 `protect_plass` 的五层防护模型。每一层都从一个"检测 → 响应"的守护循环，转化为"策略 → 执行"的查询管道阶段。

```
protect_plass 守护循环                    AIQuery 查询管道阶段
═══════════════════════                  ═══════════════════════

DynamicSampler                          渐进式查询
 ┌──────────┐                            ┌──────────┐
 │ 采样决策  │                           │ L1 缓存   │  ← 命中即返回
 └────┬─────┘                            └────┬─────┘
      ▼                                       ▼
 ┌──────────┐                            ┌──────────┐
 │ 降级采样  │                           │ L2 粗筛   │  ← 结构化查询
 └────┬─────┘                            └────┬─────┘
      ▼                                       ▼
 ┌──────────┐                            ┌──────────┐
 │ 全量采集  │                           │ L3 精筛   │  ← 语义检索
 └──────────┘                            └────┬─────┘
                                               ▼
                                          ┌──────────┐
                                          │ 生成回答  │  ← 仅必要时调用 LLM
                                          └──────────┘

BackpressureGuard                       查询背压与限流
 ┌──────────┐                            ┌──────────┐
 │ 队列长度  │ ───────────────────────▶  │ 令牌桶    │  最大并发令牌数
 │ 拒绝策略  │ ───────────────────────▶  │ 滑动窗口  │  时间窗口内最大请求数
 │ 降级返回  │ ───────────────────────▶  │ 队列缓冲  │  溢出→降级回答
 └──────────┘                            └──────────┘

MemoryGuard                             上下文内存 GC
 ┌──────────┐                            ┌──────────┐
 │ 阈值检测  │ ───────────────────────▶  │ 水位线    │  max_tokens 硬上限
 │ 强制回收  │ ───────────────────────▶  │ 滑动摘要  │  旧消息 → 摘要压缩
 │ 拒绝分配  │ ───────────────────────▶  │ 早期截断  │  上下文窗口保护
 └──────────┘                            └──────────┘

Watchdog                                查询看门狗
 ┌──────────┐                            ┌──────────┐
 │ 心跳检测  │ ───────────────────────▶  │ 超时计时  │  单次查询 deadline
 │ 无响应杀  │ ───────────────────────▶  │ 重试上限  │  最大 retry 次数
 │ 复活重启  │ ───────────────────────▶  │ 熔断器    │  连续失败 → 短路
 └──────────┘                            └──────────┘

GracefulDegrade                         回答降级
 ┌──────────┐                            ┌──────────┐
 │ 能力检测  │ ───────────────────────▶  │ 降级策略  │  主模型→备模型→规则
 │ 功能裁剪  │ ───────────────────────▶  │ 部分回答  │  "我无法完整回答，但…"
 │ 通知用户  │ ───────────────────────▶  │ 降级标记  │  response.meta.degraded
 └──────────┘                            └──────────┘
```

### 对照速查表

| protect_plass 守护 | 本质 | AIQuery 查询阶段 | 触发条件 |
|---|---|---|---|
| `DynamicSampler` | 采样率自适应 | **渐进式查询** (缓存→粗筛→精筛→生成) | 每次查询自动分层 |
| `BackpressureGuard` | 入口流量控制 | **查询背压与限流** (令牌桶 + 滑动窗口) | 并发 / QPS 超阈值 |
| `MemoryGuard` | 运行时内存保护 | **上下文内存 GC** (水位线 + 滑动摘要) | 上下文 token 逼近上限 |
| `Watchdog` | 进程存活监控 | **查询看门狗** (超时 + 熔断) | 单次调用超时 / 连续失败 |
| `GracefulDegrade` | 服务降级 | **回答降级** (主→备→规则) | 主模型不可用 / 超预算 |

---

## 与 protect_plass 的概念类比

两个项目共享同一套系统可靠性哲学，但作用域不同：

| 概念维度 | protect_plass | AIQuery | 类比说明 |
|---|---|---|---|
| **保护对象** | Python 运行时进程 | AI 查询管道 | 一个是 OS 级守护，一个是应用级守护 |
| **"内存"** | 堆内存 (MB/GB) | 上下文窗口 (tokens) | 本质都是有限资源，需要 GC |
| **"采样"** | 数据点采样率 | 查询精度层级 | 都是"用更少的代价逼近全量结果" |
| **"背压"** | 数据摄入速率 | 查询发起速率 | 都是上游过快时保护下游 |
| **"看门狗"** | 进程心跳 | 查询超时 | 都是"无响应则重启/重试" |
| **"降级"** | 功能裁剪 | 回答精度降级 | 都是"做不到最好就给次好" |
| **信号机制** | `SIGTERM` / `SIGKILL` | 超时信号 / 熔断信号 | 类比 OS 信号系统 |
| **守护进程** | `systemd` / `supervisord` | QueryGuardian 横切监控 | 类比进程管理器 |
| **资源配额** | `cgroups` (CPU/Mem) | 令牌桶 (QPS/并发) | 类比 Linux cgroups |

核心洞见：**protect_plass 保护的是"算力容器"（Python 进程），AIQuery 保护的是"智力容器"（LLM 调用管道）。二者的防护模式是同构的。**

---

## 绝对红线

以下四条是 AIQuery 的宪法级约束，任何 PR、配置变更、插件开发都不得违反：

### 红线 1：不做自主决策

```
❌ 禁止: 框架自行决定"是否调用 LLM"、"用哪个模型"
✅ 要求: 一切决策由模板中的显式规则和配置驱动
```

AIQuery 类比 Python 的 `subprocess.run()`——它只负责按照你给定的参数执行调用，从不替你做决定。它是 hammer，不是 carpenter。

### 红线 2：不持有密钥

```
❌ 禁止: 框架代码中硬编码任何 API key、token、credential
✅ 要求: 所有密钥通过环境变量 / 密钥管理服务注入
```

就像你不会把 `AWS_ACCESS_KEY_ID` 写死在 `git add` 的代码里一样，AIQuery 框架本身不包含任何密钥。

### 红线 3：不静默吞错

```
❌ 禁止: try-except-pass、静默重试、丢弃错误信息
✅ 要求: 所有错误必须被记录、可追踪、最终传播到调用方
```

类比 JavaScript 的 `unhandledRejection`——未处理的错误是最危险的错误。AIQuery 确保每一个异常都有一条审计轨迹。

### 红线 4：不伪造来源

```
❌ 禁止: 修改或隐藏模型返回的原始数据、对来源信息进行"美化"
✅ 要求: response.meta 中保留完整的 provider、model、latency、token 用量
```

每一个 `QueryResponse` 对象都有一个 `.meta` 属性（类比 HTTP 响应头），其中记录了：哪个 provider、哪个 model、多少 ms、多少 tokens。审计时不会出现"这段话是 GPT-4 还是 Claude 说的？"这种问题。

---

## 许可证

```
AIQuery — 模板化 AI 查询编排框架
Copyright (C) 2025  AIQuery Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

**AGPL-3.0 的含义（简明版）：** 你可以自由使用、修改、分发 AIQuery。如果你通过网络提供基于 AIQuery 的服务（SaaS），你必须将修改后的完整源代码开放给用户。这是"网络自由"条款——AGPL 之于 SaaS，如同 GPL 之于二进制分发。

---

## 项目结构

```
ai-query-framework/
├── README.md                    # ← 本文件
├── LICENSE                      # AGPL-3.0
│
├── src/
│   ├── template/                # 模板层
│   │   ├── engine.py            #   Jinja2 风格模板引擎
│   │   ├── compiler.py          #   模板编译 → AST
│   │   └── variables.py         #   变量解析器
│   │
│   ├── orchestrator/            # 查询编排层
│   │   ├── dag.py               #   有向无环图定义
│   │   ├── scheduler.py         #   节点调度器
│   │   ├── retry.py             #   重试策略 (指数退避等)
│   │   └── pipeline.py          #   管道组合器
│   │
│   ├── proxy/                   # 权限代理层
│   │   ├── sandbox.py           #   沙箱执行环境
│   │   ├── capability.py        #   Capability 裁剪
│   │   └── audit.py             #   审计日志与水印
│   │
│   ├── collector/               # 精准采集层
│   │   ├── sources.py           #   多数据源适配
│   │   ├── cache.py             #   L1/L2/L3 三级缓存
│   │   ├── dedup.py             #   去重归并
│   │   └── merger.py            #   结果聚合
│   │
│   ├── adapter/                 # 算法黑箱层
│   │   ├── base.py              #   AbstractAdapter (abc.ABC)
│   │   ├── openai.py            #   OpenAI Adapter
│   │   ├── anthropic.py         #   Anthropic Adapter
│   │   └── registry.py          #   Adapter 注册表
│   │
│   ├── guardian/                # QueryGuardian 监控层
│   │   ├── monitor.py           #   横切监控入口
│   │   ├── metrics.py           #   指标收集
│   │   ├── tracer.py            #   分布式追踪
│   │   └── alerter.py           #   告警规则
│   │
│   └── core/
│       ├── context.py           #   QueryContext (不可变数据载体)
│       ├── types.py             #   核心类型定义
│       └── errors.py            #   异常层次结构
│
├── config/
│   ├── default.yaml             #   默认配置
│   ├── guardians.yaml           #   防护策略配置
│   └── adapters.yaml            #   Adapter 注册配置
│
├── tests/
│   ├── test_template.py
│   ├── test_orchestrator.py
│   ├── test_proxy.py
│   ├── test_collector.py
│   ├── test_adapter.py
│   └── test_guardian.py
│
├── docs/
│   ├── architecture.md          #   详细架构文档
│   ├── template-guide.md        #   模板编写指南
│   └── deployment.md            #   部署指南
│
└── demo/
    ├── basic_query.py           #   最简示例
    ├── pipeline_demo.py         #   多步管道示例
    └── degrade_demo.py          #   降级策略示例
```

---

## 快速开始

### 安装

```bash
# 从源码安装（开发模式）
git clone https://github.com/aiquery/ai-query-framework.git
cd ai-query-framework
pip install -e ".[dev]"
```

### 你的第一个查询：30 秒上手

```python
from aiquery import Query, Template, AdapterRegistry
from aiquery.guardian import QueryGuardian

# 1. 定义模板——这是你的 prompt，不再是一段裸字符串
template = Template("""
你是一个 {{ role }}。
请用不超过 {{ max_words }} 个字回答：
{{ question }}
""")

# 2. 创建一个查询，绑定模板和参数
query = Query(template).with_vars(
    role="Python 专家",
    max_words=50,
    question="什么是 GIL？"
)

# 3. 选择模型适配器（算法黑箱层）
adapter = AdapterRegistry.get("openai/gpt-4o-mini")

# 4. 用 QueryGuardian 包裹所有调用
guardian = QueryGuardian(
    timeout_ms=30_000,      # 看门狗：30 秒超时
    max_tokens=4096,        # 内存 GC：上下文上限
)

# 5. 渐进式查询（自动走 L1→L2→L3→生成）
response = guardian.run(query, adapter=adapter)

# 6. 拿到结构化响应
print(response.text)          # 模型回答文本
print(response.meta.model)    # "gpt-4o-mini"
print(response.meta.latency)  # 1234 (ms)
print(response.meta.tokens)   # {"input": 42, "output": 18}
```

### 组装管道：多步查询

```python
from aiquery import Pipeline, Query

pipeline = (
    Pipeline("research_pipeline")
    .add_step("检索相关文档",   Query(doc_search_tpl))
    .add_step("提取关键信息",   Query(extract_tpl),    depends=["检索相关文档"])
    .add_step("生成最终回答",   Query(summarize_tpl),  depends=["提取关键信息"])
    .with_guardian(default_guardian)
    .with_fallback(             # 降级策略：主模型挂了用备选
        primary="openai/gpt-4o",
        fallback="anthropic/claude-haiku",
    )
)

response = pipeline.run(question="量子纠缠如何用于加密？")
```

### YAML 配置驱动

```yaml
# config/guardians.yaml
guardians:
  default:
    timeout_ms: 30_000
    max_tokens: 4096
    retry:
      max_attempts: 3
      backoff: exponential      # 指数退避，类比 Python tenacity
    circuit_breaker:
      failure_threshold: 5      # 连续 5 次失败 → 熔断
      recovery_seconds: 60      # 60 秒后尝试恢复
    backpressure:
      max_concurrency: 10       # 最大并发查询
      rate_limit_per_sec: 20    # 每秒最多 20 个查询
```

---

## 设计哲学

> **AIQuery 不相信 AI 会"思考"。**
>
> 它相信的是：每一个 AI 调用都可以被建模为一次"查询"（Query），然后像一个 HTTP 请求一样被路由、缓存、限流、重试、降级、监控。
>
> 这和 protect_plass 守护 Python 进程的方式完全一样——只不过 protect_plass 守护的是字节和 CPU 周期，而 AIQuery 守护的是 token 和上下文窗口。

---

*Built with the belief that AI infrastructure deserves the same rigor as any other distributed systems infrastructure.*
