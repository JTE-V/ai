# UPGRADE.md — VulnHunter 全面升级方案（2026-07-31 废弃检查后）

> 背景：联网核查 + 本地实测，确认各依赖是否有"废弃/不支持"项，并给出从现状到
> "那个 AI"的全面升级路线。本文件是方案，不修改任何程序；执行需教练确认。

## 一、废弃/不支持检查结论

| 组件 | 核查方式 | 状态 | 结论 |
|---|---|---|---|
| DeepSeek API `deepseek-chat` | 联网文档 + **本地实测** | ⚠️ 官方已推 v4 系列；实测 `deepseek-chat` 与 `deepseek-v4-flash` **当前均可用**（2026-07-31） | **建议升级**默认模型为 `deepseek-v4-flash`（官方文档称 deepseek-chat 计划退役，属待退役风险） |
| bcc（project-plass 依赖） | 联网核查 | ✅ 未废弃：iovisor/bcc 活跃维护，v0.37.0（2026-07），apt `bpfcc-tools python3-bpfcc` 全系打包 | 短期可用；中长期生态推荐 libbpf+CO-RE（需 Linux 环境） |
| ai-query-framework 依赖 | 本地扫描 | ✅ 纯标准库（csv/gc/gzip/sqlite3/concurrent.futures），零第三方 | 无废弃 |
| vuln-hunter 自身 | 本地扫描 | ✅ 纯标准库 + urllib | 无废弃 |
| Python 3.12 | 环境 | ✅ 活跃 | 无废弃 |

### DeepSeek 升级要点（实测数据）
- `model="deepseek-v4-flash"` 实测可用；`deepseek-chat` 仍有效但官方已公告退役计划。
- ⚠️ v4 系列**默认 thinking 模式**（本次探测 v4-flash tokens=257 vs deepseek-chat=28，差 9 倍）。
  非推理任务必须传 `"thinking": {"type": "disabled"}` 关闭，否则流量/成本暴涨。
- 端点不变：`https://api.deepseek.com/chat/completions`，OpenAI 兼容格式，协议零改动。
- 参数注意：`frequency_penalty`/`presence_penalty` 官方已标 deprecated（本项目未用，无影响）。

## 二、立即升级（低风险，改一行，可回退）

1. `run_model.py` 默认 `--model deepseek-chat` → `deepseek-v4-flash`；
   同时 `call_deepseek` 增加 `"thinking": {"type": "disabled"}`（省流量）；
   `--model` 参数保留，可随时回退 `--model deepseek-chat`。
2. `analyze.py` 默认模型同步（它透传 `--model`，默认值改一致）。
3. 回归：`python analyze.py --regression` 确认 4 案例仍 PASS（会花 1-2 次真实调用验证新模型输出）。

## 三、短期（差距清单补齐，接口已挂）

1. **真实感知**：`analyze.collect_sources()` 落地 —— 接 **OSV.dev**（免费、无需 key、OpenAPI）
   `POST https://api.osv.dev/v1/query` 按包名/版本查漏洞 → 进管道 → guard 净化 → L3 分析。
   验证标准（INTELLIGENCE.md）：真实漏洞公告能进入管道并产出分析。
2. **真实行动**：`analyze.execute_action()` 落地 —— 告警决策 `immediate` 时真实触发
   （写告警文件/调通知接口），行动有日志与结果回填（红线 3）。
3. **记忆回放强化**：`--regression` 从"跑 verify"升级为"E-code 回归表"——
   每个 E-code 配一个最小触发案例，确保同类错误不再犯（回归测试闭环）。

## 四、中长期（架构演进）

1. **AIQuery 六层管道集成**：把 tools/ai-query-framework 的模板层/编排层/权限层/采集层/
   黑箱层/监控层对齐进 analyze.py（VulnHunter 管道与其哲学同源），减少自研重复。
2. **guard 防护扩充**：更多注入特征（多语言 prompt 注入）、输入规范校验（CVE 格式）、
   输出 schema 严格校验（模板 01/03/05 各自白名单）。
3. **heal 规则扩充**：E-code 扩充到 E10+（guard 拦截类、模型输出结构类）；
   自动修复从"注入模板"扩展到"自动更新 rules.txt 参数"。
4. **project-plass**：短期维持 bcc；中长期在 Linux/WSL 环境规划 libbpf+CO-RE 迁移
   （去除 clang/LLVM 运行时与 kernel-devel 依赖，跨内核稳定）。
   参考：https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/
5. **成本控制**：DeepSeek 高峰/非高峰定价（官方公告在途）→ 管道加"低危情报不进模型"
   已实现；再加"模型选择路由"（简单规则走 v4-flash，深度利用链走 v4-pro）。

## 五、风险与回退

- 升级默认模型后若输出变化：`--model deepseek-chat` 一键回退，模板无需改。
- thinking 模式若误开：token 暴涨（9x）→ 必须传 disabled；监控 `meta.total_tokens` 审计。
- bcc 迁移仅影响 project-plass（Linux 环境），不影响 vuln-hunter 主链。

> 执行原则：一次只改一处 → 回归 → 沉淀 feedback_log（训练纪律不变）。
