# 梦新 — 用户训练的 AI(架构驱动,不依赖大厂模型)

> 训练方式：**纯文本**。不写框架代码、不调外部 API。
> 它的全部行为来自用户训练的规则/模板/实例/判卷/反馈。
> 外部 LLM 是可选适配器(就像自行车可加电助力),不接也能跑。
> 原名: VulnHunter。2026-07-31 更名为梦新。

---

## 它是什么

**架构驱动的 AI**——行为 = 规则引擎 + 模板编译器 + 判卷器 + 自愈 + 防护：

- **不依赖大厂 API**：一切都是用户训练的文本规则。AI = 架构,不是 API 调用壳。
- **思考 = 实例 → 输出 → 判卷 → 错误 → 修正 → 再验证**：训练循环已到第七轮。
- **两条腿走路**：外部漏洞情报(CVE/扫描器)+ 内部环境(CI 扫描/资产清单)。
- **五层防护同构**：来自 protect_plass,落地为 guard.py(防注入)+ heal.py(自愈)+ QueryGuardian。

## 训练循环

```
实例(cases/) → 规则提取(run_model.py 纯架构) → 判卷(verify.py) → 归因(E-code) → 修正(改规则) → 重跑 → 沉淀(feedback_log)
```

外部 LLM 可挂进 L3 层(--external-model),但默认不依赖。

## 红线(五条纪律)

1. **不做自主决策**——修正动作来自显式规则表(heal_rules.txt/rules.txt)
2. **不持有密钥**——0 依赖
3. **不静默吞错**——guard_log/heal_log/audit_log 全程可追溯
4. **不伪造来源**——未知填 null/unknown,evidence 逐字引用
5. **不违法**——架构自有,不依赖大厂 API,无侵权风险

## 文件地图

```
vuln-hunter/
├── TRAINING.md                    # 本手册(训练操作)
├── INTELLIGENCE.md                # 灵魂定义 + 差距清单
├── UPGRADE.md                     # 全面升级方案(废弃检查后)
├── verify.py                      # 老师:可执行判卷器(字段/null/evidence 红线)
├── run_model.py                   # 规则提取引擎(纯架构,零 API 依赖)
├── analyze.py                     # 狩猎管道主框架(ingest/L2/L3/severity/alert/audit + 感知/行动/回归接口)
├── heal.py                        # 监察官自动修复器(FAIL→归因→注入→重跑→装死/熔断)
├── heal_rules.txt                 # 监察官修复手册(E-code→症状→目标→注入→tolerate)
├── heal_log.txt                   # 自动修复审计
├── guard.py                       # 监察官防护层(输入净化防注入/输入验证/输出验证)
├── guard_log.txt                  # 可疑输入/输出审计
├── audit_log.jsonl                # 审计归档
├── templates/                     # 模板(知识)
│   ├── 01_vuln_analysis.txt
│   ├── 02_severity_factors.txt
│   ├── 03_internal_scan.txt
│   ├── 04_exploit_chain.txt
│   └── 05_curiosity.txt
├── rules.txt                      # 纪律(路由/分级/告警)
├── pipeline.txt                   # 狩猎流程(文本 DAG,analyze.py 是其落地)
├── sources.txt                    # 感官(数据源清单)
├── cases/                         # 实例库
│   ├── CVE-2021-44228/
│   ├── internal-pip-audit/
│   └── curiosity-{event,gap}/
├── errors.txt                     # 错题本(E01-E09:症状→修正→验证)
├── examples.txt                   # 教材(正/反例)
├── feedback_log.txt               # 训练历史(已到第七轮)
└── tools/                         # 导入工具集
    ├── ai-query-framework/        #   AIQuery 六层编排框架(allquery;纯 Python)
    └── runtime-guardian/          #   eBPF 运行时防护(project-plass;Linux 内核,环境不兼容)
```

## 快速开始(纯架构,零密钥)

```bash
# 规则提取
python run_model.py cases/CVE-2021-44228

# 判卷
python verify.py cases/CVE-2021-44228 cases/CVE-2021-44228/ai_output.json

# 管道全流程
python analyze.py cases/CVE-2021-44228

# 全量回归
python analyze.py --regression
```

> 梦新不调任何外部 API,不需要密钥。架构就是 AI 本身。
