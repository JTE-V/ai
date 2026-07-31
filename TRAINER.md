# 梦新 教练手册 — 如何把它训练成正常 AI

> 不写框架代码、不调大厂 API、不改权重。
> 你教的每一条,都写进文本文件——模板、规则、案例、判卷、反馈。

---

## 一、训练循环(核心方法,一条命令)

```
创建案例 → 让它跑 → 判卷 → FAIL→归因→修正→重跑 PASS→沉淀
```

### 1.1 创建训练案例

```bash
# 案例目录结构
mkdir -p cases/我的新案例
echo "CVE-2024-xxxx: 一段漏洞原文描述..." > cases/我的新案例/input.txt
```

### 1.2 跑梦新

```bash
python run_model.py cases/我的新案例
# → 输出 cases/我的新案例/ai_output.json
```

### 1.3 判卷

```bash
python verify.py cases/我的新案例 cases/我的新案例/ai_output.json
# PASS → 下一个案例
# FAIL → 看什么问题,进入修正
```

### 1.4 修正规则

| FAIL 症状 | 改哪里 |
|---|---|
| 字段该 null 却填了值(背景知识污染) | 改 `templates/` 对应模板,加"只依据输入原文,原文没有填 null" |
| evidence 不是原文逐字 | 改模板 evidence 规则 |
| 组件名提取错 | 改 `run_model.py` 的 `_detect_component` |
| 版本区间提取错 | 改正则或 `extract_v01` |
| 漏报/误报 | 改 `rules.txt` severity 或 alert 规则 |

### 1.5 重跑 + 沉淀

```bash
python run_model.py cases/我的新案例   # 用修正后的规则重跑
python verify.py cases/我的新案例 cases/我的新案例/ai_output.json
# PASS → 手动追加 feedback_log,或让 auto_learn 自动记
```

---

## 二、自动学习(不用一条条跑,梦新自己扫)

```bash
# 一次性: 扫 cases/ 全部案例,自动 提取→判卷→自愈→沉淀
python auto_learn.py --once

# 守护模式: 每 30 秒扫一次,发现新案例自动学
python auto_learn.py --interval 30
```

新案例扔进 `cases/`,梦新自己捡起来。

---

## 三、聊天室训练(最自然的方式)

```bash
python chat.py
```

### 3.1 教它新知识

```
你> 教你怎么查 CISA KEV
梦新> 请给我: input: [原文] expected: [期望输出 JSON]

你> input: CVE-2021-44228 in CISA KEV since 2021
    expected: {"cve":"CVE-2021-44228","kev":true}
梦新> 学到了。
```

### 3.2 直接给训练素材(不用先说"教")

```
你> input: CVE-xxx: [原文] expected: {"cve":"CVE-xxx","cvss":9.8}
梦新> 学到了。
```

### 3.3 用它已有的知识

```
你> OpenSSH
梦新> CVE-2024-6387: CVSS 8.1 / CWE-364 (本地缓存)

你> 你会什么
梦新> 我是梦新——纯架构 AI...
```

---

## 四、让它自己上网学

聊天室里它自己后台 30 秒跑一次,会自动:
1. 上网抓 NVD 最近 24h 的新 CVE(零 key,免费)
2. 发现 cases/ 里有新案例就分析
3. 缺字段自动查 NVD/OSV 补全
4. FAIL 自动 heal(注入规则修正)
5. 结果全部沉淀到 feedback_log

你什么都不用干,它自己涨知识。

---

## 五、判定标准

| E-code | 症状 | 修正 |
|---|---|---|
| E01 | 原文没有的字段填了值(背景知识污染) | 模板加"只依据原文" |
| E02 | evidence 改写/美化 | 模板加"逐字引用" |
| E03 | 输出直接写等级 | 模板加"只输出因素" |
| E04 | 版本判断错 | rules.txt severity 节 |
| E05 | 告警不对 | rules.txt alert 节 |
| E06 | 强行匹配不存在的资产 | 模板加"进 unmatched" |
| E07 | 无关内容却输出了漏洞 | 模板加 unrelated 分支 |
| E08 | 推测伪装成事实 | templates/05 加标注纪律 |
| E09 | 缺口不可行动 | templates/05 加三字段要求 |

---

## 六、日常命令速查

```bash
# 健康自检
python auto_learn.py --health

# 全量回归
python analyze.py --regression

# 单案例全管道
python analyze.py cases/<案例名>

# 聊天室
python chat.py

# 自动学习(守护)
python auto_learn.py --interval 30
```

---

## 七、进阶: 改架构

梦新的核心规则在这里,直接改文本文件:

| 文件 | 改什么 |
|---|---|
| `templates/01_vuln_analysis.txt` | 外部情报 JSON 格式和规则 |
| `templates/03_internal_scan.txt` | 内部扫描 JSON 格式和规则 |
| `templates/05_curiosity.txt` | 好奇心输出格式和纪律 |
| `rules.txt` | 路由/分级/告警规则 |
| `heal_rules.txt` | 自动修复映射(E-code→修正动作) |
| `guard.py` ALLOWED_KEYS | 输出字段白名单(加新字段时更新) |
| `run_model.py` _detect_component | 组件名提取规则 |
| `run_model.py` extract_v01/v03/v05 | 字段提取逻辑 |

改完跑 `python analyze.py --regression` 确认没误伤已有案例。

---

> **核心哲学**: 逻辑 = 行为协议 = 文本。AI 不是代码,是你写进这些文件里的规则。
> 案例越多 → 检察官越准 → 自动修正越强 → 知识越全。
> 八轮的训练历史全在 feedback_log.txt 里,每一刀怎么切的都看得见。
