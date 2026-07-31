# 训练梦新 — 社区贡献指南

梦新是纯架构 AI,不调大厂 API,一切行为由**你写的案例和规则**决定。你的每一次训练,都是一条案例。

## 快速开始(3 步)

```bash
# 1. 创建案例: 写 input.txt(原始输入) + expected.json(期望输出)
mkdir -p cases/我的案例
echo '你的原始情报/代码/文本' > cases/我的案例/input.txt
echo '{"期望字段":"期望值"}' > cases/我的案例/expected.json

# 2. 让梦新学习
python run_model.py cases/我的案例

# 3. 判卷
python verify.py cases/我的案例 cases/我的案例/ai_output.json
```

PASS → 提交 PR。FAIL → 看症状改规则。

## 训练格式

一个案例 = 一个目录,含两个文件:

```
cases/案例名/
├── input.txt       # 原始输入: 漏洞情报/代码片段/任意文本
└── expected.json   # 期望梦新输出的 JSON(字段名+值)
```

### 漏洞情报案例

`input.txt`:
```
CVE-2024-xxxx: 一段漏洞描述...
```

`expected.json`:
```json
{
  "cve": "CVE-2024-xxxx",
  "affected_component": "组件名",
  "affected_versions": [">=1.0, <=2.0"],
  "cvss": 9.8,
  "cwe": "CWE-xxx",
  "evidence": ["原文片段"]
}
```

### 代码分析案例

`input.txt`:
```php
<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = $id";
```

`expected.json`:
```json
{
  "language": "PHP",
  "issues": [
    {
      "line": "1-2",
      "severity": "critical",
      "cwe": "CWE-89",
      "description": "SQL 注入",
      "fix": "使用预处理语句"
    }
  ],
  "notes": "..." 
}
```

## 判卷规则

| 字段是 null | 含义 |
|---|---|
| expected 中为 null | "原文没有,必须填 null,禁止编造" |
| expected 中为 "unknown" | "原文没有明确信息,必须 unknown" |

**红线**: evidence 必须逐字来自 input.txt。原文没有的字段填 null。

## 常见 FAIL → 怎么修

| fail 症状 | 改哪里 |
|---|---|
| 字段该 null 却填了值 | 改 `templates/` 对应模板,加"只依据原文" |
| 组件名提取错 | 改 `run_model.py` 的 `_detect_component` |
| 版本区间提取错 | 改 `run_model.py` 的 `extract_v01` |
| 漏报/误报 | 改 `rules.txt` |

## 提交 PR

```bash
python auto_learn.py --health    # 健康自检
python analyze.py --regression    # 全量回归(0失败)
git add cases/我的案例/
git commit -m "训练: 案例名"
```

案例越多 → 检察官越准 → 自动修正越强 → 梦新越强。
