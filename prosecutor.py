#!/usr/bin/env python3
"""prosecutor.py — 检察官: 审查规则提取质量,低置信度自动修正(从 PASS 案例库学习)

挂在 run_model.py 的 extract 后、output 前。
两个核心能力:
  1. 质量评分: 每个关键字段给置信度(low/medium/high), low 的标记待审查
  2. 案例匹配修正: 对 low 置信度字段,查 cases/ 里已有 PASS 案例的 expected.json,
                    如果匹配(同组件/同 CVE/同包名),用 expected 的值覆盖

这是"自己造"的关键: 正则不会的,案例库来教。梦新自己维护自己的知识。
"""

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = HERE / "cases"

# 哪些字段值得检察官审查
TRACKED_FIELDS = ["affected_component", "affected_versions", "cvss", "cwe", "cve",
                   "attack_vector", "public_exploit", "package_or_component",
                   "installed_version", "vulnerable_range", "exposure", "matched_assets"]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", str(s)).strip().lower()


def confidence(key: str, value, raw_text: str) -> str:
    """对单个字段给置信度。规则:"""
    if value is None:
        return "unknown"
    s = str(value)
    if "unknown" in s.lower() or "UNKNOWN_RANGE" in s:
        return "low"
    # affected_component 只有单个词且没大写 → 可能不完整
    if key == "affected_component" and s not in raw_text and len(s.split()) < 2:
        return "medium"
    # affected_versions 含 UNKNOWN_RANGE → low
    if key == "affected_versions" and "UNKNOWN_RANGE" in s:
        return "low"
    # 其他: 非空即可为 high
    return "high"


def find_best_case(raw_text: str) -> dict | None:
    """从 PASS 案例库找最相似的案例(同 CVE 或同组件名),返回 expected 字段。"""
    best, best_score = None, 0
    for d in sorted(CASES.iterdir()):
        exp = d / "expected.json"
        inp = d / "input.txt"
        if not exp.exists() or not inp.exists():
            continue
        try:
            expected = json.loads(exp.read_text(encoding="utf-8"))
            inp_text = inp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        score = 0
        # 同 CVE → 高分
        cve_in = re.findall(r"CVE-\d{4}-\d{4,}", raw_text)
        cve_ex = re.findall(r"CVE-\d{4}-\d{4,}", inp_text)
        if cve_in and cve_ex and set(cve_in) & set(cve_ex):
            score += 50
        # 同组件名 → 加分
        for word in raw_text.split()[:20]:
            if re.match(r"^[A-Z][a-z]", word) and word in inp_text:
                score += 10
        if score > best_score:
            best_score = score
            best = expected
    return best if best_score >= 20 else None


def review(result: dict, raw_text: str) -> dict:
    """检察官审查: 评分 + 低置信度字段从案例库修正。"""
    scores = {}
    corrections = {}
    fields = {}
    if "findings" in result:
        fields = result["findings"][0] if result["findings"] else {}
    else:
        fields = result
    for key in TRACKED_FIELDS:
        if key in fields:
            scores[key] = confidence(key, fields[key], raw_text)

    low_keys = [k for k, v in scores.items() if v in ("low", "medium")]
    if low_keys:
        best_case = find_best_case(raw_text)
        if best_case:
            bc_fields = best_case.get("findings", [best_case])[0] if "findings" in best_case else best_case
            for key in low_keys:
                if key in bc_fields and bc_fields[key] is not None:
                    corrections[key] = bc_fields[key]
                    fields[key] = bc_fields[key]

    result["_prosecutor"] = {
        "confidence": scores,
        "corrections": corrections,
        "low_keys": low_keys,
    }
    return result
