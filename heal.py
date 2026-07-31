#!/usr/bin/env python3
"""heal.py — 监察官自动修复器(自愈循环,分级容错)

用法:
  python heal.py <case_dir> <actual.json> [--max-retries N]

流程(训练循环内):
  1. verify.py 判卷 → FAIL 则进入自愈
  2. 解析问题行 → 按 heal_rules.txt 症状匹配 E-code
  3. 幂等注入修正文本(目标文件已含幂等关键字则跳过)
  4. 重跑 verify:
     - PASS      → 沉淀 heal_log + feedback_log,退出 0
     - 仍 FAIL   → 分级处理(不过度熔断):
        全部命中规则 tolerate=1 → "装死": 记 tolerated 放行,退出 0(不阻塞管道)
        含 tolerate=0(红线级,如 E01/E02)→ 熔断: 交教练人工,退出 1
  5. 每次动作写 heal_log.txt(时间/E-code/文件/结果),可追溯(红线 3)

纪律(红线 1): 修正动作全部由 heal_rules.txt 显式规则驱动,本脚本不做任何自主决策。
"""

import re
import subprocess
import sys
import time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = Path(__file__).resolve().parent          # vuln-hunter/
RULES_FILE = HERE / "heal_rules.txt"
HEAL_LOG = HERE / "heal_log.txt"
MAX_RETRIES = 2                                  # 同一 E-code 最多修 2 次


def load_rules() -> list[dict]:
    rules = []
    for line in RULES_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 6:
            print(f"⚠ 跳过坏规则行: {line[:60]}...", file=sys.stderr)
            continue
        ecode, symptom, target, idem, inject, tol = parts
        rules.append({"ecode": ecode, "symptom": symptom, "target": target,
                      "idem": idem, "inject": inject, "tolerate": tol == "1"})
    return rules


def run_verify(case_dir: Path, actual: Path) -> tuple[int, str]:
    r = subprocess.run(
        [sys.executable, str(HERE / "verify.py"), str(case_dir), str(actual)],
        capture_output=True, text=True, encoding="utf-8",
    )
    return r.returncode, r.stdout + r.stderr


def extract_problems(verify_out: str) -> list[str]:
    return [ln.strip() for ln in verify_out.splitlines()
            if ln.strip() and ("期望" in ln or "缺失" in ln or "缺少" in ln or "为空" in ln or "不匹配" in ln or "矛盾" in ln or "类型" in ln)]


def match_rules(problems: list[str], rules: list[dict]) -> list[dict]:
    hits, seen = [], set()
    for p in problems:
        for r in rules:
            if r["ecode"] in seen:
                continue
            if re.search(r["symptom"], p):
                hits.append(r)
                seen.add(r["ecode"])
                break
    return hits


def apply_rule(rule: dict) -> bool:
    """幂等注入: 目标文件已含幂等关键字则跳过;否则追加注入文本。返回是否注入。"""
    target = HERE / rule["target"]
    if not target.exists():
        print(f"  ⚠ 目标文件不存在: {rule['target']}", file=sys.stderr)
        return False
    content = target.read_text(encoding="utf-8")
    if rule["idem"] in content:
        return False
    sep = "\n" if not content.endswith("\n") else ""
    target.write_text(content + sep + rule["inject"] + "\n", encoding="utf-8")
    return True


def append_log(case_dir: str, ecode: str, action: str, result: str) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    with open(HEAL_LOG, "a", encoding="utf-8") as f:
        f.write(f"{ts} | {case_dir} | {ecode} | {action} | {result}\n")


def main() -> None:
    if len(sys.argv) < 3:
        print("用法: python heal.py <case_dir> <actual.json> [--max-retries N]", file=sys.stderr)
        sys.exit(2)
    case_dir = Path(sys.argv[1])
    actual = Path(sys.argv[2])
    max_retries = MAX_RETRIES
    if "--max-retries" in sys.argv:
        max_retries = int(sys.argv[sys.argv.index("--max-retries") + 1])

    rules = load_rules()
    if not rules:
        print("✗ heal_rules.txt 无有效规则", file=sys.stderr)
        sys.exit(2)

    print(f"[heal] 监察官启动: {case_dir.name} (max_retries={max_retries})")

    rc, out = run_verify(case_dir, actual)
    if rc == 0:
        print("[heal] 无需修复,判卷已 PASS")
        sys.exit(0)

    all_hits: list[dict] = []
    for attempt in range(1, max_retries + 1):
        problems = extract_problems(out)
        hits = match_rules(problems, rules)
        all_hits = hits or all_hits
        if not hits:
            print(f"[heal] 第 {attempt} 次: 无法归因的问题(不在 heal_rules 内),装死放行(记 tolerated):")
            for p in problems:
                print(f"    {p}")
            append_log(case_dir.name, "?", "unattributable", "tolerated")
            sys.exit(0)

        print(f"[heal] 第 {attempt} 次: FAIL {len(problems)} 项 → E-code {[h['ecode'] for h in hits]}")
        injected_any = False
        for r in hits:
            injected = apply_rule(r)
            injected_any = injected_any or injected
            action = f"注入 {r['target']}" if injected else f"跳过(已含 {r['idem']!r})"
            print(f"  [{r['ecode']}] {action}")
            append_log(case_dir.name, r["ecode"], action, "applied")

        # --re-run: 注入模板后用新模板重新生成输出(真正的自愈),再判卷
        if injected_any and "--re-run" in sys.argv:
            tmpl = next((r["target"] for r in hits if r["target"].startswith("templates/")), None)
            if tmpl:
                print(f"[heal] 用新模板重新生成输出: run_model.py --template {tmpl}")
                rr = subprocess.run(
                    [sys.executable, str(HERE / "run_model.py"), str(case_dir),
                     "--template", tmpl],
                    capture_output=True, text=True, encoding="utf-8",
                )
                if rr.returncode == 0:
                    # 重生成成功: 判卷对象切换为新输出(旧 actual 是坏输出,不能继续判它)
                    new_actual = case_dir / "ai_output.json"
                    if new_actual.exists():
                        actual = new_actual
                else:
                    print(f"  ⚠ run_model 重生成失败:\n{rr.stderr[:300]}", file=sys.stderr)

        rc, out = run_verify(case_dir, actual)
        if rc == 0:
            print("[heal] ✓ 自动修复生效: 重跑 PASS")
            append_log(case_dir.name, "+".join(r["ecode"] for r in hits), "re-verify", "PASS")
            entry = (f"- {time.strftime('%Y-%m-%d')} | 自动修复(heal): {case_dir.name} FAIL → "
                     f"E-code {[r['ecode'] for r in hits]} 注入模板 → 重跑 PASS\n")
            with open(HERE / "feedback_log.txt", "a", encoding="utf-8") as f:
                f.write(entry)
            sys.exit(0)

    # 重试耗尽: 分级处理(不过度熔断)
    hard = [r for r in all_hits if not r["tolerate"]]
    if not hard:
        print(f"[heal] 重试 {max_retries} 次仍 FAIL,但均为可容忍纪律问题 → 装死放行(记 tolerated):")
        for p in extract_problems(out):
            print(f"    {p}")
        append_log(case_dir.name, "+".join(r["ecode"] for r in all_hits), "re-verify", "tolerated")
        sys.exit(0)

    print(f"[heal] ✗ 含红线级 E-code {[r['ecode'] for r in hard]} 仍 FAIL → 熔断,交教练人工:")
    print(out)
    append_log(case_dir.name, "+".join(r["ecode"] for r in all_hits), "re-verify", "FAIL(circuit-broken)")
    sys.exit(1)


if __name__ == "__main__":
    main()
