#!/usr/bin/env python3
"""test_system.py — 梦新框架检测系统（一键检测整个框架健康）

检测项:
  1. 语法: 所有核心 .py 文件编译
  2. 领域: 每个模板 + 提取器 + 案例是否就位
  3. 判卷: 跑所有有 expected 的案例 → PASS/FAIL 统计
  4. chat 冒烟: 每个领域问代表问题 → 不报错
  5. 报告: 汇总 + 失败清单

运行: python -X utf8 test_system.py
"""
import json
import py_compile
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE_PY = ["run_model.py", "chat.py", "auto_learn.py", "verify.py", "analyze.py",
           "new_domain.py", "self_check.py", "prosecutor.py", "guard.py", "heal.py"]


def section(title: str) -> None:
    print(f"\n{'=' * 52}\n{title}\n{'=' * 52}")


def main() -> None:
    print("梦新框架检测系统")
    print(f"检测时间: {__import__('time').strftime('%Y-%m-%d %H:%M:%S')}")
    problems = []
    total_checks = 0

    # 1. 语法检测
    section("[1] 语法检测 (核心 .py 文件)")
    for f in CORE_PY:
        total_checks += 1
        try:
            py_compile.compile(str(HERE / f), doraise=True)
            print(f"  ✓ {f}")
        except Exception as e:
            problems.append(f"语法 {f}: {e}")
            print(f"  ✗ {f}: {e}")

    # 2. 领域检测
    section("[2] 领域检测 (模板 + 提取器 + 案例)")
    try:
        sys.path.insert(0, str(HERE))
        import run_model
        tpls = sorted((HERE / "templates").glob("*_*.txt"))
        for tpl in tpls:
            total_checks += 1
            stem = tpl.stem
            num, name = stem.split("_", 1)
            ok_ext = name in run_model.EXTRACTORS
            # 该领域的案例
            cases = [d for d in (HERE / "cases").iterdir()
                     if not d.name.startswith("_") and (d / "input.txt").exists()]
            print(f"  {'✓' if ok_ext else '✗'} {num}_{name}: 提取器{'有' if ok_ext else '缺'} | 案例 {len(cases)} 个")
            if not ok_ext:
                problems.append(f"领域 {name}: 提取器未注册")
    except Exception as e:
        problems.append(f"领域检测异常: {e}")
        print(f"  ✗ {e}")

    # 3. 判卷检测 (所有有 expected 的案例)
    section("[3] 判卷检测 (跑所有案例)")
    passed = failed = 0
    for d in sorted((HERE / "cases").iterdir()):
        if d.name.startswith("_") or not (d / "input.txt").exists() or not (d / "expected.json").exists():
            continue
        total_checks += 1
        # 用默认模板跑(或匹配领域模板)
        tpl = None
        inp = (d / "input.txt").read_text(encoding="utf-8", errors="ignore")
        for t in (HERE / "templates").glob("*_*.txt"):
            if t.stem.split("_", 1)[1] in d.name or d.name.startswith(t.stem.split("_", 1)[1]):
                tpl = t
                break
        if tpl is None:
            tpl = (HERE / "templates" / "01_vuln_analysis.txt")
        try:
            r1 = subprocess.run([sys.executable, "-X", "utf8", str(HERE / "run_model.py"),
                                 str(d), "--template", str(tpl)],
                                capture_output=True, text=True, encoding="utf-8", timeout=120)
            r2 = subprocess.run([sys.executable, "-X", "utf8", str(HERE / "verify.py"),
                                 str(d), str(d / "ai_output.json")],
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
            ok = "PASS" in r2.stdout
            passed += ok
            if not ok:
                failed += 1
                problems.append(f"判卷 {d.name}: {r2.stdout.strip().splitlines()[-1][:80]}")
            print(f"  {'✓' if ok else '✗'} {d.name}")
        except Exception as e:
            failed += 1
            problems.append(f"判卷 {d.name}: {type(e).__name__}")
            print(f"  ✗ {d.name}: {type(e).__name__}")
    print(f"  判卷汇总: {passed} PASS / {failed} FAIL")

    # 4. chat 冒烟 (每领域代表问题, 不报错)
    section("[4] chat 冒烟 (每领域代表问题)")
    try:
        import chat
        smoke = ["什么是自由", "解方程 2x+3=11", "画一幅黄昏海边的画", "Python 怎么读取 CSV", "我被抢劫了"]
        for q in smoke:
            total_checks += 1
            try:
                r = chat.chat_response(q)
                ok = bool(r) and "出错了" not in r[:20]
                print(f"  {'✓' if ok else '✗'} {q[:20]}")
                if not ok:
                    problems.append(f"chat冒烟 {q}: {r[:50]}")
            except Exception as e:
                problems.append(f"chat冒烟 {q}: {type(e).__name__}")
                print(f"  ✗ {q}: {type(e).__name__}")
    except Exception as e:
        problems.append(f"chat冒烟异常: {e}")

    # 5. 报告
    section("[5] 检测报告")
    ok_total = total_checks - len(problems)
    print(f"总检查: {total_checks} | 通过: {ok_total} | 问题: {len(problems)}")
    if problems:
        print("\n问题清单:")
        for p in problems[:20]:
            print(f"  ✗ {p}")
    else:
        print("\n✅ 全部通过 — 框架健康")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
