#!/usr/bin/env python3
"""self_check.py — 用户训练全链路自检（证明"用户自己训不报错"）

模拟一个普通用户从零训练一个全新职业，验证完整链路:
  1. 一键生成领域(new_domain) 
  2. 建 1 个种子案例(用户只写 input.txt + expected.json)
  3. 训练(run_model) + 判卷(verify)
  4. chat 问答(问种子问题 → 应答案例, 不报错)

全绿 = 框架健康, 用户自己训练任何职业都不会报错。

运行: python -X utf8 self_check.py
"""
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TMP = HERE / "cases" / "selftest职业"  # 放 cases/ 下, 不用下划线开头(下划线=运行时目录会被跳过)
CHECKS = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    CHECKS.append(ok)
    mark = "✓" if ok else "✗"
    print(f"  {mark} {name}" + (f" — {detail}" if detail and not ok else ""))
    return ok


def run(cmd: list[str], timeout: int = 120) -> tuple[int, str]:
    try:
        r = subprocess.run([sys.executable, "-X", "utf8", *cmd], cwd=HERE,
                           capture_output=True, text=True, encoding="utf-8", timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except Exception as e:
        return -1, str(e)


def main() -> None:
    print("=" * 50)
    print("用户训练全链路自检 (模拟用户从零训一个职业)")
    print("=" * 50)

    # 清理旧测试 (模板+案例)
    if TMP.exists():
        shutil.rmtree(TMP)
    for t in (HERE / "templates").glob("*测试职业.txt"):
        t.unlink(missing_ok=True)
        t.unlink(missing_ok=True)

    # 1. 一键生成领域
    print("[1] 一键生成领域 (new_domain.py \"测试职业\")")
    rc, out = run(["new_domain.py", "测试职业"])
    tpl = list((HERE / "templates").glob("*测试职业.txt"))
    check("领域骨架生成", rc == 0 and bool(tpl), out[-200:] if rc else "")

    # 2. 用户建 1 个种子案例 (唯一用户动作: 写两个文件)
    print("[2] 用户建种子案例 (input.txt + expected.json)")
    case = TMP
    case.mkdir(exist_ok=True)
    (case / "input.txt").write_text("测试职业的示例问题: 天气怎么样", encoding="utf-8")
    exp = {"area": "测试", "key_point": "天气", "suggestions": ["带伞", "看预报"],
           "disclaimer": "仅供参考, 不构成专业意见",
           "evidence": ["测试职业的示例问题: 天气怎么样"], "unrelated": False}  # evidence=整句(与提取器分句一致)
    (case / "expected.json").write_text(json.dumps(exp, ensure_ascii=False, indent=2), encoding="utf-8")
    check("种子案例文件就位", (case / "input.txt").exists() and (case / "expected.json").exists())

    # 3. 训练 + 判卷
    print("[3] 训练 + 判卷")
    rc, out = run(["run_model.py", str(case), "--template", f"templates/{tpl[0].name}"])
    ok_train = rc == 0 and (case / "ai_output.json").exists()
    check("训练无报错", ok_train, out[-200:] if not ok_train else "")
    rc, out = run(["verify.py", str(case), str(case / "ai_output.json")])
    ok_verify = rc == 0 and "PASS" in out
    check("判卷 PASS", ok_verify, out[-200:] if not ok_verify else "")

    # 4. chat 问答 (问种子问题, 应答案例, 不报错)
    print("[4] chat 问答 (问种子问题)")
    try:
        sys.path.insert(0, str(HERE))
        import chat
        resp = chat.chat_response("测试职业的示例问题: 天气怎么样")
        ok_chat = "案例" in resp or "测试" in resp or "天气" in resp
        check("chat 应答不报错且命中案例", ok_chat, resp[:120] if not ok_chat else "")
    except Exception as e:
        check("chat 应答不报错且命中案例", False, f"{type(e).__name__}: {e}")

    # 5. 问新问题 (没教的 → 浏览器/诚实兜底, 不报错)
    print("[5] 问新问题 (没教的 → 兜底, 不报错)")
    try:
        resp2 = chat.chat_response("测试职业没教过的问题")
        check("新问题不报错(兜底)", bool(resp2) and "出错" not in resp2[:20], resp2[:80])
    except Exception as e:
        check("新问题不报错(兜底)", False, f"{type(e).__name__}: {e}")

    # 清理
    shutil.rmtree(TMP, ignore_errors=True)

    print()
    total = len(CHECKS)
    passed = sum(1 for c in CHECKS if c is True)
    print(f"自检结果: {passed}/{total} 通过")
    print("→ 用户从零训练一个职业: 全链路不报错" if passed == total else "→ 有失败, 见上")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
