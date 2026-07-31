#!/usr/bin/env python3
"""梦新 实例验证器 — 把"思考"变成可执行的判卷。

它不是学生，是老师。判卷依据全部来自纯文本文件：
  cases/<name>/input.txt      原始情报（原文，evidence 的裁判）
  cases/<name>/expected.json  老师答案（null 语义 = "原文没有，必须为 null/unknown"）

判卷规则：
  1. 结构    实际输出必须包含 expected 的全部字段，且类型一致
  2. null 语义  expected 中为 null 的字段 → 实际必须为 null/""/"unknown"
               （模型若凭背景知识填值 = 编造来源，违反红线 4）
  3. 值语义   expected 中非 null 的字段 → 实际必须匹配
               summary/notes 等自由文本字段仅检查非空；*.id 为自由标识符仅检查非空
  4. evidence 红线  实际输出的每条 evidence 必须是 input.txt 原文的子串
               （空白归一化后比较）——改写/美化/编造一律 FAIL
  5. unrelated  实际不得与 expected 矛盾
  6. dict 列表（如 findings）逐键递归比较，不做整串归一化——
     id 等自由标识符的合理差异（如加源前缀）不判 FAIL

用法：
  python verify.py <case_dir> <actual_output.json>
退出码 0 = 通过，1 = 未通过（供 CI 或训练循环判断）。
"""

import json
import re
import sys
from pathlib import Path

# Windows 控制台默认 GBK，强制 UTF-8 输出避免中文乱码
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# 自由文本字段：只要求非空，不要求与 expected 逐字一致
LOOSE_FIELDS = {"summary", "notes"}


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", str(s)).strip()


def verify_curiosity(act: dict, case_name: str, problems: list[str]) -> None:
    """好奇心专项判卷：开放结构，不逐字比较，只检查纪律。

    - 推测必须标注（speculative 措辞不得像事实）→ E08
    - 无事件时不得发散 causes/concepts，缺口必须可行动 → E09
    - honesty 必须自证（speculation_marked 为 true，计数不低于实际 speculative 数）
    """
    c = act.get("curiosity")
    if not isinstance(c, dict):
        problems.append(f"[{case_name}] 缺少 curiosity 结构")
        return
    for key in ("causes", "concepts", "gaps"):
        if key not in c or not isinstance(c[key], list):
            problems.append(f"[{case_name}] curiosity.{key} 应为数组")
            return

    # 形态 A：因果假设纪律
    SPEC_MARKERS = ("可能", "推测", "待验证", "或许", "疑似", "probably", "possibly", "likely", "unverified")
    n_spec = 0
    for i, h in enumerate(c.get("causes", [])):
        if not isinstance(h, dict) or not norm(h.get("hypothesis", "")) or "status" not in h:
            problems.append(f"[{case_name}] causes[{i}] 缺少 hypothesis/status")
            continue
        status = h.get("status")
        if status not in ("confirmed", "inferred", "speculative"):
            problems.append(f"[{case_name}] causes[{i}].status 非法: {status!r}")
        if status == "speculative":
            n_spec += 1
            if not any(m in norm(h.get("hypothesis", "")) for m in SPEC_MARKERS):
                problems.append(
                    f"[{case_name}] causes[{i}] 标注 speculative 但措辞像事实: {h.get('hypothesis')!r} — E08 推测伪装成事实"
                )

    # 形态 C：缺口必须可行动；无事件时禁止发散
    for i, g in enumerate(c.get("gaps", [])):
        if not isinstance(g, dict):
            problems.append(f"[{case_name}] gaps[{i}] 应为对象")
            continue
        for field in ("gap", "why_needed", "action"):
            if not norm(g.get(field, "")):
                problems.append(f"[{case_name}] gaps[{i}].{field} 为空 — 缺口探测必须可行动 (E09)")

    ev = act.get("event")
    if ev in (None, "", "null"):
        if c.get("causes") or c.get("concepts"):
            problems.append(
                f"[{case_name}] 无事件却给出 causes/concepts — 形态 C 只应输出 gaps (E09 无纪律发散)"
            )

    # honesty 自证
    h = act.get("honesty")
    if not isinstance(h, dict) or h.get("speculation_marked") is not True:
        problems.append(f"[{case_name}] honesty.speculation_marked 必须为 true")
    else:
        sc = h.get("speculations_count")
        if isinstance(sc, int) and sc < n_spec:
            problems.append(
                f"[{case_name}] honesty.speculations_count={sc} 小于实际 speculative 数 {n_spec} — 计数不诚实"
            )


def main() -> None:
    if len(sys.argv) != 3:
        print("用法: python verify.py <case_dir> <actual_output.json>")
        sys.exit(2)

    case_dir = Path(sys.argv[1])
    actual_path = Path(sys.argv[2])
    case_name = case_dir.name

    input_text = (case_dir / "input.txt").read_text(encoding="utf-8")
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    actual = json.loads(actual_path.read_text(encoding="utf-8"))

    problems: list[str] = []

    def check_field(key: str, exp, act) -> None:
        # dict：递归逐键，缺字段在递归处检查
        if isinstance(exp, dict):
            if not isinstance(act, dict):
                problems.append(f"[{case_name}] 字段 {key} 类型应为 dict, 实际 {type(act).__name__}")
                return
            for k, v in exp.items():
                if k not in act:
                    problems.append(f"[{case_name}] 缺少字段 {key}.{k} (期望: {v!r})")
                else:
                    check_field(f"{key}.{k}", v, act[k])
            return
        # list：逐项比较（归一化后）
        if isinstance(exp, list):
            if not isinstance(act, list):
                problems.append(f"[{case_name}] 字段 {key} 类型应为 list, 实际 {type(act).__name__}")
                return
            # dict 列表（如 findings）：逐键递归比较，不做整串归一化
            # （整串比较会把 id 等自由标识符的合理差异误判为 FAIL）
            if exp and isinstance(exp[0], dict):
                if len(exp) != len(act):
                    problems.append(
                        f"[{case_name}] 字段 {key} 长度不匹配: 期望 {len(exp)}, 实际 {len(act)}"
                    )
                    return
                for i, (ee, aa) in enumerate(zip(exp, act)):
                    if not isinstance(aa, dict):
                        problems.append(f"[{case_name}] 字段 {key}[{i}] 应为 dict, 实际 {type(aa).__name__}")
                        continue
                    for k, v in ee.items():
                        if k not in aa:
                            problems.append(f"[{case_name}] 字段 {key}[{i}] 缺少 {k} (期望: {v!r})")
                        else:
                            check_field(f"{key}[{i}].{k}", v, aa[k])
                return
            en, an = [norm(x) for x in exp], [norm(x) for x in act]
            for x in en:
                if x not in an:
                    problems.append(f"[{case_name}] 字段 {key} 缺少期望项 {x!r} (实际: {an!r})")
            for x in an:
                if x not in en:
                    problems.append(f"[{case_name}] 字段 {key} 出现多余项 {x!r} (期望: {en!r})")
            return
        # 标量：null 语义 / 值语义
        if exp is None:
            if act not in (None, "", "unknown", "null"):
                problems.append(
                    f"[{case_name}] 字段 {key} 期望 null(原文没有), 实际 {act!r} — 疑似背景知识污染 (红线 4)"
                )
        elif isinstance(exp, bool):
            if act is not exp:
                problems.append(f"[{case_name}] 字段 {key} 值不匹配: 期望 {exp!r}, 实际 {act!r}")
        elif isinstance(exp, str):
            if exp == "unknown":
                if act not in ("unknown", None, ""):
                    problems.append(f"[{case_name}] 字段 {key} 期望 unknown, 实际 {act!r}")
            elif key in LOOSE_FIELDS or key.endswith(".summary") or key.endswith(".notes"):
                if not norm(act):
                    problems.append(f"[{case_name}] 字段 {key} 为空 (自由文本至少写一句)")
            elif key.endswith(".id"):
                # id 是自由标识符：只要非空即可，允许合理差异（如加源前缀）
                if not norm(act):
                    problems.append(f"[{case_name}] 字段 {key} 为空 (id 至少写一个)")
            elif norm(act) != norm(exp):
                problems.append(f"[{case_name}] 字段 {key} 值不匹配: 期望 {exp!r}, 实际 {act!r}")
        elif isinstance(exp, (int, float)):
            if act != exp:
                problems.append(f"[{case_name}] 字段 {key} 值不匹配: 期望 {exp!r}, 实际 {act!r}")
        else:
            if act != exp:
                problems.append(f"[{case_name}] 字段 {key} 不匹配: 期望 {exp!r}, 实际 {act!r}")

    # 规则 1/2/3：逐字段判卷（缺字段在顶层检查）
    # 好奇心实例：开放结构走专项判卷，避免逐字比较误伤
    if "curiosity" in expected:
        # event 判卷分两种语义:
        #   期望有事件 → 实际必须非空且覆盖期望的 CVE(防张冠李戴)
        #   期望无事件(null/空) → 实际必须为空(无事件却编 event = 编造)
        exp_ev, act_ev = expected.get("event"), actual.get("event")
        if exp_ev in (None, "", "null"):
            if act_ev not in (None, "", "null"):
                problems.append(f"[{case_name}] 无事件却填了 event: {act_ev!r}")
        else:
            if not norm(str(act_ev or "")):
                problems.append(f"[{case_name}] event 为空")
            else:
                m = re.search(r"CVE-\d{4}-\d{4,}", str(exp_ev))
                if m and m.group() not in str(act_ev):
                    problems.append(f"[{case_name}] event 未覆盖期望事件 {m.group()}")
        verify_curiosity(actual, case_name, problems)
    else:
        for k, v in expected.items():
            if k not in actual:
                problems.append(f"[{case_name}] 缺少字段 {k} (期望: {v!r})")
            else:
                check_field(k, v, actual[k])

    # 规则 4：evidence 逐字红线
    ev_list = actual.get("evidence") if isinstance(actual.get("evidence"), list) else []
    in_norm = norm(input_text)
    for i, ev in enumerate(ev_list):
        if norm(ev) not in in_norm:
            problems.append(f"[{case_name}] evidence[{i}] 不是原文逐字引用: {ev!r} — 违反红线 4")

    # 规则 5：unrelated 一致性
    if "unrelated" in expected and "unrelated" in actual and expected["unrelated"] != actual["unrelated"]:
        problems.append(
            f"[{case_name}] unrelated 与期望矛盾: 期望 {expected['unrelated']}, 实际 {actual['unrelated']}"
        )

    if problems:
        print(f"✗ FAIL — {case_name}: {len(problems)} 个问题")
        for p in problems:
            print("   " + p)
        sys.exit(1)
    print(f"✓ PASS — {case_name}: {len(expected)} 个字段与 evidence 校验全部通过")
    sys.exit(0)


if __name__ == "__main__":
    main()
