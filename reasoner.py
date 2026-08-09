#!/usr/bin/env python3
"""reasoner.py — 外置推理 AI（纯架构, 零 API）

像教官训练 Reasonix 那样训练它:
  - 规则库(内置公式/解法, 纯 Python, 零 API)
  - 案例库(用户/教官喂新题型: input=题目, expected=答案+步骤)
  - 记忆体(推理知识沉淀, 追加不覆盖)
  - 判卷(答案校验)

用法:
  python reasoner.py "200的15%是多少"     # 推理入口
  或 import reasoner; reasoner.reason("...")

训练新题型(案例驱动):
  cases/reasoner-<题型>/
    input.txt       # 题目模板(含变量示例)
    expected.json   # {"answer": "答案", "steps": ["步骤"]}
  喂了案例后, reason 先查案例库匹配同类题。
"""
import json
import math
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = HERE / "reasoner_cases"


# ============ 规则库 (内置公式, 零 API) ============
def _solve_rules(text: str) -> dict | None:
    """规则引擎: 内置数学公式. 算出→{answer,steps,type}; 算不出→None."""
    t = text.replace(" ", "")
    r = {"type": None, "answer": None, "steps": []}

    # 1. 一元一次方程
    m = None
    if "x^2" not in t and "x²" not in t:
        m = re.search(r"([-+]?[\d.]+)x([-+])([\d.]+)=([-+]?[\d.]+)", t)
    if not m and "x^2" not in t and "x²" not in t:
        m = re.search(r"([-+]?[\d.]+)x=([-+]?[\d.]+)", t)
        if m:
            a, c = float(m.group(1)), float(m.group(2))
            if a != 0:
                x = c / a
                return {"type": "一元一次方程", "answer": f"x={x:g}", "steps": [f"{a}x={c}", f"x={c}/{a}", f"x={x:g}"]}
    elif m:
        a, op, b, c = float(m.group(1)), m.group(2), float(m.group(3)), float(m.group(4))
        if a != 0:
            x = (c - b) / a if op == "+" else (c + b) / a
            return {"type": "一元一次方程", "answer": f"x={x:g}",
                    "steps": [f"{a:g}x{op}{b:g}={c:g}", f"x=({c:g}{'-' if op=='+' else '+'}{b:g})/{a:g}", f"x={x:g}"]}

    # 2. 二次方程
    m = re.search(r"([-+]?[\d.]*)x\^2([-+]?[\d.]*)x([-+]?[\d.]+)=0", t)
    if m:
        def _f(s):
            if s in ("", "+"): return 1.0
            if s == "-": return -1.0
            return float(s)
        a, b, c = _f(m.group(1)), _f(m.group(2) or "+1"), float(m.group(3))
        disc = b * b - 4 * a * c
        if disc >= 0:
            x1 = (-b + math.sqrt(disc)) / (2 * a)
            x2 = (-b - math.sqrt(disc)) / (2 * a)
            return {"type": "一元二次方程", "answer": f"x={x1:g} 或 x={x2:g}",
                    "steps": [f"Δ={disc:g}", f"x=(-b±√Δ)/2a", f"x={x1:g} 或 {x2:g}"]}

    # 3. 求导
    terms = re.findall(r"([-+]?[\d.]*x(?:\^\d+)?)", t)
    if terms and re.search(r"求导|导数|微分", t):
        derivs = []
        for term in terms:
            m2 = re.match(r"([-+]?[\d.]*)(x)(?:\^(\d+))?", term)
            if m2:
                coeff_s, exp_s = m2.group(1), m2.group(3)
                coeff = 1.0 if coeff_s in ("", "+") else (-1.0 if coeff_s == "-" else float(coeff_s))
                exp = int(exp_s) if exp_s else 1
                if exp > 0:
                    ncoeff, nexp = coeff * exp, exp - 1
                    term_d = f"{ncoeff:g}x" if nexp == 1 else (f"{ncoeff:g}" if nexp == 0 else f"{ncoeff:g}x^{nexp}")
                    derivs.append(term_d)
        if derivs:
            return {"type": "求导", "answer": " + ".join(derivs).replace("+ -", "- "),
                    "steps": ["d/dx(x^n)=nx^(n-1)"] + [f"d/dx({term})" for term in terms]}

    # 4. 定积分
    m = re.search(r"∫(\d+)到(\d+)\s*(x)(?:\^(\d+))?", t)
    if m:
        a, b = float(m.group(1)), float(m.group(2))
        n = int(m.group(4)) if m.group(4) else 1
        val = (b ** (n + 1) - a ** (n + 1)) / (n + 1)
        return {"type": "定积分", "answer": f"{val:g}" if val == int(val) else f"{val:.4f}",
                "steps": [f"∫x^{n}dx=x^{n+1}/({n+1})", f"[{b:g}^{n+1}-{a:g}^{n+1}]/({n+1})", f"={val:g}"]}

    # 5. 极限
    m = re.search(r"lim\s*x→(∞|\d+)\s*([^,，。]*)", t)
    if m:
        to, expr = m.group(1), m.group(2)
        if to == "∞" and re.search(r"1/x", expr):
            return {"type": "极限", "answer": "0", "steps": ["lim x→∞ 1/x = 0"]}
        if to == "0" and re.search(r"sin\s*x\s*/\s*x", expr):
            return {"type": "极限", "answer": "1", "steps": ["lim x→0 sinx/x = 1"]}

    # 6. 等差数列求和
    m = re.search(r"等差[^\d]*?(\d+)[^\d]*?(\d+)[^\d]*?(\d+)", t)
    if m and ("等差" in t or "数列" in t):
        a1, n, d = float(m.group(1)), float(m.group(2)), float(m.group(3))
        an = a1 + (n - 1) * d
        S = n * (a1 + an) / 2
        return {"type": "等差数列求和", "answer": f"{S:g}",
                "steps": [f"an=a1+(n-1)d={an:g}", f"S=n(a1+an)/2={S:g}"]}

    # 7. 百分比/折扣
    m = re.search(r"(\d+)[的的]*([\d.]+)%", t)
    if m and "%" in t:
        base, pct = float(m.group(1)), float(m.group(2))
        val = base * pct / 100
        return {"type": "百分比", "answer": f"{val:g}", "steps": [f"{base:g}×{pct:g}%={val:g}"]}
    m = re.search(r"打([\d.]+)折", t)
    if m:
        disc = float(m.group(1))
        return {"type": "折扣", "answer": f"{disc:g}折=原价×{disc/10:g}", "steps": [f"打{disc:g}折=原价×{disc/10:g}"]}

    # 8. 勾股定理
    m = re.search(r"(?:直角|勾股)[^\d]*(\d+)[^\d]*(\d+)", t)
    if m and ("直角" in t or "勾股" in t or "斜边" in t):
        a, b = float(m.group(1)), float(m.group(2))
        c = math.sqrt(a * a + b * b)
        return {"type": "勾股定理", "answer": f"{c:.4f}", "steps": [f"c=√({a:g}²+{b:g}²)", f"={c:.4f}"]}

    # 9. 概率
    m = re.search(r"掷[^\d]*(\d+)面[^\d]*出(\d+)", t)
    if m:
        faces = int(m.group(1))
        return {"type": "概率", "answer": f"1/{faces}", "steps": [f"P=1/{faces}"]}

    # 10. 单位换算
    m = re.search(r"(\d+(?:\.\d+)?)\s*(km/h|kg)", t)
    if m:
        val, unit = float(m.group(1)), m.group(2)
        if unit == "km/h":
            return {"type": "单位换算", "answer": f"{val/3.6:.4f} m/s", "steps": [f"{val:g}km/h÷3.6={val/3.6:.4f}m/s"]}
        if unit == "kg":
            return {"type": "单位换算", "answer": f"{val*1000:g} g", "steps": [f"{val:g}kg×1000={val*1000:g}g"]}

    return None


# ============ 案例库 (用户/教官喂新题型) ============
_CASE_CACHE = None


def _load_cases():
    """加载 reasoner_cases/: 案例 = 题型+解法 (可训练)."""
    global _CASE_CACHE
    if _CASE_CACHE is None:
        _CASE_CACHE = []
        if CASES.exists():
            for d in sorted(CASES.iterdir()):
                inp = d / "input.txt"
                exp = d / "expected.json"
                if inp.exists() and exp.exists():
                    try:
                        _CASE_CACHE.append({"name": d.name,
                                            "input": inp.read_text(encoding="utf-8"),
                                            "expected": json.loads(exp.read_text(encoding="utf-8"))})
                    except Exception:
                        pass
    return _CASE_CACHE


def _case_match(text: str):
    """案例匹配: 题目与案例共享数字/运算符模式(同类题)."""
    t = text.replace(" ", "")
    nums = set(re.findall(r"\d+", t))
    for c in _load_cases():
        cnums = set(re.findall(r"\d+", c["input"]))
        # 同类题: 共享运算符 + 至少1个数字结构(把数字替换为N后相同)
        t_pat = re.sub(r"\d+", "N", t)
        c_pat = re.sub(r"\d+", "N", c["input"].replace(" ", ""))
        if t_pat == c_pat:
            return c
    return None


# ============ 推理入口 ============
def reason(text: str) -> dict:
    """外置推理: 规则库 → 案例库 → 诚实不会. 零 API."""
    # 1. 规则库(内置公式)
    r = _solve_rules(text)
    if r:
        return {"solved": True, "source": "rules", **r}
    # 2. 案例库(同类题) — 仅识别题型; 数字不同不抄答案(红线: 不编造)
    c = _case_match(text)
    if c:
        # 数字完全一致 → 直接返回案例答案
        if set(re.findall(r"\d+", text)) == set(re.findall(r"\d+", c["input"])):
            return {"solved": True, "source": f"case:{c['name']}",
                    "answer": c["expected"].get("answer"),
                    "steps": c["expected"].get("steps", [])}
        # 数字不同 → 同类题但需重算, 诚实说明
        return {"solved": False, "source": f"case:{c['name']}(同类)",
                "answer": None, "steps": [],
                "note": f"这是{c['name']}同类题, 但数值不同需重算 — 教我具体解法, 我能推出"} 
    # 3. 诚实不会
    return {"solved": False, "source": None, "answer": None, "steps": [],
            "note": "规则库和案例库都不会 — 告诉我答案, 我可以记住(建案例)"}


def main():
    q = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "200的15%是多少"
    r = reason(q)
    print(f"题目: {q}")
    if r["solved"]:
        print(f"类型: {r['type']} (来源: {r['source']})")
        for s in r.get("steps", []):
            print(f"  步骤: {s}")
        print(f"答案: {r['answer']}")
    else:
        print(f"不会: {r.get('note')}")


if __name__ == "__main__":
    main()
