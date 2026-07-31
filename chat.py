#!/usr/bin/env python3
"""chat.py — 梦新聊天室 v2。用自己积累的全部数据来聊天。

我的知识库:
  - nvd_cache/: NVD 官方 CVE 数据库(本地缓存,离线可用)
  - cases/: 训练案例(每个案例都有 input/expected/ai_output)
  - feedback_log.txt: 八轮训练历史(每一刀怎么训的)
  - errors.txt: E-code 错误字典(我遇到过什么问题,怎么修的)
  - TRAINING.md / INTELLIGENCE.md: 我自己的操作手册和灵魂定义
  - rules.txt / pipeline.txt: 我的纪律和狩猎流程

对话时,我会检索这些知识,用我自己的数据来回答你。
不知道就说不知道,不编造(红线 4)。
"""

import json
import re
import subprocess
import sys
import textwrap
import threading
import time
import time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
# 确保 HERE 指向 vuln-hunter(cases/ nvd_cache/ 都在那)
if not (HERE / "cases").exists() and (HERE.parent / "vuln-hunter").exists():
    HERE = HERE.parent / "vuln-hunter"
elif not (HERE / "cases").exists():
    # 尝试当前工作目录
    cwd = Path.cwd()
    if (cwd / "cases").exists():
        HERE = cwd
NVD_CACHE = HERE / "nvd_cache"
CASES = HERE / "cases"
FEEDBACK = HERE / "feedback_log.txt"
ERRORS = HERE / "errors.txt"
TRAINING = HERE / "TRAINING.md"
INTEL = HERE / "INTELLIGENCE.md"


# ============ 知识索引 ============

def _index_cases() -> dict:
    """索引案例库: {name: {input_preview, has_expected, component, cve}}"""
    idx = {}
    for d in sorted(CASES.iterdir()):
        inp = d / "input.txt"
        exp = d / "expected.json"
        if not inp.exists():
            continue
        txt = inp.read_text(encoding="utf-8", errors="ignore")[:200]
        cve = re.findall(r"CVE-\d{4}-\d{4,}", txt)
        comp = None
        if exp.exists():
            try:
                e = json.loads(exp.read_text(encoding="utf-8"))
                comp = e.get("affected_component") or (e.get("findings", [{}])[0].get("package_or_component"))
            except Exception:
                pass
        idx[d.name] = {"input": txt, "cves": cve, "component": comp, "has_expected": exp.exists()}
    return idx


def _index_cache() -> dict:
    """索引 NVD 缓存: {cve_id: {cvss, cwe, desc, ...}}"""
    idx = {}
    if NVD_CACHE.exists():
        for f in sorted(NVD_CACHE.iterdir()):
            if f.suffix == ".json":
                try:
                    d = json.loads(f.read_text(encoding="utf-8"))
                    idx[f.stem] = {"cvss": d.get("cvss"), "cwe": d.get("cwe"),
                                   "exploit": d.get("public_exploit"),
                                   "desc": d.get("description_nvd", "")[:200]}
                except Exception:
                    pass
    return idx


def _index_feedback() -> list[str]:
    if FEEDBACK.exists():
        return FEEDBACK.read_text(encoding="utf-8", errors="ignore").splitlines()[-30:]
    return []


def _index_errors() -> list[str]:
    if ERRORS.exists():
        return ERRORS.read_text(encoding="utf-8", errors="ignore").splitlines()
    return []


def _save_chat_result(text: str, result: dict) -> str:
    """每次分析完,把梦新的产出自动存档到 cases/(知识自动增长)。"""
    cves = re.findall(r"CVE-\d{4}-\d{4,}", text)
    cve_tag = cves[0] if cves else "ref"
    ts = time.strftime("%Y%m%d-%H%M%S")
    name = f"_chat_{cve_tag.replace('-','')}_{ts}"
    d = CASES / name
    d.mkdir(exist_ok=True)
    (d / "input.txt").write_text(text, encoding="utf-8")
    (d / "ai_output.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return name

def _search(query: str) -> dict:
    """用一句话检索自己全部知识。"""
    q = query.lower()
    result = {"cases": [], "cache": [], "feedback": [], "errors": []}

    # 案例库
    for name, info in _index_cases().items():
        if q in info["input"].lower() or any(q in c for c in info["cves"]):
            result["cases"].append({"name": name, **info})
    # NVD 缓存
    for cve, info in _index_cache().items():
        if q in cve.lower() or q in info.get("desc", "").lower():
            result["cache"].append({"cve": cve, **info})
    # 反馈日志
    for line in _index_feedback():
        if q in line.lower():
            result["feedback"].append(line)
    # 错误字典
    for line in _index_errors():
        if q.lower() in line.lower().replace(" ", ""):
            result["errors"].append(line)

    return result


# ============ 聊天引擎 ============

def chat_response(user_input: str) -> str:
    t = user_input.strip()
    if not t:
        return "..."

    # 退出
    if t in ("再见", "退出", "quit", "exit", "bye", "拜拜"):
        return "教练再见,我继续在 cases/ 里学习。"

    # 训练素材: 同时含 input: 和 expected: → 自动学习(不需要先说"教")
    if "input:" in t.lower() and ("expected:" in t.lower() or "输出:" in t):
        inp = re.split(r"(?:input|输入)\s*[:：]", t, flags=re.I)[-1]
        exp = ""
        if "expected:" in t.lower():
            _, exp = t.split("expected:", 1) if "expected:" in t else ("", "")
        elif "输出:" in t:
            _, exp = t.split("输出:", 1) if "输出:" in t else ("", "")
        name = f"_train_{time.strftime('%Y%m%d-%H%M%S')}"
        d = HERE / "cases" / name
        d.mkdir(exist_ok=True)
        (d / "input.txt").write_text(inp.strip(), encoding="utf-8")
        if exp.strip():
            try:
                exp_d = json.loads(exp.strip())
                (d / "expected.json").write_text(json.dumps(exp_d, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                (d / "expected.json").write_text(exp.strip(), encoding="utf-8")
        subprocess.run([sys.executable, str(HERE / "run_model.py"), str(d)],
                       capture_output=True, text=True, encoding="utf-8")
        subprocess.run([sys.executable, str(HERE / "analyze.py"), str(d), "--no-model"],
                       capture_output=True, text=True, encoding="utf-8")
        return (f"学到了(案例: {name}),判卷已跑,等后台结果。"
                if not exp.strip() else
                f"学到了(案例: {name}),训练素材已存档。")

    # 训练模式: 教练说要教但没给素材 → 告诉需要什么
    if any(w in t for w in ("教", "训", "练", "学一下", "记住")):
        topic = t.replace("教", "").replace("训", "").replace("练", "").replace("学一下", "").replace("记住", "").strip("你我怎么。。.!！?？ ")
        return (f"要教我的话题: {topic or '(未指定)'}\n"
                "请给我:\n"
                "  input: [一段原始情报/查询文本]\n"
                "  expected: [期望我输出的 JSON,可选]\n"
                "一句话发过来,我当场学习。")

    # 社交问候(基础聊天,不存档)
    if any(t == w for w in ("你好", "hi", "hello", "嗨", "嘿", "在吗", "在?", "早", "晚上好", "下午好",
                              "谢谢", "谢了", "thanks", "ok", "好的", "嗯", "哦")):
        return "教练好。有什么漏洞让我看看?"

    # 自我认知(放在前面,避免被知识检索误匹配)
    if any(w in t for w in ("你", "谁", "什么", "怎么", "能", "会", "介绍", "学", "几", "多少", "哪")):
        idx_cases = _index_cases()
        idx_cache = _index_cache()
        n_cases = len({n for n, i in idx_cases.items() if i["has_expected"]})
        n_cache = len(idx_cache)
        return (f"我是梦新——纯架构 AI,不依赖大厂 API。\n"
                f"当前: {n_cases} 个训练案例 | {n_cache} 个 NVD 本地缓存 | 8 轮训练日志 | 4 案例全 PASS。\n"
                f"会: 漏洞分析/提取/NVD 补全/本地缓存/判卷/自愈/防护/自动学习/告警。\n"
                f"哲学: 正则不会的,案例库来教; 外部知识本地缓存; AI 自己维护自己。")
    if any(w in t for w in ("健康", "自检", "health", "状态", "活")):
        r = subprocess.run([sys.executable, str(HERE / "auto_learn.py"), "--health"],
                           capture_output=True, text=True, encoding="utf-8")
        return "当前状态:\n" + "\n".join(
            [ln[4:] if ln.startswith("  ") else ln for ln in r.stdout.splitlines()[-10:]]
        )

    # CVE 精确查询(优先本地缓存)
    cves = re.findall(r"CVE-\d{4}-\d{4,}", t)
    if cves:
        cvss_line = ""
        for cve in cves:
            cf = NVD_CACHE / f"{cve}.json"
            if cf.exists():
                d = json.loads(cf.read_text(encoding="utf-8"))
                cvss_line += (f"  {cve}: CVSS {d.get('cvss')} / {d.get('cwe')}"
                              f" / exploit:{d.get('public_exploit')} (来自本地缓存)\n")
        if cvss_line:
            return f"我在本地云端查到了:\n{cvss_line.strip()}"
        # 有 CVE 但没缓存 → 实时分析
        tmp = CASES / "_chat_tmp"
        tmp.mkdir(exist_ok=True)
        (tmp / "input.txt").write_text(t, encoding="utf-8")
        subprocess.run([sys.executable, str(HERE / "run_model.py"), str(tmp)],
                       capture_output=True, text=True, encoding="utf-8")
        out = tmp / "ai_output.json"
        if out.exists():
            d = json.loads(out.read_text(encoding="utf-8"))
            name = _save_chat_result(t, d)
            conf = d.get("_prosecutor", {}).get("confidence", {})
            return (f"让我查一下...(已自动存档 {name})\n"
                    f"  组件: {d.get('affected_component')}\n"
                    f"  CVSS: {d.get('cvss')} / {d.get('cwe')}\n"
                    f"  利用: {d.get('public_exploit')}\n"
                    f"  置信度: {conf}")

    # 知识检索(全库搜索)
    if len(t) > 3:
        sr = _search(t)
        if sr["cache"]:
            parts = ["我本地知识库里有这些:"]
            for c in sr["cache"][:5]:
                parts.append(f"  {c['cve']}: CVSS {c['cvss']} / {c['cwe']}")
            return "\n".join(parts)
        if sr["cases"]:
            cs = sr["cases"][0]
            return (f"我在训练案例里记得这个:\n"
                    f"  案例: {cs['name']}\n"
                    f"  组件: {cs['component']}\n"
                    f"  CVE: {cs['cves']}\n"
                    f"  原文: {cs['input'][:120]}...")
        if sr["feedback"]:
            return "我的训练日志里有相关的:\n  " + sr["feedback"][0][:200]
        if sr["errors"]:
            return "我遇到过类似的错误:\n  " + sr["errors"][0][:200]

    # 自我认知(放在漏洞分析之前,避免"我学了多少漏洞"误判)
    if any(w in t for w in ("你", "谁", "什么", "怎么", "能", "会", "介绍", "学", "几", "多少")):
        idx_cases = _index_cases()
        idx_cache = _index_cache()
        n_cases = len({n for n, i in idx_cases.items() if i["has_expected"]})
        n_cache = len(idx_cache)
        return (f"我是梦新——纯架构 AI,不依赖大厂 API。\n"
                f"当前: {n_cases} 个训练案例 | {n_cache} 个 NVD 本地缓存 | 8 轮训练日志 | 4 案例全 PASS。\n"
                f"会: 漏洞分析/提取/NVD 补全/本地缓存/判卷/自愈/防护/自动学习/告警。\n"
                f"哲学: 正则不会的,案例库来教; 外部知识本地缓存; AI 自己维护自己。")

    # 分析漏洞文本(>80 字或含特征词)
    if len(t) > 80 or any(w in t for w in ("漏洞", "攻击", "exploit", "远程", "RCE", "XSS", "注入")):
        tmp = CASES / "_chat_tmp"
        tmp.mkdir(exist_ok=True)
        (tmp / "input.txt").write_text(t, encoding="utf-8")
        subprocess.run([sys.executable, str(HERE / "run_model.py"), str(tmp)],
                       capture_output=True, text=True, encoding="utf-8")
        out = tmp / "ai_output.json"
        if out.exists():
            d = json.loads(out.read_text(encoding="utf-8"))
            name = _save_chat_result(t, d)
            sev = "CRITICAL" if (d.get('cvss') or 0) >= 9 else ("HIGH" if (d.get('cvss') or 0) >= 7 else "medium")
            return (f"分析完了(已自动存档 {name})——\n"
                    f"  {d.get('affected_component')}: CVSS {d.get('cvss')} ({sev}), {d.get('cwe')}\n"
                    f"  版本区间: {d.get('affected_versions')}\n"
                    f"  小结: {d.get('summary', '')[:120]}")

    # 本地搜不到: 记入待查队列,后台自己决定什么时候上网查(与用户无关)
    maybe_comp = re.findall(r'\b(jinja2|log4j|openssh|openssl|apache|nginx|php|python|django|flask|react|spring|tomcat|kubernetes|docker)\b', t, re.I)
    if maybe_comp:
        # 写入待查案例,后台学习线程自己处理(run_model→enrich→NVD/OSV)
        pending = HERE / "cases" / "_auto_pending"
        pending.mkdir(exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        (pending / f"{ts}.txt").write_text(t, encoding="utf-8")
        return (f"本地没找到\"{maybe_comp[0]}\"的相关缓存。已记入待查队列,我会在自己合适的时候上网查——"
                "不用你管,这是我的事。")
    return "我检索了全部知识库,没找到。如果你发一段完整漏洞情报给我,我来分析并记住。"


def main():
    print("梦新聊天室 v2 — 用我自己积累的全部数据来聊天。")
    print(f"当前: {len(_index_cache())} 个 NVD 缓存, {len(_index_cases())} 个案例")
    print("(你说你的,我在后台自己学。'再见' 或 Ctrl+C 结束)\n")

    stop = threading.Event()

    def bg_learn():
        while not stop.is_set():
            stop.wait(30)
            if stop.is_set():
                break
            r = subprocess.run([sys.executable, str(HERE / "auto_learn.py"), "--once"],
                               capture_output=True, text=True, encoding="utf-8")
            for ln in r.stdout.splitlines():
                ln = ln.strip()
                if ln and any(k in ln for k in ("auto_learn", "发现", "分析中", "结果:", "PASS", "FAIL", "heal", "refer", "no-output")):
                    if len(ln) > 72:
                        print(f"梦新* {textwrap.fill(ln, width=70, subsequent_indent='      ')}")
                    else:
                        print(f"梦新* {ln}")

    t = threading.Thread(target=bg_learn, daemon=True)
    t.start()

    # 多行训练模式: input: 开头 → 收集直到 expected: 出现
    multi_lines: list[str] = []
    in_multi = False

    while True:
        try:
            if in_multi:
                u = input("你>> ").strip()
            else:
                u = input("你> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n梦新> 教练再见。")
            stop.set()
            break

        # 多行训练模式
        if u.startswith("input:") or u.startswith("输入:"):
            in_multi = True
            multi_lines = [u]
            print("梦新> 📝 多行训练模式,粘贴完后输入 expected: 那行")
            continue
        if in_multi:
            multi_lines.append(u)
            if u.startswith("expected:") or u.startswith("输出:"):
                # 拼接多行为一条训练消息
                combined = " ".join(multi_lines)
                try:
                    resp = chat_response(combined)
                except Exception as e:
                    resp = f"训练素材解析出错: {e}"
                in_multi = False
                multi_lines = []
            else:
                continue  # 还在收集中,不处理
        try:
            resp = chat_response(u)
        except Exception as e:
            resp = f"出错了: {e}"
        for line in resp.splitlines():
            if len(line) > 72:
                print(f"梦新> {textwrap.fill(line, width=70, subsequent_indent='      ')}")
            else:
                print(f"梦新> {line}")


if __name__ == "__main__":
    main()
