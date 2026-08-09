#!/usr/bin/env python3
"""auto_learn.py — 离线自动学习引擎(不等待命令,循环自驱)

用法:
  python auto_learn.py [--once] [--interval 300]

模式:
  --once     一次性: 遍历 cases/ 所有案例,跑管道+判卷+自愈,退出
  --interval 守护模式: 每隔 N 秒检查 cases/ 新案例,自动分析+判卷+heal+沉淀

核心逻辑(每个新案例):
  1. analyze.py 跑全管道(ingest→guard→L2→L3(架构驱动+HTTP补全)→severity→alert→audit)
  2. verify.py 判卷
  3. FAIL → heal.py 自动修复(红线 1: 修正动作来自 heal_rules 显式规则)
  4. PASS → 沉淀 feedback_log
  5. 写入 seen_cases.json(已处理列表,防重复)

用户输入不是命令是参照——本引擎把用户在聊天里发的任何文本当训练素材,
自动创建 case、跑管道、判卷、沉淀。用户只管给参照,梦新自己学。

零 API key,零外部大厂模型依赖。纯架构驱动。
"""

import json
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = Path(__file__).resolve().parent          # vuln-hunter/
CASES = HERE / "cases"
SEEN = HERE / "seen_cases.json"


def load_seen() -> set[str]:
    if SEEN.exists():
        return set(json.loads(SEEN.read_text(encoding="utf-8")))
    return set()


def save_seen(names: set[str]) -> None:
    SEEN.write_text(json.dumps(sorted(names)), encoding="utf-8")


def discover_new_cases(seen: set[str]) -> list[Path]:
    """扫描 cases/ 及 cases/nvd-feed/ 下所有含 input.txt 的子目录,排除已处理。"""
    new = []
    roots = [CASES] + ([CASES / "nvd-feed"] if (CASES / "nvd-feed").exists() else [])
    for root in roots:
        for d in sorted(root.iterdir()):
            if not d.is_dir():
                continue
            if d.name in seen:
                continue
            if (d / "input.txt").exists():
                new.append(d)
    return new


def run_analysis(case_dir: Path) -> str:
    """1)规则提取+HTTP补全(run_model) 2)管道(analyze)。返回输出摘要。"""
    tmpl = "templates/01_vuln_analysis.txt"
    inp = (case_dir / "input.txt").read_text(encoding="utf-8", errors="ignore")
    if "[CI-scan]" in inp or "[assets]" in inp:
        tmpl = "templates/03_internal_scan.txt"
    elif "[事件]" in inp or "[上下文]" in inp or "[参照]" in inp:
        tmpl = "templates/05_curiosity.txt"
    elif re.search(r"<\?(php|=)|#!/|^import |^def |^function |^class ", inp[:200], re.I):
        tmpl = "templates/06_code_analysis.txt"
    # 步骤1: 规则提取 + HTTP 补全 → ai_output.json
    r1 = subprocess.run(
        [sys.executable, str(HERE / "run_model.py"), str(case_dir), "--template", tmpl],
        capture_output=True, text=True, encoding="utf-8",
    )
    # 步骤2: 管道全流程
    r2 = subprocess.run(
        [sys.executable, str(HERE / "analyze.py"), str(case_dir), "--template", tmpl, "--no-model"],
        capture_output=True, text=True, encoding="utf-8",
    )
    return r1.stdout + r2.stdout


def verify_and_heal(case_dir: Path) -> str:
    """判卷 + 自动修复。无 expected.json 的参照案例跳过判卷。"""
    out = case_dir / "ai_output.json"
    exp = case_dir / "expected.json"
    if not out.exists():
        return "no-output"
    if not exp.exists():
        return "refer(无判卷,纯参照)"
    r = subprocess.run(
        [sys.executable, str(HERE / "verify.py"), str(case_dir), str(out)],
        capture_output=True, text=True, encoding="utf-8",
    )
    if r.returncode == 0:
        return "PASS"
    # FAIL → 自动 heal(架构驱动,不需要外部 API)
    hr = subprocess.run(
        [sys.executable, str(HERE / "heal.py"), str(case_dir), str(out)],
        capture_output=True, text=True, encoding="utf-8",
    )
    return f"FAIL→heal(exited {hr.returncode})"


# ============ 联网知识 → 记忆体 沉淀 (自动学习完整闭环) ============
def _sink_web_cache_to_memory() -> int:
    """把 web_cache/ 查到的知识沉淀进记忆体 knowledge/.
    按领域分本子: 查询命中某领域案例 → 沉淀到 web-notes-<领域>.md; 否则通用 web-notes.md.
    下次 chat 直接用, 不联网. 返回新增条数."""
    import json as _json
    from pathlib import Path as _P
    here = _P(__file__).resolve().parent
    cache_dir = here / "web_cache"
    kb_dir = here.parent / "memory-body" / "knowledge"
    kb_dir.mkdir(parents=True, exist_ok=True)
    kb_file = kb_dir / "web-notes.md"
    # 领域映射: 从 cases/ 现有领域名提取 (本子 = 领域文件夹)
    domain_map = {}
    cases_dir = here / "cases"
    if cases_dir.exists():
        for d in sorted(cases_dir.iterdir()):
            if not d.name.startswith("_") and (d / "input.txt").exists():
                try:
                    txt = (d / "input.txt").read_text(encoding="utf-8")[:100]
                    # 2-gram 关键词(中文连续不分词): "新手钓鱼" → {新手,手钓,钓鱼}
                    _han = re.sub(r"[^\u4e00-\u9fff]", "", txt)
                    domain_map[d.name] = [_han[i:i+2] for i in range(len(_han)-1)][:20]
                except Exception:
                    pass
    seen = set()
    if kb_file.exists():
        for line in kb_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("## ") and ":" in line:
                seen.add(line[3:].split(":")[0].strip())
    added = 0
    if cache_dir.exists():
        for f in sorted(cache_dir.glob("*.json")):
            try:
                d = _json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not d.get("found") or not d.get("data"):
                continue
            data = d.get("data") or {}
            q = (data.get("query") or "").strip()
            # 过滤非知识查询: 训练消息/个人信息/文件名格式 → 不污染知识库
            if (not q or q in seen
                    or "expected" in q or "input.txt" in q or "expected.json" in q
                    or q.startswith(("我", "你", "我们"))
                    or ":" in q[:10]):
                continue
            src = d.get("source") or "web"
            if "summary" in data:
                content = f"## {q}: {src}\n\n{data['summary']}\n"
            elif "hits" in data:
                lines = [f"## {q}: {src} (NVD)\n"]
                for h in (data["hits"] or [])[:3]:
                    lines.append(f"- {h.get('id')}: {(h.get('desc') or '')[:120]}")
                content = "\n".join(lines) + "\n"
            else:
                content = f"## {q}: {src}\n\n{str(data)[:200]}\n"
            # 按领域分本子: 查询词匹配某领域案例关键词 → 该领域文件
            target_file = kb_file
            _q_han = re.sub(r"[^\u4e00-\u9fff]", "", q)
            _q_grams = {_q_han[i:i+2] for i in range(len(_q_han)-1)}
            for dom, kws in domain_map.items():
                if len(_q_grams & set(kws)) >= 1:
                    target_file = kb_dir / f"web-notes-{dom}.md"
                    break
            with open(target_file, "a", encoding="utf-8") as kf:
                kf.write(content)
            # 同步自动生成案例 (用户零负担: AI 自己把查到的知识变成可复用案例)
            try:
                case_dir = here / "cases" / f"_auto_web_{len(seen):04d}"
                case_dir.mkdir(exist_ok=True)
                (case_dir / "input.txt").write_text(q, encoding="utf-8")
                exp = {"question": q, "answer": (data.get("summary") or str(data))[:400],
                       "source": src, "unrelated": False}
                (case_dir / "expected.json").write_text(
                    _json.dumps(exp, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
            seen.add(q)
            added += 1
    if added:
        print(f"  [auto_learn] 联网知识沉淀: +{added} 条 -> 记忆体+自动案例(用户零负担)")
    return added


# ============ 好奇心驱动学习 (无提示自主探索) ============
# 不靠用户喂: 自己发现"知识缺口"→ 主动查 → 沉淀
CURIOSITY_FILE = None  # 惰性初始化
_CURIOSITY_SEEN = set()

def _curiosity_queue() -> Path:
    global CURIOSITY_FILE
    if CURIOSITY_FILE is None:
        here = Path(__file__).resolve().parent
        CURIOSITY_FILE = here / "curiosity.txt"
        if CURIOSITY_FILE.exists():
            _CURIOSITY_SEEN.update(CURIOSITY_FILE.read_text(encoding="utf-8").splitlines())
    return CURIOSITY_FILE

def _discover_gaps() -> list[str]:
    """发现知识缺口: ①memory-body gaps.md(查不到的记忆体缺口)
                     ②web_cache里found=False的词(用户问过没找到)
                     ③web-notes里提到的名词但未沉淀 ④NVD组件待查"""
    import json as _json
    here = Path(__file__).resolve().parent
    gaps = []
    # ① 记忆体缺口 gaps.md (查不到自动记的, 优先补)
    gaps_md = here.parent / "memory-body" / "knowledge" / "gaps.md"
    if gaps_md.exists():
        for line in gaps_md.read_text(encoding="utf-8").splitlines():
            m = re.search(r"\|\s*([^|]{2,30}?)\s*\|", line)
            if m and m.group(1).strip() not in _CURIOSITY_SEEN:
                gaps.append(m.group(1).strip())
    # ② found=False 的缓存 (用户问过没答上 = 真实好奇缺口)
    cache_dir = here / "web_cache"
    if cache_dir.exists():
        for f in sorted(cache_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:50]:
            try:
                d = _json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not d.get("found"):
                q = (d.get("data") or {}).get("query") or ""
                q = q.strip()
                # 过滤用户个人信息/非知识词 (好奇只学知识缺口, 不学"我的xx")
                if (2 <= len(q) <= 20 and q not in _CURIOSITY_SEEN
                        and not re.search(r"^(我|你|我们)", q)
                        and not re.search(r"[∫∑√π→=+×]", q)):
                    gaps.append(q)
    return gaps[:5]

def _curiosity_learn(max_queries: int = 3) -> int:
    """好奇学习: 发现缺口 → 联网查 → 沉淀. 返回新增沉淀条数."""
    import run_model as _rm
    qfile = _curiosity_queue()
    gaps = [g for g in _discover_gaps() if g not in _CURIOSITY_SEEN][:max_queries]
    if not gaps:
        return 0
    learned = 0
    for q in gaps:
        try:
            r = _rm._web_lookup(q)
            _CURIOSITY_SEEN.add(q)
            if r.get("found"):
                learned += 1
                print(f"  [好奇] 自己发现并学会: {q} (来自 {r.get('source')})")
            else:
                print(f"  [好奇] 探索 {q}: 暂不可得({r.get('note')[:40]})")
        except Exception as e:
            print(f"  [好奇] {q} 探索异常: {type(e).__name__}", file=sys.stderr)
        time.sleep(1)  # 礼貌限速
    # 记录已探索 (防重复)
    try:
        with open(qfile, "a", encoding="utf-8") as f:
            f.write("\n".join(gaps) + "\n")
    except Exception:
        pass
    return learned


def fetch_nvd_recent() -> list[dict]:
    """从 NVD 抓最近 24h 修改的 CVE,每个生成案例。返回新增列表。"""
    yesterday = time.strftime("%Y-%m-%dT00:00:00.000", time.localtime(time.time() - 86400))
    today = time.strftime("%Y-%m-%dT23:59:59.999", time.localtime())
    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?lastModStartDate={yesterday}&lastModEndDate={today}&resultsPerPage=10")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "MengXin/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"  ⚠ NVD 抓取失败: {e}", file=sys.stderr)
        return []

    added = []
    feed_dir = HERE / "cases" / "nvd-feed"
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            continue
        descs = cve_data.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        if not desc:
            continue
        d = feed_dir / cve_id
        if (d / "input.txt").exists():
            continue  # 已抓过
        d.mkdir(parents=True, exist_ok=True)
        (d / "input.txt").write_text(f"{cve_id}: {desc}", encoding="utf-8")
        added.append(cve_id)
    return added


def append_feedback(case_name: str, status: str) -> None:
    ts = time.strftime("%Y-%m-%d")
    line = f"- {ts} | 自动学习: {case_name} ({status})\n"
    with open(HERE / "feedback_log.txt", "a", encoding="utf-8") as f:
        f.write(line)


def process_case(case_dir: Path) -> str:
    """处理一个案例的完整自动学习循环。"""
    name = case_dir.name
    print(f"\n{'='*50}")
    print(f"[auto_learn] {name}")
    print(f"  分析中...")
    run_analysis(case_dir)
    status = verify_and_heal(case_dir)
    print(f"  结果: {status}")
    append_feedback(name, status)
    return status


def main() -> None:
    once = "--once" in sys.argv
    health = "--health" in sys.argv
    interval = 300
    if "--interval" in sys.argv:
        interval = int(sys.argv[sys.argv.index("--interval") + 1])

    print(f"[auto_learn] 梦新离线自动学习引擎启动 ({'单次' if once else f'守护/每{interval}s'})")

    if health:
        print("[health] 梦新健康自检(NVD/OSV/本地)...")
        import urllib.request, json
        ok = True
        for name, url in [("NVD API 2.0", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"),
                          ("OSV.dev", "https://api.osv.dev/v1/query")]:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "MengXin/1.0"})
                if "osv" in url.lower():
                    req = urllib.request.Request(url, data=json.dumps({"package":{"name":"jinja2","ecosystem":"PyPI"},"version":"3.1.2"}).encode(),
                                                  headers={"Content-Type":"application/json","User-Agent":"MengXin/1.0"})
                urllib.request.urlopen(req, timeout=10)
                print(f"  ✅ {name}: 可达")
            except Exception as e:
                print(f"  ❌ {name}: {e}")
                ok = False
        import py_compile
        for f in ["verify.py","run_model.py","analyze.py","heal.py","guard.py","auto_learn.py"]:
            try:
                py_compile.compile(str(HERE / f), doraise=True)
                print(f"  ✅ {f}: 编译通过")
            except Exception as e:
                print(f"  ❌ {f}: {e}")
                ok = False
        print(f"[health] {'全部健康 ✅' if ok else '存在问题,见上 ❌'}")
        sys.exit(0 if ok else 1)
    seen = load_seen()

    while True:
        # 先自动上网抓新 CVE(梦新自己决定查不查,不用等用户)
        fetched = fetch_nvd_recent()
        if fetched:
            print(f"[auto_learn] 从 NVD 抓了 {len(set(fetched))} 条新 CVE: {fetched[:5]}")
        new = discover_new_cases(seen)
        if not new:
            if once:
                print("[auto_learn] 无新案例,结束")
                break
        else:
            print(f"[auto_learn] 发现 {len(new)} 个新案例")
            for d in new:
                process_case(d)
                seen.add(d.name)
            save_seen(seen)
        # 完整闭环: 联网知识 → 记忆体沉淀(下次直接用, 不联网)
        try:
            _sink_web_cache_to_memory()
            # 好奇心驱动: 无提示自主探索知识缺口
            _curiosity_learn(max_queries=3)
        except Exception as e:
            print(f"  [auto_learn] 沉淀失败: {e}", file=sys.stderr)
        if once:
            break
        time.sleep(interval)


if __name__ == "__main__":
    main()
