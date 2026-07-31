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
        if once:
            break
        time.sleep(interval)


if __name__ == "__main__":
    main()
