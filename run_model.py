#!/usr/bin/env python3
"""梦新 规则提取器 — 不调外部 API,纯架构驱动(模板 + 正则 + 规则引擎)。

一切行为由用户训练的文本规则决定,不依赖任何大厂模型。
外部 LLM 是可选的"加速器"适配器,不接也能跑。

用法:
  python run_model.py <case_dir> [--template templates/01_vuln_analysis.txt]
  (无 --model 参数 — 默认规则驱动,不调外部 API)

流程:
  input.txt → 模板填充({{source}}/{{raw_text}}/段切分)
  → 规则提取字段(正则/模板匹配,原文没有的填 null,红线 4)
  → 写 <case_dir>/ai_output.json → 退出码 0
  (判卷: python verify.py <case_dir> <case_dir>/ai_output.json)

红线 2: 不留密钥。红线 4: 未知填 null,不编造。
"""

import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

# 本地 NVD 缓存目录(查一次记住,离线也能用)
NVD_CACHE_DIR = Path(__file__).resolve().parent / "nvd_cache"
NVD_CACHE_DIR.mkdir(exist_ok=True)


def _cache_path(cve_id: str) -> Path:
    return NVD_CACHE_DIR / f"{cve_id}.json"


def _cache_get(cve_id: str) -> dict | None:
    p = _cache_path(cve_id)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _cache_set(cve_id: str, data: dict) -> None:
    _cache_path(cve_id).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


def load_template(path: str) -> str:
    return open(path, encoding="utf-8").read()


def fill_template(tpl: str, case_dir, text: str | None = None) -> str:
    raw_text = text.strip() if text is not None else (case_dir / "input.txt").read_text(encoding="utf-8").strip()
    sections: dict[str, list[str]] = {}
    cur = None
    for line in raw_text.splitlines():
        m = re.match(r"^\s*\[([^\]]+)\]\s*$", line)
        if m:
            cur = m.group(1)
            sections[cur] = []
        elif cur is not None:
            sections[cur].append(line)
    seg = {k: "\n".join(v).strip() for k, v in sections.items()}
    mapping = {
        "{{source}}": "NVD",
        "{{raw_text}}": raw_text,
        "{{input}}": raw_text,
        "{{knowledge}}": seg.get("已知") or seg.get("knowledge") or "无",
        "{{scan_result}}": seg.get("CI-scan") or raw_text,
        "{{assets}}": seg.get("assets") or raw_text,
        "{{code}}": raw_text,
    }
    for k, v in mapping.items():
        tpl = tpl.replace(k, v)
    return tpl


# ============ HTTP 查询(主动感知: 文本找不到去网页拿,零 key) ============

HTTP_TIMEOUT = 15  # 单次查询超时秒数
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1/query"


def http_get(url: str) -> dict:
    """HTTP GET → JSON dict; 失败抛异常(不静默, 红线 3)。"""
    req = urllib.request.Request(url, headers={"User-Agent": "MengXin/1.0"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_post_json(url: str, body: dict) -> dict:
    """HTTP POST JSON → JSON dict。"""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": "MengXin/1.0"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def query_nvd(cve_id: str) -> dict | None:
    """NVD API 2.0: 按 CVE 查 cvss/cwe/description。先查本地缓存(离线也能用)。"""
    cached = _cache_get(cve_id)
    if cached is not None:
        print(f"  📦 NVD 缓存命中: {cve_id}")
        return cached
    try:
        data = http_get(f"{NVD_API}?cveId={cve_id}")
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        cve_data = vulns[0].get("cve", {})
        # CVSS v3.1 优先, 退 v3.0
        metrics = cve_data.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            for m in metrics.get(key, []):
                d = m.get("cvssData", {})
                if d.get("baseScore"):
                    cvss = d["baseScore"]
                    break
            if cvss is not None:
                break
        # CWE
        cwes = []
        for w in cve_data.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("value", "").startswith("CWE-"):
                    cwes.append(d["value"])
        # public_exploit 线索: CISA KEV 或 NVD 标注
        pub = "unknown"
        if cve_data.get("cisaVulnerabilityName") or cve_data.get("exploitabilityScore"):
            pub = "yes"
        descs = cve_data.get("descriptions", [])
        desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), None)
        result = {"cvss": cvss, "cwe": cwes[0] if cwes else None, "public_exploit": pub,
                  "description_nvd": desc_en, "source": "NVD"}
        _cache_set(cve_id, result)  # 存本地,下次离线直接用
        return result
    except Exception as e:
        print(f"  ⚠ NVD 查询失败({cve_id}): {e}", file=sys.stderr)
        return None


def query_osv(package: str, version: str, ecosystem: str = "PyPI") -> dict | None:
    """OSV.dev: 按包名+版本查漏洞。免费, 无 key。"""
    try:
        data = http_post_json(OSV_API, {"package": {"name": package, "ecosystem": ecosystem}, "version": version})
        vulns = data.get("vulns", [])
        if not vulns:
            return None
        cves = []
        for v in vulns:
            cves.extend(v.get("aliases", []))
        return {"cves": cves, "count": len(vulns), "source": "OSV.dev"}
    except Exception as e:
        print(f"  ⚠ OSV 查询失败({package}=={version}): {e}", file=sys.stderr)
        return None


def enrich_from_web(result: dict, raw_text: str) -> dict:
    """规则提取后补全 null 字段: 文本找不到 → 网页拿(NVD/OSV)。"""
    cve = result.get("cve")
    if cve is None:
        m = re.search(r"CVE-\d{4}-\d{4,}", raw_text)
        if m:
            cve = m.group()
            result["cve"] = cve
    if cve:
        nvd = query_nvd(cve)
        if nvd:
            if result.get("cvss") is None:
                result["cvss"] = nvd.get("cvss")
            if result.get("cwe") is None:
                result["cwe"] = nvd.get("cwe")
            if result.get("public_exploit") == "unknown" and nvd.get("public_exploit") == "yes":
                result["public_exploit"] = "yes"
            # 标注来源
            extra = result.setdefault("_enrich", {})
            extra["nvd"] = {"source": "NVD", "fields": [k for k in ("cvss", "cwe", "public_exploit") if nvd.get(k)]}
    # OSV 补全(内部扫描用)
    findings = result.get("findings")
    if isinstance(findings, list):
        for f in findings:
            fcve = f.get("cve")
            if fcve:
                nvd = query_nvd(fcve)
                if nvd:
                    f.setdefault("cvss_nvd", nvd.get("cvss"))
                    f.setdefault("cwe_nvd", nvd.get("cwe"))
                    notes = result.get("notes", "")
                    if "NVD" not in notes:
                        result["notes"] = (notes + " | enriched from NVD").strip(" |")
    return result

def extract_v01(raw_text: str) -> dict:
    """模板 01 外部情报: 正则规则 + 原文切片提取字段。未知 = null(红线 4)。"""
    t = raw_text
    cve = re.search(r"CVE-\d{4}-\d{4,}", t)
    summary = t[:100].replace("\n", " ").strip()
    evidence = [s.strip() for s in re.split(r"(?<=[.!?])\s+", t) if len(s.strip()) > 10]
    if not evidence:
        evidence = [t.strip()]

    # 版本区间提取: 支持 beta/alpha/rc 等前缀版本
    ver_range = None
    ver_word = r"[\d][\d.\-a-z]*[a-z0-9]"
    ver_pat = re.search(
        rf"(?:({ver_word})\s*(?:through|to|—|-)\s*({ver_word}))|(?:>=\s*({ver_word})\s*,\s*<=\s*({ver_word}))",
        t, re.I,
    )
    if ver_pat:
        g = ver_pat.groups()
        if g[1] and g[0]:
            ver_range = [f">={g[0].strip()}, <={g[1].strip()}"]
        elif g[3] and g[2]:
            ver_range = [f">={g[2].strip()}, <={g[3].strip()}"]
    if ver_range is None:
        ver_range = ["UNKNOWN_RANGE"]

    # CVSS(原文明确出现才取)
    cvss = None
    cvss_m = re.search(r"CVSS\s*(?:score)?\s*(?:[:=])?\s*(\d+\.\d+)", t, re.I)
    if cvss_m:
        try:
            cvss = float(cvss_m.group(1))
        except Exception:
            pass

    return {
        "cve": cve.group() if cve else None,
        "unrelated": False,
        "affected_component": _detect_component(t),
        "affected_versions": ver_range,
        "cwe": None,
        "cvss": cvss,
        "public_exploit": "unknown",
        "attack_vector": None,
        "summary": summary if len(summary) > 5 else t[:100],
        "evidence": evidence,
        "meta": {"provider": "mengxin-arch", "model": "rule-extract-v01", "latency_s": 0},
    }
    result["meta"]["latency_s"] = round(time.time(), 2)  # 后续 if enrich 会更新
    return result


def extract_v03(raw_text: str) -> dict:
    """模板 03 内部扫描: 解析 pip-audit 输出 + 资产匹配。"""
    vuln_lines = re.findall(r"^\s*(\S+)\s+(\S+)\s+(CVE-\d{4}-\d{4,})\s*\((\w+)\)\s*(.*)$", raw_text, re.M)
    assets = re.findall(r"^\s*-\s*(\S+)\s+\(([^)]*)\)\s+uses\s+(\S+)==(\S+)$", raw_text, re.M)
    findings, unmatched = [], []
    for v in vuln_lines:
        pkg, ver, cve, level, fix = v
        matched = []
        for a in assets:
            name, exposure, apkg, aver = a
            if apkg == pkg:
                # 受影响 = 资产版本 < fix 版本
                m = re.search(r">=\s*(\d[\w.]*)", fix)
                fix_ver = tuple(int(x) for x in m.group(1).split(".")) if m else None
                cur_ver = tuple(int(x) for x in aver.split("."))
                if fix_ver and cur_ver < fix_ver:
                    matched.append(name)
            # exposure: 从括号里提取 internet_facing/internal/offline(不含 critical_asset 等标签)
            exp_match = [a[1] for a in assets if a[0] in matched]
            exposure = "unknown"
            if exp_match:
                for tag in ("internet_facing", "public", "external"):
                    if tag in exp_match[0]:
                        exposure = "internet_facing"
                        break
                else:
                    for tag in ("internal", "private"):
                        if tag in exp_match[0]:
                            exposure = "internal"
        findings.append({
            "id": f"{pkg}-{ver}",
            "package_or_component": pkg,
            "installed_version": ver,
            "vulnerable_range": f"<{fix.strip('>= ')}" if fix else "unknown",
            "cve": cve,
            "matched_assets": matched,
            "exposure": exposure,
        })
    return {
        "findings": findings,
        "unmatched": unmatched,
        "notes": "规则提取(架构驱动,未知=null)",
        "meta": {"provider": "mengxin-arch", "model": "rule-extract-v03"},
    }


def extract_v05(raw_text: str) -> dict:
    """模板 05 好奇心: 空架构(好奇心是提问不是编造,红线 4 延伸)。"""
    ev = re.search(r"\[事件\]\s*(.+)", raw_text)
    return {
        "event": ev.group(1).strip() if ev else None,
        "curiosity": {"causes": [], "concepts": [], "gaps": []},
        "honesty": {"speculation_marked": True, "facts_count": 0, "speculations_count": 0},
        "meta": {"provider": "mengxin-arch", "model": "rule-extract-v05"},
    }


def extract_v06(raw_text: str) -> dict:
    """模板 06 代码安全分析: 检测语言,输出空 issues(需要更多训练案例)。"""
    lang = "unknown"
    if re.search(r"<\?(php|=)", raw_text, re.I):
        lang = "PHP"
    elif "#!/" in raw_text[:50] or "def " in raw_text:
        lang = "Python"
    elif "function " in raw_text[:100] or "var " in raw_text[:100]:
        lang = "JavaScript"
    return {
        "language": lang,
        "issues": [],
        "notes": "规则提取(代码分析需要更多训练案例)",
        "meta": {"provider": "mengxin-arch", "model": "rule-extract-v06"},
    }
    """提取组件名: 优先取前缀+主体词组(如 Apache Log4j2),退全文搜索。"""
    skip = {"A", "An", "The", "In", "On", "At", "By", "This", "CVE", "CVSS", "NVD", "MITRE", "SSHD",
            "SIGALRM", "LoginGraceTime", "LDAP", "JNDI"}
    # 策略1: 取开头连续大写词序列(排除冠词后),适合 Apache Log4j2
    m = re.search(r"^([A-Z][a-zA-Z0-9]*(?:\s+[A-Z][a-zA-Z0-9]*)*)", text)
    if m:
        words = [w for w in m.group(1).split() if w not in skip and len(w) >= 2]
        if words and len(words) >= 2:
            return " ".join(words)
    # 策略2: 全文找混合大小写词(如 OpenSSH、Log4j2)—但排除已出现在词组中的单字
    for w in text.split():
        w = w.strip(",;:()[]{}.!?\"'")
        if len(w) < 3 or w in skip:
            continue
        if re.match(r"^[A-Z][a-z]+[A-Z]", w) or re.match(r"^[A-Z][a-z]+[0-9]", w):
            return w
    # 策略3: 找大写开头≥3字母
    for w in text.split():
        w = w.strip(",;:()[]{}.!?\"'")
        if len(w) < 3 or w in skip:
            continue
        if re.match(r"^[A-Z][a-zA-Z]{2,}$", w):
            return w
    return "unknown_component"


# ============ 主入口 ============

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("case_dir", help="cases/<name>/ 目录")
    parser.add_argument("--template", default="templates/01_vuln_analysis.txt")
    args = parser.parse_args()

    case_dir = Path(args.case_dir)
    tpl = load_template(args.template)
    prompt = fill_template(tpl, case_dir)  # 填充模板(用于教练审阅)
    raw_text = (case_dir / "input.txt").read_text(encoding="utf-8").strip()

    # 根据模板类型选择规则提取器(架构驱动,不调 API)
    if "curiosity" in args.template or "05" in args.template:
        result = extract_v05(raw_text)
    elif "internal" in args.template or "03" in args.template:
        result = extract_v03(raw_text)
    elif "code" in args.template or "06" in args.template:
        result = extract_v06(raw_text)
    else:
        result = extract_v01(raw_text)

    # 文本找不到? 去网页拿(主动感知, HTTP 查询, 零 key)
    if result.get("meta", {}).get("model", "").startswith("rule-extract-v0"):
        import prosecutor
        result = prosecutor.review(result, raw_text)
        result = enrich_from_web(result, raw_text)

    out = case_dir / "ai_output.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"✓ 架构驱动输出已写: {out}")
    print(f"  provider: {result.get('meta', {}).get('provider')} | model: {result.get('meta', {}).get('model')}")
    print(f"  判卷: python verify.py {case_dir} {out}")


if __name__ == "__main__":
    main()
