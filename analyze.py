#!/usr/bin/env python3
"""VulnHunter 狩猎管道主框架 — 把 pipeline.txt 的文本 DAG 落地为可执行代码。

分层(每层只做一件事,对应 pipeline.txt 的层):
  ingest    采集/输入: 读 case(外部情报 或 内部扫描)
  l2        规则粗筛: L1 缓存命中 + L2 组件/版本匹配(不调模型)
  l3        真实模型精筛: 复用 run_model.py(--no-model 则读已有 ai_output.json)
  severity  严重性计算: rules.txt 第 2 节(等级 = 规则计算,模型只给因素)
  alert     告警决策: rules.txt 第 3 节(critical/high 立即, medium 每日, low 归档)
  audit     审计归档: audit_log.jsonl(meta 可追溯,红线 3 不静默)

预留接口(差距清单: 无真实感知 / 无真实行动 / 无记忆回放):
  collect_sources()  感知 — TODO: 按 sources.txt 抓 NVD/OSV/KEV
  execute_action()   行动 — TODO: action 真实触发查询/告警
  regression()       记忆回放 — TODO: 全部 cases 回归,同类 E-code 不再犯

用法:
  python analyze.py <case_dir> [--no-model] [--template templates/01_vuln_analysis.txt]
  python analyze.py --regression        # 记忆回放(跑全部 cases 的 verify)

凭据(红线 2): 密钥只走环境变量 DEEPSEEK_API_KEY,本文件/训练文本永不出现。
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
AUDIT_LOG = HERE / "audit_log.jsonl"

# ---- rules.txt 第 2 节: 严重性规则(文本即规则,这里只是它的执行器) ----
SEVERITY_CRITICAL = "critical"  # public_exploit==true AND internet_facing==true
SEVERITY_HIGH = "high"          # cvss>=7.0 OR public_exploit==true OR impact.confidentiality==high
SEVERITY_MEDIUM = "medium"      # cvss>=4.0
SEVERITY_LOW = "low"            # 其余
ASSET_WEIGHT = {"critical_asset": 2.0, "internal": 1.0, "dev": 0.5}  # rules.txt 资产重要性加权


# ============================================================ ingest
def ingest(case_dir: Path) -> dict:
    """采集层: 读入情报原文,判定类型(外部情报 / 内部扫描)。"""
    text = (case_dir / "input.txt").read_text(encoding="utf-8").strip()
    kind = "internal" if "[assets]" in text else "external"
    return {"kind": kind, "text": text}


# ============================================================ l2 规则粗筛
def _parse_version(v: str):
    m = re.search(r"\d+(\.\d+)*", v or "")
    if not m:
        return None
    return tuple(int(x) for x in m.group().split("."))


def _version_le(a, b) -> bool:
    """版本 a <= b(简单元组比较)。"""
    return a is not None and b is not None and a <= b


def _extract_internal(text: str) -> dict:
    """解析内部扫描文本: 漏洞行 + 资产清单。"""
    vuln_lines = re.findall(r"^\s*(\S+)\s+(\S+)\s+(CVE-\d{4}-\d{4,})\s*\((\w+)\)\s*(.*)$", text, re.M)
    assets = re.findall(r"^\s*-\s*(\S+)\s+\(([^)]*)\)\s+uses\s+(\S+)==(\S+)$", text, re.M)
    return {
        "vulns": [
            {"package": p, "version": v, "cve": c, "level": lv, "fix": fix.strip()}
            for p, v, c, lv, fix in vuln_lines
        ],
        "assets": [
            {"name": n, "exposure": exp, "package": pkg, "version": ver}
            for n, exp, pkg, ver in assets
        ],
    }


def l2(case_dir: Path, ingest_info: dict, audit_entries: list) -> dict:
    """L1 缓存 + L2 规则匹配。返回 {pass, reason, matched_assets, exposure}。"""
    kind = ingest_info["kind"]
    text = ingest_info["text"]

    if kind == "internal":
        parsed = _extract_internal(text)
        matched, reasons = [], []
        for v in parsed["vulns"]:
            for a in parsed["assets"]:
                if a["package"] != v["package"]:
                    continue
                # 受影响 = 资产自己的版本 < fix 版本(不是漏洞行的版本)
                affected = _version_le(_parse_version(a["version"]), _parse_version(v["fix"]))
                if affected:
                    matched.append({"asset": a["name"], "exposure": a["exposure"],
                                    "cve": v["cve"], "level": v["level"], "fix": v["fix"]})
                    reasons.append(f"{a['name']} {a['package']}=={a['version']} 受影响(需 >= {v['fix']})")
                else:
                    reasons.append(f"{a['name']} {a['package']}=={a['version']} 不受影响")
        # L1 缓存: 同 cve 已判定 → 直接返回
        cves = {v["cve"] for v in parsed["vulns"]}
        for e in audit_entries:
            if e.get("key") in {f"cve:{c}" for c in cves} and e.get("decision") == "archive":
                return {"pass": False, "reason": f"L1 缓存命中: {e['key']} 已归档", "matched_assets": []}
        return {
            "pass": bool(matched),
            "reason": "; ".join(reasons) or "无命中",
            "matched_assets": [m["asset"] for m in matched],
            "exposure": matched[0]["exposure"] if matched else None,
            "vulns": parsed["vulns"],
        }

    # 外部情报: 无关注清单时默认放行(关注清单 = 未来 L2 配置)
    cve = re.search(r"CVE-\d{4}-\d{4,}", text)
    return {"pass": True, "reason": f"外部情报放行(cve={cve.group() if cve else '未提及'}, 关注清单未配置)", "matched_assets": []}


# ============================================================ l3 真实模型精筛
def l3(case_dir: Path, template: str, no_model: bool) -> dict:
    """L3 精筛: 默认架构驱动(规则提取,不调外部 API),外部模型为可选适配器。"""
    if no_model:
        out = case_dir / "ai_output.json"
        if not out.exists():
            print(f"✗ --no-model 需要 {out} 已存在", file=sys.stderr)
            sys.exit(2)
        return json.loads(out.read_text(encoding="utf-8"))
    # 架构驱动: 调用纯架构版 run_model(不依赖外部 API,零密钥)
    import run_model as rm
    tpl = rm.load_template(str(HERE / template))
    prompt = rm.fill_template(tpl, case_dir)
    raw_text = (case_dir / "input.txt").read_text(encoding="utf-8").strip()
    if "curiosity" in template or "05" in template:
        result = rm.extract_v05(raw_text)
    elif "internal" in template or "03" in template:
        result = rm.extract_v03(raw_text)
    else:
        result = rm.extract_v01(raw_text)
    return result


# ============================================================ severity 规则计算
def severity(vuln: dict) -> dict:
    """rules.txt 第 2 节执行器。模型只提供因素,等级由这里算。"""
    cvss = vuln.get("cvss")
    pub = vuln.get("public_exploit")  # "yes"/"no"/"unknown" 或 true/false
    pub_bool = True if pub in ("yes", True) else (False if pub in ("no", False) else None)

    factors = vuln.get("factors") or {}
    internet_facing = factors.get("internet_facing")

    if pub_bool is True and internet_facing is True:
        level, used = SEVERITY_CRITICAL, "critical: public_exploit==true AND internet_facing==true"
    elif (isinstance(cvss, (int, float)) and cvss >= 7.0) or pub_bool is True or factors.get("impact", {}).get("confidentiality") == "high":
        level, used = SEVERITY_HIGH, "high: cvss>=7.0 OR public_exploit==true OR confidentiality==high"
    elif isinstance(cvss, (int, float)) and cvss >= 4.0:
        level, used = SEVERITY_MEDIUM, "medium: cvss>=4.0"
    elif not factors and vuln.get("level") in ("high", "critical", "medium"):
        # 因素缺失降级: 采用输入原文自带的等级标注(红线 4: 依据来自原文,不是模型定级)
        level, used = vuln["level"], f"fallback: 因素缺失,采用原文标注 level={vuln['level']}"
    else:
        level, used = SEVERITY_LOW, "low: 其余"
    return {"level": level, "rule": used, "factors_missing": not factors}


# ============================================================ alert 告警决策
def alert(level: str, exposure: str | None, audit_entries: list, key: str) -> dict:
    """rules.txt 第 3 节: critical/high 立即, medium 每日汇总, low 归档; 去重。"""
    asset_tier = "critical_asset" if exposure == "internet_facing" else ("internal" if exposure else None)
    weight = ASSET_WEIGHT.get(asset_tier, 1.0)

    for e in audit_entries:
        if e.get("key") == key:
            return {"decision": "dedup", "reason": f"已处理过(key={key}),不重复告警", "priority": 0}

    if level in ("critical", "high"):
        decision, reason = "immediate", "critical/high → 立即告警 + 触发模板 04 利用链分析"
    elif level == "medium":
        decision, reason = "daily_summary", "medium → 每日汇总告警一次"
    else:
        decision, reason = "archive", "low → 归档,不打扰"
    return {"decision": decision, "reason": reason, "priority": round(weight * (3 if decision == "immediate" else 2 if decision == "daily_summary" else 1), 2)}


# ============================================================ audit 审计归档
def audit_write(entry: dict) -> None:
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def audit_read() -> list:
    if not AUDIT_LOG.exists():
        return []
    return [json.loads(line) for line in AUDIT_LOG.read_text(encoding="utf-8").splitlines() if line.strip()]


# ============================================================ 预留接口(差距清单)
def collect_sources() -> None:
    """感知 — TODO: 按 sources.txt 抓 NVD/OSV/KEV,新公告 30s 内进入管道。"""
    raise NotImplementedError("感知未接: 见 sources.txt 外部情报源清单")


def execute_action(action: dict) -> None:
    """行动 — TODO: action 真实触发查询/告警,行动有日志与结果回填。"""
    raise NotImplementedError("行动未接: gaps.action 还是文本,未执行")


def regression() -> int:
    """记忆回放(简单版) — 跑全部 cases 的 verify.py,确认历史错误不复发。"""
    import subprocess

    fails = 0
    for case_dir in sorted((HERE / "cases").iterdir()):
        out = case_dir / "ai_output.json"
        if not out.exists() or not (case_dir / "expected.json").exists():
            continue  # 参照案例(无 expected)或未生成输出的跳过
        r = subprocess.run([sys.executable, str(HERE / "verify.py"), str(case_dir), str(out)],
                           capture_output=True, text=True, encoding="utf-8")
        print(("✓ " if r.returncode == 0 else "✗ ") + case_dir.name)
        if r.returncode != 0:
            fails += 1
            print(r.stdout)
    print(f"回归完成: {fails} 个失败")
    return fails


# ============================================================ 主流程
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("case_dir", nargs="?", help="cases/<name>/ 目录")
    parser.add_argument("--no-model", action="store_true", help="复用已有 ai_output.json(零流量,框架调试用)")
    parser.add_argument("--template", default="templates/01_vuln_analysis.txt")
    parser.add_argument("--regression", action="store_true", help="记忆回放: 跑全部 cases 的 verify")
    parser.add_argument("--heal", action="store_true", help="管道判卷 FAIL 时自动接 heal.py 自愈(监察官)")
    args = parser.parse_args()

    if args.regression:
        sys.exit(regression())

    case_dir = Path(args.case_dir)
    info = ingest(case_dir)
    entries = audit_read()

    # [guard] 防护层: 输入验证 + 净化(防 prompt 注入/投毒,红线 3 不静默)
    import guard
    g_ok, g_why = guard.validate_input(info["text"])
    if not g_ok:
        print(f"[guard] ✗ 输入被拒: {g_why}")
        audit_write({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "key": "guard:" + case_dir.name,
                     "decision": "rejected", "reason": g_why})
        return
    cleaned, g_warn = guard.sanitize(info["text"])
    if g_warn:
        print(f"[guard] ⚠ 输入净化: {g_warn}")
    info["text"] = cleaned

    print(f"[ingest]    kind={info['kind']}")

    l2r = l2(case_dir, info, entries)
    print(f"[l2]        pass={l2r['pass']}  {l2r['reason']}")
    if not l2r["pass"]:
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "key": "l2:" + case_dir.name,
                 "decision": "archive", "reason": l2r["reason"]}
        audit_write(entry)
        print("[decision]  archive(L2 未命中)")
        return

    out = l3(case_dir, args.template, args.no_model)
    provider = out.get("meta", {}).get("provider", "mengxin-arch")
    print(f"[l3]        provider={provider}")

    # [guard] 输出验证: 字段白名单/类型/注入特征(防输出注入污染下游)
    g_ok2, g_probs = guard.validate_output(out)
    if not g_ok2:
        print(f"[guard] ⚠ 输出验证: {g_probs}(记录在案,继续处理)")

    # 外部模板 01 / 内部模板 03 两种结构统一成漏洞列表
    findings = out.get("findings") if isinstance(out.get("findings"), list) else [out]
    results = []
    for f in findings:
        # cve 可为 null(原文未提及),但对象不能是空壳
        if not f or all(f.get(k) is None for k in ("cve", "id", "affected_component", "package_or_component")):
            continue
        comp = f.get("affected_component") or f.get("package_or_component") or f.get("id") or case_dir.name
        key = "cve:" + (f.get("cve") or comp)
        # 内部案例: 模型输出缺 level 时,补输入原文自带的等级标注(红线 4 依据)
        if not f.get("level") and info["kind"] == "internal":
            for v in (l2r.get("vulns") or []):
                if v["cve"] == f.get("cve"):
                    f["level"] = v["level"]
                    break
        sev = severity(f)
        exposure = f.get("exposure") or l2r.get("exposure")
        al = alert(sev["level"], exposure, entries, key)
        results.append({"key": key, "component": comp,
                        "cve": f.get("cve"), "severity": sev["level"], "rule": sev["rule"],
                        "factors_missing": sev["factors_missing"], "decision": al["decision"],
                        "priority": al["priority"], "reason": al["reason"]})
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "key": key, **results[-1],
                 "meta": out.get("meta"), "evidence": f.get("evidence")}
        if al["decision"] != "dedup":
            audit_write(entry)

    sev_summary = ", ".join(f"{(r['cve'] or r['key'])}: {r['severity']}" for r in results)
    alert_summary = ", ".join(f"{r['key']}: {r['decision']}(priority {r['priority']})" for r in results)
    print(f"[severity]  {sev_summary}")
    print(f"[alert]     {alert_summary}")
    print(f"[audit]     已写入 {AUDIT_LOG.name} ({len(audit_read())} 条)")
    print(f"[summary]   {json.dumps(results, ensure_ascii=False, indent=2)}")

    # 真实行动: immediate 告警写入 alerts/(差距清单最后一项闭环)
    for r in results:
        if r["decision"] == "immediate":
            alert_dir = HERE / "alerts"
            alert_dir.mkdir(exist_ok=True)
            ts = time.strftime("%Y%m%d-%H%M%S")
            af = alert_dir / f"{case_dir.name}_{ts}.json"
            af.write_text(json.dumps({"case": case_dir.name, "timestamp": ts, **r},
                                     ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"[action]   告警已写入: {af.name}")

    # --heal: 判卷 FAIL 时自动接监察官自愈(analyze 的 L3 输出已写 ai_output.json)
    if args.heal:
        import subprocess
        out_json = case_dir / "ai_output.json"
        if out_json.exists():
            print(f"[heal] 接入监察官自动修复...")
            r = subprocess.run([sys.executable, str(HERE / "verify.py"), str(case_dir), str(out_json)],
                               capture_output=True, text=True, encoding="utf-8")
            if r.returncode != 0:
                hr = subprocess.run([sys.executable, str(HERE / "heal.py"), str(case_dir), str(out_json), "--re-run"])
                sys.exit(hr.returncode)
            print("[heal] 判卷 PASS,无需修复")


if __name__ == "__main__":
    main()
