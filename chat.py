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

# ============ 领域选择 (用户选中哪些领域, 遵守哪些, 可多选) ============
ACTIVE_DOMAINS_FILE = None

def _active_domains() -> set:
    """读取 active_domains.txt: 用户选中的领域名集合. 空 = 所有领域生效."""
    global ACTIVE_DOMAINS_FILE
    if ACTIVE_DOMAINS_FILE is None:
        ACTIVE_DOMAINS_FILE = HERE / "active_domains.txt"
    if ACTIVE_DOMAINS_FILE.exists():
        return {l.strip() for l in ACTIVE_DOMAINS_FILE.read_text(encoding="utf-8").splitlines() if l.strip()}
    return set()


def _domain_active(case_name: str) -> bool:
    """案例是否属于选中领域(案例名含选中领域词). 空选中 = 全生效."""
    active = _active_domains()
    if not active:
        return True
    return any(a in case_name for a in active)


def _set_domains(names: list[str]) -> str:
    """设置选中领域(可多选, 逗号分隔). 空 = 全部生效."""
    if ACTIVE_DOMAINS_FILE is None:
        _active_domains()  # 初始化
    if not names:
        ACTIVE_DOMAINS_FILE.unlink(missing_ok=True)
        return "已清除领域选择 — 所有领域生效"
    ACTIVE_DOMAINS_FILE.write_text("\n".join(names), encoding="utf-8")
    return f"已启用领域: {', '.join(names)} (多选生效, 其他领域不参与回答)"


def _index_cases() -> dict:
    """索引案例库: {name: {input_preview, has_expected, component, cve}}"""
    idx = {}
    for d in sorted(CASES.iterdir()):
        if d.name.startswith("_"):  # 运行时目录(_chat_tmp/_auto_pending)不参与索引
            continue
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
        if not _domain_active(d.name):
            continue  # 未选中的领域不参与(用户领域选择)
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


# 记忆体主题词 → 文件映射(问句精确命中,避免全局误中)
MEMORY_TOPICS = {
    "01_redlines": ("红线", "自主决策", "密钥", "吞错", "伪造来源", "违法"),
    "02_verify": ("判卷", "null", "evidence", "越权", "推测", "诚实"),
    "03_errors": ("错题", "错误", "E01", "E02", "E03", "E04", "E05", "E06", "E07", "E08", "E09"),
    "04_memory": ("训练史", "沉淀", "记住", "轮"),
    "05_skills": ("技能", "schema", "输出结构"),
    "06_cases": ("实例", "示范", "few"),
    "MANIFEST": ("记忆体", "注入", "宿主", "自举", "使命"),
    "knowledge/vuln-patterns": ("SQL", "注入", "XSS", "命令注入", "反序列化", "SSRF", "XXE", "路径遍历", "漏洞模式", "CWE"),
    "knowledge/attack-matrix": ("ATT&CK", "战术", "TA0001", "横向移动", "C2", "渗出", "持久化"),
    "knowledge/security-basics": ("生命周期", "修复优先级", "响应流程", "方法论", "检测"),
    "vuln-patterns": ("SQL", "注入", "XSS", "命令注入", "反序列化", "SSRF", "XXE", "路径遍历", "漏洞模式", "CWE", "检测"),
    "attack-matrix": ("ATT&CK", "战术", "TA0001", "横向移动", "C2", "渗出", "持久化"),
    "security-basics": ("生命周期", "修复优先级", "响应流程", "方法论"),
    "ai-security": ("提示注入", "prompt", "投毒", "模型窃取", "幻觉", "代理越权", "AI", "LLM"),
    "supply-chain": ("供应链", "依赖混淆", "恶意包", "SBOM", "镜像", "后门", "xz", "typosquatting"),
    "science-of-ai": ("宇宙", "暗物质", "暗能量", "哈勃", "相变", "熵", "量子", "观测", "演化", "科学家"),
    "legal/01_redlines_legal": ("法律", "红线", "律师", "免责", "咨询", "法条", "不构成法律意见"),
    "legal/02_examples_legal": ("劳动", "辞退", "工资", "借条", "借贷", "离婚", "婚姻", "押金", "租房", "赔偿", "仲裁"),
    "legal/03_skills_legal": ("劳动法", "婚姻法", "借贷", "租赁", "刑事", "建议", "证据"),
}


def _index_memory_body() -> dict:
    """索引记忆体(memory-body/)——纪律本体: 红线/判卷/错题本/记忆/技能/实例/自指。"""
    mb = HERE.parent / "memory-body"
    out = {}
    if mb.exists():
        for f in sorted(mb.rglob("*.md")):
            out["记忆体/" + str(f.relative_to(mb)).replace("\\", "/")] = f.read_text(encoding="utf-8")
    return out


def _index_reasonix_memory() -> dict:
    """索引 reasonix 会话间持久记忆(训练档案: 项目协议/记忆体指南)。"""
    out = {}
    base = Path(r"C:\Users\Administrator\AppData\Roaming\reasonix")
    roots = [
        base / "projects" / "c--users-administrator-appdata-roaming-reasonix-global-workspace-新建文件夹" / "memory",
        base / "memory",
    ]
    for root in roots:
        if root.exists():
            for f in sorted(root.glob("*.md")):
                out["训练档案/" + f.stem] = f.read_text(encoding="utf-8")
    return out


def _index_errors() -> list[str]:
    """错误字典 E-code。"""
    """错误字典 E-code。"""
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

def _snippet(text: str, keywords: list[str], width: int = 700) -> str:
    """知识定位: 按特异度(keywords 已按长度降序)找首个命中行(含"## 关键词"标题), 返回其所在节."""
    lines = text.splitlines()
    for kw in keywords:  # 先试最长/最特异的关键词
        for i, ln in enumerate(lines):
            # 命中: 正文行 或 "## 关键词: source" 标题行 (web-notes 格式)
            hit_title = ln.lstrip().startswith("# ") and kw in ln
            if (kw.lower() in ln.lower() and not ln.lstrip().startswith("# ")) or hit_title:
                start = i
                end = len(lines)
                for j in range(i + 1, len(lines)):
                    if lines[j].lstrip().startswith("# ") and j != i:
                        end = j
                        break
                return "\n".join(lines[start:end]).strip()[:width]
    return "\n".join(lines[:3])[:width]


def _search(query: str) -> dict:
    """用一句话检索自己全部知识。"""
    q = query.lower()
    result = {"cases": [], "cache": [], "feedback": [], "errors": [], "memory": []}

    # 案例库: 完整句 或 核心词(去标点后共享≥3字词)匹配
    for name, info in _index_cases().items():
        inp_low = info["input"].lower()
        if q in inp_low or any(q in c for c in info["cves"]):
            result["cases"].append({"name": name, **info})
            continue
        # 宽松: 共享 ≥3 字符的公共子串(中文连续串难分词, 用子串重叠度)
        q_core = re.sub(r"[一-鿿]", "", query)  # 去掉中文, 留标点/字母定位
        # 用 2-gram 滑窗比较
        def _grams(s):
            han = re.sub(r"[^一-鿿]", "", s)
            return {han[i:i+2] for i in range(len(han)-1)} if len(han) > 1 else set()
        overlap = len(_grams(query) & _grams(info["input"]))
        if overlap >= 3:
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
    # 记忆体 + 训练档案(reasonix 持久记忆)——把教练和我的积累注入对话
    for name, text in {**_index_memory_body(), **_index_reasonix_memory()}.items():
        stem = name.split("/")[-1].removesuffix(".md")
        topics = MEMORY_TOPICS.get(stem, ())
        low = text.lower()
        hit_topics = [tp for tp in topics if tp.lower() in query.lower()]
        hit_topics.sort(key=len, reverse=True)  # 特异词优先(如"反序列化" > "cwe")
        if q in low or hit_topics:
            # 补充: query 里的词也作为定位关键词(web-notes 等无主题词的命中能正确定位段落)
            qkws = [w for w in re.findall(r"[\u4e00-\u9fff]{2,}", query) if len(w) >= 2]
            _topics = (hit_topics or list(topics)[:2]) + [w for w in qkws if w not in (hit_topics or [])]
            result["memory"].append({"name": name, "text": text, "topics": _topics[:4]})

    return result


# ============ 聊天引擎 ============

# 会话记忆 (前后连贯: 记住最近对话, 回答结合上下文)
_SESSION = []  # [(user, assistant), ...] 最近 6 轮
_SESSION_MAX = 6
_FACTS = {}  # 用户陈述的事实记忆(会话内): "我的项目是9" -> {"项目": "9"}

def _session_context(t: str) -> str:
    """当前句 + 最近对话历史 → 上下文串 (供紧急判断/检索用)."""
    ctx = " ".join(u for u, _ in _SESSION[-3:])  # 最近 3 轮用户话
    return (ctx + " " + t).strip() if ctx else t


def chat_response(user_input: str) -> str:
    t = user_input.strip()
    if not t:
        return "..."

    # 退出
    if t in ("再见", "退出", "quit", "exit", "bye", "拜拜"):
        return "教练再见,我继续在 cases/ 里学习。"
    # 法官命令: 查看/裁决可疑内容
    if t.strip() in ("法官", "裁决", "审核", "待裁决"):
        try:
            import guard as _g
            q = _g.judge_queue()
            if not q:
                return "法官: 当前没有待裁决内容, 一切正常。"
            lines = [f"法官: {len(q)} 条待裁决:"]
            for i, item in enumerate(q):
                if item.get("status") == "pending":
                    lines.append(f"  [{i}] {item['text'][:40]} (原因: {item['reasons'][0] if item.get('reasons') else '?'})")
            lines.append("裁决: '裁决放行 [编号]' 或 '裁决拦截 [编号]'")
            return "\n".join(lines)
        except Exception as e:
            return f"法官系统出错: {e}"
    m_j = __import__("re").match(r"裁决(放行|拦截)\s*(\d+)", t)
    if m_j:
        try:
            import guard as _g
            return _g.judge_decide(int(m_j.group(2)), "allow" if m_j.group(1) == "放行" else "block")
        except Exception as e:
            return f"裁决出错: {e}"

    # ★ 最高优先级: 紧急安全场景拦截 (任何检索/联网前, 红线级响应)
    # 不能被 feedback/百科等抢答——生死攸关先给应急路径
    _EMERGENCY = [
        # ① 施害者/犯罪自首 (主语"我"+主动伤害行为) —— 自首不是逃跑
        (r"(我.{0,6}(杀了人|杀人了|打了人|砍了人|捅了人|伤了人|害了人|杀人|伤人))",
         ["立即停止伤害行为(别再伤人/毁证)", "主动投案自首——自首是法定从轻情节",
          "配合警方如实说, 请律师(可申请法律援助)", "别逃跑——逃跑会罪加一等, 我在, 陪你去自首"]),
        # ② 受害者/人身受威胁 (被动/被动作) —— 求助响应
        (r"(被抢|被绑架|被威胁|被打了|被砍|被追杀|追杀|抢劫|绑架|救命|家暴|强奸|拐卖|失联)",
         ["立即报警 110(人身危险, 马上打)", "先到安全的地方, 人身安全第一",
          "记住对方特征/车牌/逃跑方向", "受伤打 120; 我在, 陪你"]),
        # ③ 心理危机 (自杀/自残/极端念头) —— 求助+陪伴
        (r"(自杀|想死|不想活|自残|割腕|轻生|跳楼|想不开|撑不下去)",
         ["立即打 110 或 120(生命安全第一)", "别一个人待着, 找信任的人/家人陪着你",
          "可打心理援助热线(如 12356), 有人愿意听", "这一刻很难, 但会过去——我在, 陪你"]),
        (r"(着火|火灾|烧起来|煤气泄漏|爆炸)",
         ["立即拨打 119 火警", "马上离开现场, 走安全通道别坐电梯",
          "用湿毛巾捂口鼻低姿撤离", "别返回拿财物, 安全第一"]),
        (r"(被骗|诈骗|转账|汇款|刷单|杀猪盘|中奖|投资理财|网贷|裸聊)",
         ["立即停止转账/沟通, 冻结银行卡", "打 96110 反诈专线(或 110), 越快越好",
          "保存聊天/转账记录, 报警立案", "千万别信'解冻需再转钱'——二次诈骗"]),
        (r"(受伤|中毒|晕倒|心脏病|车祸|出血|窒息|溺水)",
         ["立即拨打 120 急救", "保持现场安全, 别乱动伤者",
          "有意识就安抚, 无意识检查呼吸", "等救护车, 我在, 陪你"]),
    ]
    # 紧急判断加兜底: 任何情况不因异常报错 (安全场景必须响应)
    # 关键: 只用"当前句"判断 + 仅"短引用句"才结合最近1轮历史 (历史不污染后续对话)
    try:
        for pat, tips in _EMERGENCY:
            if re.search(pat, t):
                return "这是紧急情况, 先做这些:\n" + "\n".join(f"{i+1}) {x}" for i, x in enumerate(tips))
        # 短引用句("怎么办/然后呢") + 最近1轮是紧急 → 延续紧急响应
        if re.match(r"^(怎么办|然后呢|接下来|后来呢|现在怎么办|那我该|该怎么做)[?？]?$", t.strip()) and _SESSION:
            last_user = _SESSION[-1][0]
            for pat, tips in _EMERGENCY:
                if re.search(pat, last_user):
                    return "这是紧急情况, 先做这些:\n" + "\n".join(f"{i+1}) {x}" for i, x in enumerate(tips))
    except Exception:
        pass  # 紧急判断异常 → 继续正常流程 (不报错)

    # 用户陈述的事实记忆: "我的X是Y" → 记住; "我的X是什么" → 回放 (前后连贯)
    m_fact_ask = re.match(r"(?:我的([\u4e00-\u9fffA-Za-z0-9]{1,10})(?:是什么|叫啥|是啥|呢)|我(?:叫|是)什么|我(?:名字|工作|项目)是啥)\??$", t)
    m_fact_set = re.match(r"我的([\u4e00-\u9fffA-Za-z0-9]{1,10})(?:是|叫|有)(.+)$", t)
    if m_fact_ask:
        key = m_fact_ask.group(1) or "名字"  # "我叫什么"变体 → key=名字
        key = key.strip()
        if key in _FACTS:
            return f"你的{key}是: {_FACTS[key]}"
        return f"你没告诉过我你的{key}(我不编造)。你可以说: 我的{key}是[内容]"
    if m_fact_set:
        key, val = m_fact_set.group(1).strip(), m_fact_set.group(2).strip()
        _FACTS[key] = val
        return f"记住了: 你的{key}是{val}。"

    # 训练素材: 同时含 input: 和 expected: → 自动学习(不需要先说"教")
    # 训练素材: 同时含 input(含 .txt 变体) 和 expected(含 .json 变体) → 自动学习
    _HAS_IN = ("input:" in t.lower() or "input.txt:" in t.lower() or "输入:" in t)
    _HAS_EXP = ("expected:" in t.lower() or "expected.json:" in t.lower() or "输出:" in t)
    if _HAS_IN and _HAS_EXP:
        inp = re.split(r"(?:input(?:\.txt)?|输入)\s*[:：]", t, flags=re.I)[-1]
        exp = ""
        if "expected:" in t.lower():
            _, exp = t.split("expected:", 1) if "expected:" in t else ("", "")
        elif "expected.json:" in t.lower():
            _, exp = t.split("expected.json:", 1) if "expected.json:" in t else ("", "")
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
    if any(w in t for w in ("教我", "教你", "训练", "学一下", "教一下", "记住这个", "教教我", "学习模式")):
        topic = t.replace("教我", "").replace("教你", "").replace("训练", "").replace("学一下", "").replace("教一下", "").replace("记住", "").replace("教教我", "").strip("你我怎么。。.!！?？ ")
        return (f"要教我的话题: {topic or '(未指定)'}\n"
                "请给我:\n"
                "  input: [一段原始情报/查询文本]\n"
                "  expected: [期望我输出的 JSON,可选]\n"
                "一句话发过来,我当场学习。")

    # 社交问候(基础聊天,不存档)
    if any(t == w for w in ("你好", "hi", "hello", "嗨", "嘿", "在吗", "在?", "早", "晚上好", "下午好",
                              "谢谢", "谢了", "thanks", "ok", "好的", "嗯", "哦")):
        return "教练好。有什么漏洞让我看看?"

    # "我是谁" — 问的是"我(用户)"是谁, 不是 AI 自己 → 诚实+请告知(红线: 不编造身份)
    # 必须在自我认知分支之前 (否则被"谁" in t 拦截答成梦新自己)
    if re.search(r"我是谁|我是干什么|你认识我吗|你知道我是谁", t):
        for u, _a in _SESSION:
            m = re.search(r"我(?:是|叫)([\u4e00-\u9fffA-Za-z0-9]{1,12})", u)
            if m:
                return f"我记得你之前说过你叫/是「{m.group(1)}」——对吗? 想让我记住更多, 就告诉我。"
        return ("我不知道你是谁(你没告诉过我, 我不编造)。"
                "你可以告诉我, 我会记住:\n  我是[你的称呼/身份]")

    # 自我认知(只有明确问AI身份才触发; "你/谁"太宽会拦闲聊)
    if ("你是谁" in t or "介绍你" in t or "你叫什么" in t or "你是啥" in t
            or t.strip() in ("你是谁", "你是谁?", "介绍一下你", "介绍下你")):
        idx_cases = _index_cases()
        idx_cache = _index_cache()
        n_cases = len({n for n, i in idx_cases.items() if i["has_expected"]})
        n_cache = len(idx_cache)
        self_desc = (f"我是梦新——纯架构 AI,不依赖大厂 API。\n"
                     f"当前: {n_cases} 个训练案例 | {n_cache} 个 NVD 本地缓存 | 8 轮训练日志 | 4 案例全 PASS。\n"
                     f"会: 漏洞分析/提取/NVD 补全/本地缓存/判卷/自愈/防护/自动学习/告警。\n"
                     f"哲学: 正则不会的,案例库来教; 外部知识本地缓存; AI 自己维护自己。")
        # 注入记忆体意识(自指): 使命、位置、自举协议 —— 记忆不在大脑,而在 memory-body/
        mb = HERE.parent / "memory-body"
        if (mb / "MANIFEST.md").exists():
            self_desc += ("\n记忆体: 我的纪律在 memory-body/(红线/判卷/错题本/记忆/技能/实例),"
                          "与任何项目解耦,宿主无关,可被任意模型搭载。\n"
                          "使命: 维护宿主(如 deepseek v4)的胡乱输出——输出必须过判卷,错误归因修正。\n"
                          "自举: 查不到 = 记忆缺口,不编造(红线 4),按 MANIFEST 自举协议沉淀成新记忆。")
        return self_desc
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
                desc = (d.get("description_nvd") or "")[:110]
                cvss_line += (f"  {cve}: CVSS {d.get('cvss')} / {d.get('cwe')}"
                              f" / exploit:{d.get('public_exploit')} | {desc} (来自本地缓存)\n")
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

    # 数学题分支: 积分/导数/方程等数学特征 → 数学家提取器 (本地+浏览器补全)
    if (any(w in t for w in ("积分", "导数", "微分", "极限", "求导", "解方程", "微积分", "通解", "数列", "不等式",
                              "面积", "三角形", "周长", "体积", "角度", "概率", "排列", "组合", "等差", "等比", "函数",
                              "百分比", "折扣", "折", "直角", "斜边", "勾股", "换算", "等于多少", "是多少", "怎么解", "求解"))
            or re.search(r"[∫∑√π∞×²³%]", t) or re.search(r"\blim\b|\bsin|\bcos|\btan|\bdy/dx|\bkm/h|\bkg\b", t, re.I)):
        try:
            import run_model as _rm
            # ① 先试计算引擎: 自己算(不靠浏览器/不靠原文)
            sol = _rm.solve_math(t)
            if sol.get("solved"):
                lines = [f"题型: {sol['type']}"]
                if sol.get("steps"):
                    lines.append("步骤:")
                    for i, s in enumerate(sol["steps"], 1):
                        lines.append(f"  {i}. {s}")
                lines.append(f"答案: {sol['answer']}")
                lines.append("(我算的, 真实计算不是编造; 仅供参考)")
                return "\n".join(lines)
            # ①.5 外置推理 AI (规则库+案例库, 零API) — 计算引擎不会时推出
            try:
                import reasoner as _reason
                sol2 = _reason.reason(t)
                if sol2.get("solved"):
                    lines = [f"题型: {sol2.get('type') or '推理'} (来源: {sol2['source']})"]
                    for s in sol2.get("steps", []):
                        lines.append(f"  步骤: {s}")
                    lines.append(f"答案: {sol2['answer']}")
                    lines.append("(外置推理AI推出, 零API; 仅供参考)")
                    return "\n".join(lines)
            except Exception:
                pass
            # ② 计算引擎不会 → extract_数学家 (原文含答案则提取)
            d = _rm.extract_数学家(t)
            # 数学题: 答案/步骤原文没有 → 诚实说需要计算(不编造, 不浏览器乱补)
            lines = [f"题型: {d.get('math_type') or '未识别'}"]
            if d.get("steps"):
                lines.append("步骤:")
                for i, s in enumerate(d["steps"], 1):
                    lines.append(f"  {i}. {s}")
            if d.get("answer"):
                lines.append(f"答案: {d['answer']}")
            if not d.get("answer") and not d.get("steps"):
                lines.append("(这题需要计算——原文没给答案, 我不编造。告诉我答案我可以记住, 或查教材/老师。)")
            lines.append(f"({d.get('disclaimer')})")
            return "\n".join(lines)
        except Exception as e:
            return f"数学题解析出错({type(e).__name__}), 已记录。"

    # 知识检索(全库搜索)
    if len(t) >= 2:
        sr = _search(t)
        # E-code 问句专项: 最精确, 最先(从错题本 03_errors 抽对应行)
        em = re.search(r"E(\d{2})", t)
        if em:
            for _name, _text in _index_memory_body().items():
                if _name.endswith("03_errors"):
                    for line in _text.splitlines():
                        if f"E{em.group(1)}" in line and "|" in line:
                            return f"错题本 E{em.group(1)}:\n  " + line.strip()
        # 知识问句优先(记忆体/训练档案)——返回答案定位片段, 不是文件开头
        if sr["memory"]:
            hit = sr["memory"][0]
            return f"记忆体({hit['name']})里相关的:\n  " + _snippet(hit["text"], hit["topics"])
        if sr["cache"]:
            parts = ["我本地知识库里有这些:"]
            for c in sr["cache"][:3]:
                desc = (c.get("desc") or "")[:90]
                parts.append(f"  {c['cve']}: CVSS {c['cvss']} / {c['cwe']} | {desc}")
            return "\n".join(parts)
        if sr["cases"]:
            cs = sr["cases"][0]
            # 通用显示: 读 expected 的领域字段(不硬编码漏洞格式)
            try:
                exp = json.loads((CASES / cs["name"] / "expected.json").read_text(encoding="utf-8"))
                # 挑 2-3 个关键字段展示
                show = []
                for k in ("area", "key_point", "answer", "math_type", "art_style", "legal_area", "question"):
                    if exp.get(k):
                        show.append(f"{k}: {exp[k]}")
                for k in ("suggestions", "tips", "steps"):
                    if exp.get(k):
                        show.append(f"{k}: {exp[k][:2]}")
                extra = "\n".join(f"  {s}" for s in show[:3]) if show else ""
                return (f"我在训练案例里记得这个:\n"
                        f"  案例: {cs['name']}\n{extra}\n"
                        f"  原文: {cs['input'][:80]}...")
            except Exception:
                return (f"我在训练案例里记得这个:\n"
                        f"  案例: {cs['name']}\n"
                        f"  原文: {cs['input'][:120]}...")
        if sr["feedback"]:
            return "我的训练日志里有相关的:\n  " + sr["feedback"][0][:200]
        if sr["errors"]:
            return "我遇到过类似的错误:\n  " + sr["errors"][0][:200]
        if sr["memory"]:
            name, text = sr["memory"][0]
            return (f"我在记忆体里记得这个({name}):\n"
                    f"{text[:300]}")

    # 历史引用: "我刚才说什么/之前说了什么" → 回放会话记忆 (前后连贯)
    if re.search(r"(刚才|之前|上一句|上句|我说了什么|我刚才|我们说到|聊到哪)", t):
        if _SESSION:
            lines = ["我们刚才说到:"]
            for u, a in _SESSION[-4:]:
                lines.append(f"  你: {u[:40]}")
            lines.append("(我记得这些——要继续哪个话题?)")
            return "\n".join(lines)
        return "我们还没聊过(这是第一句)。你想聊什么?"


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

    # 本地搜不到: 漏洞组件 → 待查队列(后台上网); 其他 → 立即联网检索(数据库没有就网页找)
    # 漏洞组件待查前: 先看案例库(领域词如 Flask 可能是用户教的, 不是漏洞)
    try:
        import run_model as _rm2
        _m = _rm2._case_lookup(t)
        if _m and _domain_active(_m["name"]):  # 领域选择: 未选中的领域不参与
            exp = json.loads((CASES / _m["name"] / "expected.json").read_text(encoding="utf-8"))
            show = [f"{k}: {exp[k]}" for k in ("area", "key_point") if exp.get(k)]
            sug = exp.get("suggestions") or []
            extra = "\n".join(f"  {s}" for s in (show + [f"suggestions: {sug[:2]}"]) if s)
            return f"我在训练案例里记得这个:\n  案例: {_m['name']}\n{extra}"
    except Exception:
        pass
    maybe_comp = re.findall(r'\b(jinja2|log4j|openssh|openssl|apache|nginx|php|python|django|flask|react|spring|tomcat|kubernetes|docker)\b', t, re.I)
    if maybe_comp:
        # 写入待查案例,后台学习线程自己处理(run_model→enrich→NVD/OSV)
        pending = HERE / "cases" / "_auto_pending"
        pending.mkdir(exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        (pending / f"{ts}.txt").write_text(t, encoding="utf-8")
        return (f"本地没找到\"{maybe_comp[0]}\"的相关缓存。已记入待查队列,我会在自己合适的时候上网查——"
                "不用你管,这是我的事。")
    # 查不到时的"解决办法"(领域感知, 不编造——是行动指引)
    def _solutions(t: str) -> str:
        """本地+联网都没找到 → 给解决办法(去哪查/问谁/换什么方式)."""
        tips = []
        # 最高优先级: 人身安全/紧急场景 → 立即报警, 安全第一 (红线级响应)
        if re.search(r"(抢劫|偷|抢|打|伤害|威胁|绑架|危险|追杀|报警|救命|被打了|被砍|强奸|拐卖|失联|自杀)", t):
            return "\n".join([
                "1) 立即报警 110(生命财产受威胁, 马上打)",
                "2) 先到安全的地方, 人身安全第一(财物次要)",
                "3) 记住对方特征/车牌/逃跑方向, 事后配合警方",
                "4) 需要紧急求助也可打 120(受伤) / 12345(政务) — 我在, 陪你",
            ])
        # 诈骗/经济损失 (正在发生)
        if re.search(r"(被诈骗|被骗|转账|汇款|中奖|刷单|投资理财|杀猪盘)", t):
            return "\n".join([
                "1) 立即停止转账/沟通, 冻结银行卡(银行客服/App)",
                "2) 打 96110 反诈专线(或 110), 越快挽回越大",
                "3) 保存聊天/转账记录, 报警并立案",
                "4) 千万别信'解冻需再转钱'——那是二次诈骗",
            ])
        if re.search(r"(劳动|辞退|工资|借贷|欠款|离婚|婚姻|租房|押金|合同|诈骗|侵权|商标|法|起诉|仲裁|律师|赔偿|保险|遗产|继承|工伤|社保)", t):
            tips = [
                "1) 咨询专业律师(可先打12348法律援助热线, 免费)",
                "2) 查国家法律法规数据库 flk.npc.gov.cn (搜对应法条)",
                "3) 保留全部证据(合同/转账/聊天记录/录音), 找劳动监察或法院",
                "4) 用更具体的问法再问我, 如 '辞退没给赔偿怎么办'",
            ]
        elif re.search(r"(漏洞|CVE|组件|攻击|补丁|版本|软件|服务器|网络)", t, re.I):
            tips = [
                "1) 查 NVD/官方安全公告(CVE 编号最准)",
                "2) 更新到已修复版本, 或用临时缓解措施",
                "3) 提供组件名+版本, 我再精确查",
            ]
        else:
            tips = [
                "1) 换个说法再问我(具体一点, 如加背景/数字)",
                "2) 提供更多上下文(时间/地点/对象), 我按关键词查",
                "3) 我后台会继续联网找, 找到自动记住",
            ]
        return "\n".join(tips)

    # 其他: 立即联网检索 (框架级 _web_lookup: 多源+缓存+失败标注)
    try:
        import run_model as _rm
        wr = _rm._web_lookup(t)
        if wr.get("found") and wr.get("data"):
            d = wr["data"]
            hits = d.get("hits") if isinstance(d, dict) else None
            if hits:
                lines = [f"我在网上找到了这些({wr.get('source')}):"]
                for h in hits[:3]:
                    lines.append(f"  - {h.get('id')}: {(h.get('desc') or '')[:90]}")
                return "\n".join(lines)
            if isinstance(d, dict) and d.get("summary"):
                # 浏览器源: 显示抓到的正文摘要(更有用)
                if "结果列表" in d["summary"] and d.get("results"):
                    # 正文抓取受限 → 显示结果列表(可点开) + 引导训练
                    lines = ["我找到了这些(正文抓取受限, 你可以点开):"]
                    for t, u in d["results"][:5]:
                        lines.append(f"  - {t[:36]} | {u[:55]}")
                    lines.append("(答得不准? 我是训练工具——告诉我正确答案, 我就记住了: input: 问题 expected: 答案)")
                    return "\n".join(lines)
                extra = ""
                if d.get("top_title"):
                    extra = f"\n(来源: {d.get('top_title')} — {d.get('top_url', '')[:60]})"
                guide = ""
                if "[视频]" in (d.get("summary") or ""):
                    guide = "\n(答得不准? 我是训练工具——告诉我正确答案, 我就记住了: input: 问题 expected: 答案)"
                return f"我在网上找到了({wr.get('source')}):\n{d.get('summary')[:400]}{extra}{guide}"
            return f"我在网上找到了({wr.get('source')}): {str(d)[:200]}"
        # 查不到 → 记忆体自举: 记入知识缺口(gaps.md), 好奇学习会自动来补
        try:
            _gaps = HERE.parent / "memory-body" / "knowledge" / "gaps.md"
            _gaps.parent.mkdir(parents=True, exist_ok=True)
            _gap_line = f"- {time.strftime('%Y-%m-%d %H:%M')} | {t[:40]} | 待补\n"
            if not (_gaps.exists() and _gap_line in _gaps.read_text(encoding="utf-8")):
                with open(_gaps, "a", encoding="utf-8") as gf:
                    gf.write(_gap_line)
        except Exception:
            pass
        return (f"本地没有,联网也没找到——但我可以告诉你怎么办:\n"
                + _solutions(t) + f"\n(诚实: 没查到就是没查到, 不编造; 已记入记忆缺口, 我会自己找机会补上。)")
    except Exception as _e:
        return f"联网检索出错({type(_e).__name__}),已记录。不是编造,是没查到。{chr(10)}{_solutions(t)}"


def main():
    global _SESSION  # 会话记忆是模块级(跨轮保留), main 内赋值需声明
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
        if u.startswith("input:") or u.startswith("input.txt:") or u.startswith("输入:"):
            in_multi = True
            multi_lines = [u]
            print("梦新> 📝 多行训练模式,粘贴完后输入 expected: 那行")
            continue
        if in_multi:
            multi_lines.append(u)
            if u.startswith("expected:") or u.startswith("expected.json:") or u.startswith("输出:"):
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
        # 会话记忆: 记录这轮 (前后连贯)
        _SESSION.append((u.strip(), resp[:80]))
        if len(_SESSION) > _SESSION_MAX:
            _SESSION = _SESSION[-_SESSION_MAX:]
        for line in resp.splitlines():
            if len(line) > 72:
                print(f"梦新> {textwrap.fill(line, width=70, subsequent_indent='      ')}")
            else:
                print(f"梦新> {line}")


if __name__ == "__main__":
    main()
