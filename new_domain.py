#!/usr/bin/env python3
"""new_domain.py — 梦新框架脚手架: 一键生成新领域骨架.

用法:
  python new_domain.py "医疗咨询"
  python new_domain.py 医疗咨询

生成:
  templates/0X_<slug>.txt     领域模板(字段定义+红线+免责)
  run_model.py 里 extract_<slug>() 提取器骨架 + EXTRACTORS 自动注册
  cases/<slug>-示例/          示例案例目录(input.txt + expected.json 骨架)

用户只需:
  1. 填模板字段(期望输出什么JSON)
  2. 填提取器规则(从原文怎么抽)
  3. 建案例(input+expected) → 训练 → 判卷
  浏览器补全/自动学习/记忆体 → 框架默认内置, 零配置

纯架构: 不调任何大厂 API。浏览器(必应)是默认组件, 新领域自动有。
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATES = HERE / "templates"
RUN_MODEL = HERE / "run_model.py"
CASES = HERE / "cases"

SLUG_BLACKLIST = {"", "none", "test", "demo"}


def to_slug(name: str) -> str:
    """领域名 → 文件 slug (中文/空格 → 下划线, 小写)."""
    s = re.sub(r"[^\w\u4e00-\u9fff]+", "_", name.strip()).strip("_").lower()
    return s or "newdomain"


def next_template_num() -> int:
    """找下一个模板编号 (现有 08 → 09)."""
    nums = []
    for f in TEMPLATES.glob("*.txt"):
        m = re.match(r"(\d+)_", f.name)
        if m:
            nums.append(int(m.group(1)))
    return (max(nums) + 1) if nums else 1


def build_template(num: int, name: str, slug: str) -> str:
    """生成领域模板 (骨架: 字段 JSON + 红线 + 免责)."""
    return f"""# 技能 {num:02d}：{name} (领域骨架)
# 用法：{name}相关输入进入 → 结构化输出。
# 纪律：只输出 JSON；只依据原文描述，不编造原文没有的信息(红线 3/4)。

你是{name}。输入是一段相关描述/查询。
你只输出 JSON，不输出其他文字。

输入：
----
{{{{raw_text}}}}
----

输出 JSON：
{{
  "area": "领域识别(从原文判断, 原文没有则 null)",
  "key_point": "原文的核心信息(没有则 null)",
  "suggestions": ["从原文可推断的建议"],
  "disclaimer": "仅供参考, 不构成专业意见",
  "evidence": ["逐字来自原文的关键句"],
  "unrelated": false
}}

规则：
- 只依据原文输出，不推测原文没有的信息。
- 原文没有的字段填 null 或空数组，禁止编造。
- evidence 必须逐字来自原文(原句)。
- 查不到就 null——浏览器补全(框架内置)会帮你联网找, 但绝不编造。
"""


def build_extractor(num: int, name: str, slug: str) -> str:
    """生成提取器骨架 (照 extract_art 结构)."""
    return f'''def extract_{slug}(raw_text: str) -> dict:
    """{name}提取器: 原文 → 结构化字段 (红线合规: 不编造, 空字段交浏览器补全)."""
    import re as _re
    t = raw_text.strip()
    # 领域识别: 从原文判断(示例: 关键词列表)
    area = None
    # TODO: 填你的领域关键词, 如: if "关键词" in t: area = "子类"
    # 核心信息: 从原文提取(示例: 正则)
    key_point = None
    # TODO: 填你的提取规则, 如: m = _re.search(r"模式", t); key_point = m.group(1) if m else None
    # evidence: 原文分句 (句号/逗号/顿号/换行都切)
    sentences = [x.strip() for x in _re.split(r"[。！？；，,\\n]", t) if len(x.strip()) > 2]
    return {{
        "area": area,
        "key_point": key_point,
        "suggestions": [],
        "disclaimer": "仅供参考, 不构成专业意见",
        "evidence": sentences[:2],
        "unrelated": False,
        "meta": {{"provider": "mengxin-arch", "model": "rule-extract-{slug}", "latency_s": 0}},
    }}


'''

def insert_extractor(num: int, slug: str, code: str) -> bool:
    """把提取器插进 run_model.py (EXTRACTORS 定义前) + 注册一行."""
    src = RUN_MODEL.read_text(encoding="utf-8")
    # 1. 插入提取器定义 (EXTRACTORS 定义前)
    anchor = "EXTRACTORS = {"
    if anchor not in src:
        print("  ✗ run_model.py 找不到 EXTRACTORS 锚点", file=sys.stderr)
        return False
    src = src.replace(anchor, code + anchor, 1)
    # 2. 注册
    reg = f'    "{num:02d}_{slug}": extract_{slug},\n'
    src = src.replace('    "08_art_director": extract_art,\n', reg + '    "08_art_director": extract_art,\n', 1) \
        if '    "08_art_director": extract_art,\n' in src else src
    RUN_MODEL.write_text(src, encoding="utf-8")
    return True


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    name = " ".join(sys.argv[1:]).strip()
    slug = to_slug(name)
    if slug in SLUG_BLACKLIST:
        print(f"✗ 无效领域名: {name!r}", file=sys.stderr)
        sys.exit(1)

    num = next_template_num()
    print(f"生成新领域: {name} (slug={slug}, 模板号 {num:02d})")

    # 1. 模板
    tpl_path = TEMPLATES / f"{num:02d}_{slug}.txt"
    if tpl_path.exists():
        print(f"  ✗ 模板已存在: {tpl_path}", file=sys.stderr)
    else:
        tpl_path.write_text(build_template(num, name, slug), encoding="utf-8")
        print(f"  ✓ 模板: {tpl_path}")

    # 2. 提取器 + 注册
    if insert_extractor(num, slug, build_extractor(num, name, slug)):
        print(f"  ✓ 提取器 extract_{slug} + EXTRACTORS 注册")
    else:
        print("  ✗ 提取器插入失败", file=sys.stderr)

    # 3. 示例案例
    case_dir = CASES / f"{slug}-示例"
    case_dir.mkdir(parents=True, exist_ok=True)  # 确保 cases/ 存在(交付包无空目录)
    (case_dir / "input.txt").write_text(f"这是{name}的示例输入, 替换成你的真实内容。", encoding="utf-8")
    if not (case_dir / "expected.json").exists():
        (case_dir / "expected.json").write_text(
            '{\n  "area": null,\n  "key_point": null,\n  "suggestions": [],\n'
            '  "disclaimer": "仅供参考, 不构成专业意见",\n'
            '  "evidence": ["示例输入原文"],\n  "unrelated": false\n}\n',
            encoding="utf-8")
    print(f"  ✓ 示例案例: {case_dir}")

    print()
    print("下一步(3 步训练):")
    print(f"  1. 填模板字段: templates/{num:02d}_{slug}.txt (期望输出什么JSON)")
    print(f"  2. 填提取规则: run_model.py 的 extract_{slug} (怎么从原文抽)")
    print(f"  3. 建案例训练: cases/{slug}-示例/ 改 input.txt + expected.json")
    print("     python run_model.py cases/{}-示例 --template templates/{:02d}_{}.txt".format(slug, num, slug))
    print("     python verify.py cases/{}-示例 cases/{}-示例/ai_output.json".format(slug, slug))
    print()
    print("浏览器补全/自动学习/记忆体 → 框架默认内置, 不用配。")


if __name__ == "__main__":
    main()
