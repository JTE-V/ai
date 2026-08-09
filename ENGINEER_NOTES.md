# 工程师必读 — 梦新框架踩坑清单（下个工程师先看这个！）

> 这些坑都是真实踩过的（花了大量时间修）。**改代码前先读，能省 80% 时间。**

---

## ⚠️ 第 1 条（最重要）：改 run_model.py 前先备份！

**run_model.py 的 EXTRACTORS 定义被覆盖删除过 2 次**（extract_v01 也被删过）。
改它之前：
```cmd
cp run_model.py run_model.py.bak
```
恢复：`cp run_model.py.bak run_model.py`
（备份还有：`新建文件夹/新建文件夹/run_model.py` 是旧版，extract_v01 从那恢复过）

## ⚠️ 第 2 条：不要在 heredoc/python -c 里写含 `\n` `\s` 的代码！

```
bash heredoc (<< 'EOF') 或 python -c "..." 里:
  - \\n 会变成真实换行 → 正则 r"[^。！？；\n]" 断行 → SyntaxError
  - \\s 会变真实 \s（有时对有时错, 不可靠）
正确做法: 用 read_file 看实际代码 + edit_file 精确替换（避开转义地狱）
```

## ⚠️ 第 3 条：大段替换前先 read_file 确认实际内容

heredoc 里写的 old_string 经常和文件实际（转义/缩进/CRLF）不一致 → AssertionError。
**先 read_file 拿到精确文本，再 edit_file。**

## 第 4 条：函数定义必须在 EXTRACTORS 之前

EXTRACTORS = {...} 引用 extract_* 函数——如果函数定义在后面 → NameError。
加新领域：extract_<name> 定义插到 EXTRACTORS 前 + 注册一行。

## 第 5 条：数学引擎的坑

- 一元一次方程正则用 search 会误抓二次方程片段（`x^2-5x+6=0` 里的 `-5x+6=0`）
  → 含 `x^2`/`x²` 时跳过一元一次
- 符号逻辑: `2x+3=11` → `x=(11-3)/2`（op="+" 是 c-b）
- 答案正则: "答案是 3x^2" 的"是"不能进捕获; 排除逗号避免抓整句

## 第 6 条：chat.py 分支顺序（重要）

```
紧急拦截(110/119/96110) → 训练素材(input/expected) → 数学分支(solve_math)
→ 知识检索(案例/记忆体/缓存) → 漏洞分析 → 浏览器兜底 → 诚实兜底
```
- 数学分支必须在知识检索**前**（否则"解方程"先命中案例显示原文）
- 训练分支必须识别 `input.txt:`/`expected.json:` 变体（用户会贴文件名格式）
- 多行模式: `input.txt:` 开头 → `expected.json:` 结束

## 第 7 条：浏览器源的坑（修了 7 次）

- 编码: GBK 站 → _decode_html 智能解码(meta charset → utf8 → gbk → gb2312 → big5)
- gzip: bilibili 等返回压缩流 → _decompress 解压(Content-Encoding + magic bytes 1f 8b)
- 正文: _extract_article 优先 `<p>`+关键词, 跳过导航(营业执照/ICP/英雄档案)
- 乱码: _is_garbled(罕见符号 + 中文查询但正文无中文)
- 视频站(bilibili/youtube): 不解析, 直接给链接
- 词典站(hgcha/zdic): 过滤
- 媒体词条(baike 返回电影/歌曲): 跳过(对"什么是X"语义不符)

## 第 8 条：用户侧

- 用户测试可能跑旧进程 → 改完代码让用户重启 chat.py
- 训练定位: 梦新是"训练工具"不是"成品 AI"(TRAIN_GUIDE 开头声明)
- 用户训练可靠方式 = 文件方式(cases/领域/input.txt+expected.json), 不是 chat 多行

## 第 9 条：性能/后台

- 大计算(全量扫描/大t验证)会超时被杀 → 分阶段/缩小区间
- auto_learn 后台线程 + chat 主循环——改 auto_learn 后同样备份

---

**记住顺序: 备份 → read_file 看实际 → edit_file 精确改 → py_compile 语法检查 → 回归测试(全领域 PASS)。**
