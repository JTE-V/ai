# 梦新 — 可训练的 AI 框架

> **不是算力堆出来的 AI，是你自己训出来的 AI。**
> 下载压缩包 → 解压 → 自己训练你的职业 → 它越来越懂你。

## 快速开始（3 步）

### 1. 下载并解压
下载 `用户框架交付包.zip` → 解压 → 双击 `start_mengxin.bat` 启动聊天室。

### 2. 创造你的职业
```cmd
python new_domain.py "你的职业/爱好"
```
例：`python new_domain.py "钓鱼"` / `"健身"` / `"厨师"`

### 3. 建案例训练（你唯一要做的）
在 `cases/` 建你的案例（一个案例 = 一个问题 + 回答）：
```cmd
mkdir cases\钓鱼-装备
echo 新手钓鱼买什么装备 > cases\钓鱼-装备\input.txt
```
编辑 `cases\钓鱼-装备\expected.json`（回答）：
```json
{
  "area": "钓鱼",
  "key_point": "装备",
  "suggestions": ["鱼竿+线组+鱼饵"],
  "disclaimer": "仅供参考, 不构成专业意见",
  "evidence": ["新手钓鱼买什么装备"],
  "unrelated": false
}
```
训练 + 判卷：
```cmd
python run_model.py cases\钓鱼-装备 --template templates\你的职业.txt
python verify.py cases\钓鱼-装备 cases\钓鱼-装备\ai_output.json
```
看到 **PASS** = 学会了！

## 内置能力（你不用管）

| 能力 | 说明 |
|---|---|
| 数学推理 | 方程/积分/百分比/勾股...自己算（零 API） |
| 内容红线监测 | 违法内容自动拦截, 灰色内容你裁决 |
| 领域选择 | 换职业不用退出, 输入 "启用领域: 钓鱼,健身" |
| 记忆体 | 学一次记住, 越用越懂你 |
| 自动学习 | 没教过的自己联网学 + 沉淀 |

## 详细文档（解压后看）
- `TRAIN_GUIDE.md` — 用户训练手册（案例怎么写）
- `USER_FAQS.md` — 常见问题交代
- `ENGINEER_NOTES.md` — 工程师/开发者坑位清单

## 理念
> 大模型靠算力记住全世界，但它记不住**你**。
> 梦新靠记忆体记住**你**——你教一次，它懂一辈子。
> 算力会过时，训练会困扰；记忆不会。
