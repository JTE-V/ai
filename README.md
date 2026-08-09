# 梦新 — 可训练的 AI 框架

> **不是算力堆出来的 AI，是你自己训出来的 AI。**
> 下载压缩包 → 解压 → 自己训练你的职业 → 它越来越懂你。

## 📥 下载 & 开始

1. 下载 **`用户框架交付包.zip`** → 解压
2. 双击 **`start_mengxin.bat`** → 进入聊天室（直接打字问它）
3. 没教过的问题它会自己联网学 + 记住

---

## 🛠️ 训练你的职业（位置很明确）

### 第 1 步：创造职业（在解压目录里执行）
```cmd
cd vuln-hunter
python new_domain.py "你的职业"
```
例：`python new_domain.py "钓鱼"` → 自动生成 `templates/钓鱼.txt`

### 第 2 步：建案例（在 `cases\钓鱼-装备\` 文件夹里）
```
cases\钓鱼-装备\
├── input.txt       ← 写"用户会怎么问"
└── expected.json   ← 写"想让它怎么答"
```
**input.txt**（问题）：
```
新手钓鱼买什么装备
```
**expected.json**（回答）：
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

### 第 3 步：训练 + 判卷（在解压目录执行）
```cmd
python run_model.py cases\钓鱼-装备 --template templates\钓鱼.txt
python verify.py cases\钓鱼-装备 cases\钓鱼-装备\ai_output.json
```
看到 **PASS** = 学会了！回到聊天室问它试试。

> 💡 **不会写 JSON？** 复制 `cases\钓鱼-装备\expected.json` 改内容就行。
> `suggestions` = 你想让它说的话，`evidence` = 照抄 input.txt 的原话。

---

## 🧠 内置能力（你不用管）

| 能力 | 说明 |
|---|---|
| 数学推理 | 方程/积分/百分比/勾股...自己算（零 API） |
| 内容红线监测 | 违法内容自动拦截, 灰色内容你裁决 |
| 法官 | 输入 "法官" 看待裁决, "裁决放行 0" 决定 |
| 领域选择 | 换职业不用退出: "启用领域: 钓鱼,健身" |
| 记忆体 | 学一次记住, 越用越懂你 |
| 自动学习 | 没教过的自己联网学 + 沉淀 |

---

## 📖 解压后看这些文档

- `TRAIN_GUIDE.md` — 完整训练手册
- `USER_FAQS.md` — 常见问题
- `ENGINEER_NOTES.md` — 开发者坑位

## 理念

> 大模型靠算力记住全世界，但它记不住**你**。
> 梦新靠记忆体记住**你**——你教一次，它懂一辈子。
> 算力会过时，训练会困扰；记忆不会。

## 许可
[CC BY 4.0](LICENSE)
