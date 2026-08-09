# 梦新框架 — 极简使用指引

> **梦新是训练工具。你只需要会两件事：引用职业 + 加种子案例。**
> 我们没替你训任何东西——你的梦新从 0 开始，只学你教它的。

---

## 一、引用一个职业（1 条命令）

```cmd
python new_domain.py "你的职业/爱好"
```
例：
```cmd
python new_domain.py "钓鱼"
python new_domain.py "陪聊"
python new_domain.py "健身"
```
→ 自动生成该职业的文件夹（模板/提取器/示例案例）。

## 二、加种子案例（你唯一要做的内容）

在 `cases/` 建你的职业案例（一个案例 = 一个"问题+回答"）：

```cmd
# 1. 建文件夹
mkdir cases\钓鱼-装备

# 2. 写"用户会问什么"
echo 新手钓鱼买什么装备？ > cases\钓鱼-装备\input.txt

# 3. 写"你想让它怎么答"
#    编辑 cases\钓鱼-装备\expected.json:
#    {"area":"钓鱼","key_point":"装备","suggestions":["鱼竿+线组+鱼饵"],"disclaimer":"仅供参考, 不构成专业意见","evidence":["新手钓鱼买什么装备"],"unrelated":false}

# 4. 训练 + 判卷
python run_model.py cases\钓鱼-装备 --template templates\你的职业.txt
python verify.py cases\钓鱼-装备 cases\钓鱼-装备\ai_output.json
```
看到 **PASS** = 学会了。3-5 个案例起步，越多越懂你。

## 三、用

```cmd
双击 start_mengxin.bat
```
直接问你的职业问题。没教过的，它会自己联网学 + 记住（自动沉淀进你的职业本子）。

---

**记住：梦新不笨，只是还没人教。你教什么，它懂什么。**
