# AIQuery 鸿蒙/ArkTS 适配思路

> 本框架最终需在 OpenHarmony 设备上运行（ArkTS 前端 + Python/云后端）

---

## 当前架构 vs 鸿蒙部署模型

```
┌─────────────────────────────────────────────┐
│              ArkTS 前端 (Stage模型)           │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │ 对话界面  │  │ 模板编辑器│  │ 结果展示   │  │
│  └────┬─────┘  └────┬─────┘  └─────┬─────┘  │
│       └──────────────┼──────────────┘        │
│                      │ @ohos.net.http        │
├──────────────────────┼──────────────────────┤
│              鸿蒙 IPC 通信层                  │
│  ┌───────────────────┴───────────────────┐   │
│  │  鸿蒙服务卡片 / Ability 间通信          │   │
│  │  - 权限校验可在此层拦截                 │   │
│  │  - 调用审计可对接鸿蒙 HUKS 密钥管理     │   │
│  └───────────────────┬───────────────────┘   │
├──────────────────────┼──────────────────────┤
│           Python 后端 (云/边缘)               │
│  ┌───────────────────┴───────────────────┐   │
│  │  AIQuery 框架 (orchestrator.py)        │   │
│  │  - QueryGuardian 五层防护              │   │
│  │  - 精准采集 + 权限代理                  │   │
│  └───────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

---

## 一、鸿蒙权限机制如何作为"白名单校验层"

### 1.1 鸿蒙现有权限体系

| 鸿蒙机制 | AIQuery 用途 | 类比 protect_plass |
|---------|-------------|-------------------|
| **AccessToken** | 应用身份验证 | 进程 UID 验证 |
| **Ability 隔离** | 查询请求必须来自授权 Ability | 进程间 IPC 白名单 |
| **HUKS 密钥管理** | API Key / Token 安全存储 | 内核态密钥保护 |
| **分布式数据管理** | 跨设备查询结果缓存 | perf ring buffer 跨态通信 |
| **BundleManager** | 验证调用方包名和签名 | 进程名白名单 |

### 1.2 白名单校验的鸿蒙实现方案

```typescript
// ArkTS 端：调用前先校验权限
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import bundleManager from '@ohos.bundle.bundleManager';

async function checkQueryPermission(queryType: string): Promise<boolean> {
  // 1. 检查应用是否有"查询"权限
  const atManager = abilityAccessCtrl.createAtManager();
  const tokenID = bundleManager.getBundleInfoForSelfSync(0).appId;
  
  // 2. 查询是否在白名单中
  const result = await fetch('http://localhost:8080/auth/check', {
    method: 'POST',
    body: JSON.stringify({ tokenID, queryType })
  });
  
  // 3. 未授权 → 直接拒绝，不发起查询
  if (!result.ok) {
    console.error(`[AuthProxy] 未授权查询: ${queryType}`);
    return false;
  }
  return true;
}
```

### 1.3 三层权限校验链路

```
ArkTS 前端                    Python 后端
───────────                  ────────────
AccessToken 校验  ────────→  AuthProxy.check_permission()
  (鸿蒙系统层)                  (白名单匹配)
       │                            │
       ▼                            ▼
HUKS 密钥签名     ────────→  TempToken 验证
  (防篡改)                       (用完即焚)
       │                            │
       ▼                            ▼
BundleManager     ────────→  审计日志 (HUKS 签名)
  (调用方身份)                   (不可否认)
```

---

## 二、精准采集在鸿蒙上的实现

### 2.1 ArkTS 端 Schema 定义

```typescript
// 模板可以在 ArkTS 端定义，发送到 Python 后端执行
interface FieldSchema {
  field_name: string;
  selector: string;      // JSONPath 表达式
  type: 'str' | 'int' | 'float' | 'date';
  validators?: string[]; // 验证规则
}

interface CollectSchema {
  source_type: 'api' | 'database' | 'local_file';
  fields: FieldSchema[];
}
```

### 2.2 边缘端采集优化

鸿蒙设备可能部署在边缘，需要本地采集能力：

| 场景 | 实现方式 | 类比 |
|------|---------|------|
| 本地传感器数据 | 直接调用 @ohos.sensor API | eBPF 内核态直接读取 |
| 本地文件 | @ohos.file.fs 读取 + JSON 解析 | 文件系统系统调用 |
| 远程 API | @ohos.net.http 请求 + Schema 抽取 | 系统调用 connect/recv |
| 分布式数据 | @ohos.data.distributedKVStore | eBPF Map 跨态共享 |

### 2.3 精准采集 vs 全文抓取对比

```
传统方式:  HTTP GET → 整页 HTML → 让 AI 读 → 提取关键信息
           ❌ 噪声 95%    ❌ 延迟高    ❌ 幻觉风险

AIQuery:   Schema 定义字段 → 只抽取指定列 → 结构化 JSON
           ✅ 零噪声      ✅ 低延迟    ✅ 可验证
```

---

## 三、鸿蒙 IPC 权限监控（类比 protect_plass 的 eBPF 监控）

### 3.1 监控对象映射

| protect_plass 监控对象 | AIQuery 鸿蒙版监控对象 |
|----------------------|---------------------|
| sys_enter_openat | @ohos.net.http 请求发起 |
| sys_enter_connect | 跨 Ability IPC 调用 |
| sys_enter_execve | 算法房间启动 |
| sys_enter_read/write | 数据流入/流出 |
| /etc/passwd 访问 | HUKS 密钥读取 |

### 3.2 鸿蒙安全机制映射

```
protect_plass              AIQuery 鸿蒙版
────────────               ─────────────
eBPF tracepoint     →      鸿蒙 HDC 系统跟踪
perf ring buffer    →      分布式数据通道
SIGKILL 终止进程     →      Ability 强制停止
iptables 阻断       →      网络策略拦截
cgroup 隔离         →      Ability 沙箱隔离
```

---

## 四、渐进式查询在边缘端的实现

### 4.1 边缘-云分层

```
┌──────────────────────────────────────────┐
│ 边缘设备 (鸿蒙)                            │
│ ① 本地缓存 (KV Store)                     │
│    命中 → 直接返回，零延迟                  │
│    未命中 → 推给下一层                      │
│                                           │
│ ② 本地粗筛 (设备端向量库)                   │
│    召回 Top-20                             │
├──────────────────────────────────────────┤
│ 云端 (Python 后端)                         │
│ ③ 云侧精筛 (GPU 向量库 + 重排序)            │
│    Top-20 → Top-5                         │
│                                           │
│ ④ LLM 生成                                │
│    最终答案                                 │
└──────────────────────────────────────────┘
```

### 4.2 离线能力

鸿蒙设备断网时：
- FULL → 降级为 REDUCED（仅本地缓存）
- REDUCED → 降级为 MINIMAL（预置模板回答）
- 网络恢复后自动切回 FULL

---

## 五、部署架构建议

```
阶段1（当前）: Python 后端 + ArkTS 前端通过 HTTP 通信
阶段2（优化）: 边缘设备嵌入 Python 运行时（termux 或 Chaquopy）
阶段3（终极）: 鸿蒙原生实现精准采集（ArkTS 版 PrecisionCollector）
```

### 阶段3 的 ArkTS 伪代码

```typescript
// 鸿蒙原生精准采集器
class PrecisionCollectorNative {
  static collectFromHTTP(response: HttpResponse, schema: CollectSchema): object {
    const result: Record<string, Object> = {};
    const body = JSON.parse(response.result as string);
    
    for (const field of schema.fields) {
      // JSONPath 简化实现
      const value = this.resolveJSONPath(body, field.selector);
      result[field.field_name] = this.castType(value, field.type);
    }
    
    return result; // 结构化数据，不是文本
  }
}
```

---

## 六、关键结论

1. **鸿蒙的 AccessToken + HUKS 完全可以替代 AuthProxy 的系统层校验**
2. **精准采集在鸿蒙上更高效**——直接在设备端用 ArkTS 实现 Schema 抽取，避免传输整页 HTML
3. **渐进式查询天然适合边缘-云架构**——缓存层在边缘，精筛层在云端
4. **鸿蒙的 Ability 隔离机制本身就是 QueryGuardian 的"进程级防护"**
5. **不需要在鸿蒙上运行 eBPF**——鸿蒙的权限体系和 IPC 审计已提供足够的监控能力
