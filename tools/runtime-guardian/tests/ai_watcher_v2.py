#!/usr/bin/env python3
"""
AI 永驻监听 + AIQuery 联动原型
=================================
监听者抓变化 → 调研者判异常 → AIQuery管道处理 → 压缩归档

架构串联：
  ai_watcher (监听者)          AIQuery (处理者)
  ─────────────────────        ─────────────────
  PageStore.save()     →       template.render()
  DiffChecker.check()  →       orchestrator.execute()
  变化=是              →       触发AI查询管道
  jsonl.gz 归档         ←       conversation_manager 压缩存储

运行: python3 ai_watcher_v2.py
"""

import asyncio, gzip, json, signal, time, os, sys
from datetime import datetime
from urllib.parse import urlparse

# === 路径 ===
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ai-query-framework', 'src'))

# === 配置 ===
WATCH_LIST = ["https://httpbin.org/json"]
CHECK_INTERVAL = 30
DATA_DIR = "/tmp/ai_watcher_v2"

os.makedirs(DATA_DIR, exist_ok=True)
running = True
exit_now = False

def shutdown(sig, frame):
    global running, exit_now
    if exit_now: os._exit(0)
    exit_now = True; running = False
    print(f"\n🛑 退出中...")

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


# ═══════════════════════════════════════════════
# 监听者 + 调研者（protect_plass → 本原型平移）
# ═══════════════════════════════════════════════

class PageStore:
    """压缩存储 — 对应 conversation_manager 的 .json.gz"""
    @staticmethod
    def save(url: str, content: str, status: int):
        domain = urlparse(url).netloc
        entry = {"url": url, "ts": datetime.now().isoformat(),
                 "status": status, "content": content[:3000], "len": len(content)}
        path = os.path.join(DATA_DIR, f"{domain}.jsonl.gz")
        with gzip.open(path, "at", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

class DiffChecker:
    """调研器 — 对应 baseline_detector 的异常检测"""
    def __init__(self):
        self._last = {}
    def check(self, url: str, content: str) -> dict:
        prev = self._last.get(url, "")
        changed = (prev != content)
        self._last[url] = content
        return {"changed": changed, "old_len": len(prev), "new_len": len(content)}


# ═══════════════════════════════════════════════
# AIQuery 处理者（收到变化后触发）
# ═══════════════════════════════════════════════

class AIQueryHandler:
    """
    AIQuery 管道入口 — 收到变化后:
      1. 用 template_engine 渲染处理模板
      2. 用 query_guardian 管理调用生命周期（超时/熔断/降级）
      3. 结果返回 + 压缩归档
    
    对应架构：
      template_engine.py   → render_template()
      query_guardian.py    → ask() with timeout
      orchestrator.py      → 编排流程
    """
    
    def __init__(self):
        self._guardian = None  # QueryGuardian 实例（延迟加载）
        self._template = None  # AITemplate 实例
    
    def handle_change(self, url: str, old_len: int, new_len: int):
        """收到变化回调 → 模拟 AIQuery 管道处理"""
        
        # 步骤1: 模板渲染（对应 template_engine）
        context = {
            "url": url, "old_len": old_len, "new_len": new_len,
            "delta": new_len - old_len, "time": datetime.now().isoformat()
        }
        prompt = f"[AIQuery 模板渲染] 检测到 {url} 内容变化 ({old_len}→{new_len}字节, delta={context['delta']})"
        
        # 步骤2: 模拟算法调用（对应 query_guardian.ask()）
        # 实际生产环境这里调用 orchestrator.execute()
        result = self._simulate_llm_call(prompt, timeout=10)
        
        # 步骤3: 压缩归档（对应 conversation_manager.add_turn + compress）
        self._archive(prompt, result)
        
        return result
    
    def _simulate_llm_call(self, prompt: str, timeout: int) -> str:
        """模拟 LLM 调用 — 对应 query_guardian.ask() 的看门狗+超时"""
        import random
        if random.random() < 0.1:  # 10% 概率模拟降级
            return "[降级回答] 内容已变化，建议人工查看"
        return f"[AI 分析] 页面更新 {len(prompt)} 字符，delta 在正常范围"
    
    def _archive(self, prompt: str, result: str):
        """压缩归档 — 对应 conversation_manager.compress_session"""
        path = os.path.join(DATA_DIR, "ai_archive.jsonl.gz")
        entry = {"ts": datetime.now().isoformat(), "prompt": prompt[:500],
                 "result": result, "degraded": "降级" in result}
        with gzip.open(path, "at", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ═══════════════════════════════════════════════
# 主循环（窗口不关）
# ═══════════════════════════════════════════════

async def fetch(session, url: str):
    try:
        async with session.get(url, timeout=10) as resp:
            return await resp.text(), resp.status
    except Exception as e:
        return str(e), 0

async def main():
    import aiohttp
    store = PageStore()
    checker = DiffChecker()
    ai_handler = AIQueryHandler()
    
    print("╔══════════════════════════════════════════╗")
    print("║ AI 永驻监听 v2 — AIQuery 联动原型       ║")
    print("╠══════════════════════════════════════════╣")
    print("║ 监听者: aiohttp 定时爬取                ║")
    print("║ 调研者: diff 变化检测                   ║")
    print("║ 处理者: AIQuery 管道（模板+看门狗+降级）║")
    print("║ 归档:   jsonl.gz 压缩存储               ║")
    print("╚══════════════════════════════════════════╝")
    print(f"\n   监控 {len(WATCH_LIST)} 站点 | {CHECK_INTERVAL}s 间隔 | {DATA_DIR}/")
    print("   Ctrl+C 退出\n")
    
    import threading
    def heartbeat():
        start = time.time()
        while running:
            time.sleep(60)
            if running:
                print(f"💓 心跳 OK | 运行{(time.time()-start)/60:.0f}分钟")
    threading.Thread(target=heartbeat, daemon=True).start()
    
    async with aiohttp.ClientSession() as session:
        while running:
            for url in WATCH_LIST:
                if not running: break
                content, status = await fetch(session, url)
                entry = store.save(url, content, status)
                diff = checker.check(url, content)
                
                icon = "🔄" if diff["changed"] else "✅"
                msg = f"{icon} {urlparse(url).netloc} | 状态={status} | 长度={entry['len']}"
                
                # === 核心联动点：变化时触发 AIQuery ===
                if diff["changed"]:
                    ai_result = ai_handler.handle_change(
                        url, diff["old_len"], diff["new_len"])
                    msg += f"\n   🤖 {ai_result}"
                
                print(msg)
            
            if running:
                await asyncio.sleep(CHECK_INTERVAL)
    
    print(f"\n📊 归档在 {DATA_DIR}/")
    print("👋 退出")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        os._exit(0)
