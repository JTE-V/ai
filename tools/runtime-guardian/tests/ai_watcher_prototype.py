#!/usr/bin/env python3
"""
AI 永驻监听原型 — 验证"监听+调研+压缩存储+永不关闭"可行性

架构映射：
  protect_plass          →  本原型
  ─────────────────────     ─────────
  eBPF tracepoint       →  aiohttp 定时爬取
  perf ring buffer      →  jsonl.gz 压缩队列
  baseline_detector     →  diff 调研器（变化检测）
  MultiUserProfiler     →  多站点独立监控
  Watchdog 120s         →  signal + 心跳线程
  GracefulDegrader      →  超时降级策略

运行: python3 ai_watcher.py
Ctrl+C 优雅退出，永不卡死
"""
import asyncio, gzip, json, signal, time, sys, os
from datetime import datetime
from urllib.parse import urlparse

# ==================== 配置 ====================
WATCH_LIST = [
    "https://example.com",
    "https://httpbin.org/json",
]
CHECK_INTERVAL = 30  # 秒
DATA_DIR = "/tmp/ai_watcher_data"
# =============================================

os.makedirs(DATA_DIR, exist_ok=True)
running = True
exit_now = False

def shutdown(sig, frame):
    global running, exit_now
    if exit_now:
        os._exit(0)
    exit_now = True
    running = False
    print(f"\n🛑 收到信号{sig}，退出中...(再按强杀)")

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

class PageStore:
    """压缩存储 — 类比 conversation_manager 的 .json.gz"""
    
    @staticmethod
    def save(url: str, content: str, status: int):
        domain = urlparse(url).netloc
        ts = datetime.now().isoformat()
        entry = {"url": url, "ts": ts, "status": status,
                 "content": content[:2000], "len": len(content)}
        
        path = os.path.join(DATA_DIR, f"{domain}.jsonl.gz")
        with gzip.open(path, "at", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

class DiffChecker:
    """调研器 — 类比 baseline_detector 的异常检测"""
    
    def __init__(self):
        self._last = {}
    
    def check(self, url: str, content: str) -> dict:
        prev = self._last.get(url, "")
        changed = (prev != content)
        self._last[url] = content
        return {"changed": changed, "old_len": len(prev), "new_len": len(content)}

async def fetch(session, url: str):
    """监听者 — 类比 eBPF tracepoint 挂钩"""
    try:
        async with session.get(url, timeout=10) as resp:
            return await resp.text(), resp.status
    except Exception as e:
        return str(e), 0

async def main():
    import aiohttp
    store = PageStore()
    checker = DiffChecker()
    
    print(f"🚀 AI 永驻监听启动 | {len(WATCH_LIST)}个站点 | {CHECK_INTERVAL}s间隔")
    print(f"   数据目录: {DATA_DIR}")
    print(f"   Ctrl+C 退出\n")
    
    # 心跳线程 — 类比 watchdog
    def heartbeat():
        start = time.time()
        while running:
            time.sleep(60)
            if running:
                print(f"💓 心跳 OK | 运行{(time.time()-start)/60:.0f}分钟")
    import threading
    threading.Thread(target=heartbeat, daemon=True).start()
    
    async with aiohttp.ClientSession() as session:
        while running:
            for url in WATCH_LIST:
                if not running: break
                content, status = await fetch(session, url)
                entry = store.save(url, content, status)
                diff = checker.check(url, content)
                
                icon = "🔄" if diff["changed"] else "✅"
                print(f"{icon} {urlparse(url).netloc} | "
                      f"状态={status} | 长度={entry['len']} | "
                      f"变化={'是' if diff['changed'] else '否'}")
            
            if running:
                await asyncio.sleep(CHECK_INTERVAL)
    
    print(f"\n📊 数据保存在 {DATA_DIR}/")
    print("👋 退出")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        print("👋 已退出")
        os._exit(0)
