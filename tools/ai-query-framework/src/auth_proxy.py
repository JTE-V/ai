"""
权限代理层 — Auth Proxy
=======================
在查询引擎与数据源之间插入一道权限门禁。所有查询请求都必须经过白名单校验，
未授权请求直接拒绝，绝不进入下游。

类比：
  - AWS IAM / API Gateway Authorizer  — 请求到达 Lambda 之前先检查权限
  - Kubernetes Admission Controller   — 资源创建前先过 webhook
  - Nginx auth_request                — 反向代理转发前先验签

JS 类比：
  - Express.js middleware: app.use(authProxy.checkPermission)
  - Passport.js 的 verify callback

核心组件：
  1. WhitelistConfig  — 白名单规则集（域名/表/接口/API Key 范围）
  2. TempToken        — 临时令牌（TTL + 用完即焚 one-shot）
  3. AuthProxy        — 对外统一的权限代理接口
  4. AuditLog         — 结构化审计日志（JSON，不是纯文本！）
"""

import json
import re
import time
import uuid
import hashlib
import hmac
import threading
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


# ============================================================================
# 1. 枚举 & 数据类
# ============================================================================

class Permission(Enum):
    """权限级别 — 类比 Linux rwx"""
    READ = "read"        # 只读查询
    WRITE = "write"      # 写入（一般不用于 AI 查询框架，预留）
    ADMIN = "admin"      # 管理操作（修改白名单等）
    NONE = "none"        # 无权限


class QueryAction(Enum):
    """查询动作类型"""
    VECTOR_SEARCH = "vector_search"    # 向量库检索
    API_CALL = "api_call"              # API 调用
    WEB_SCRAPE = "web_scrape"         # 网页抓取
    DB_QUERY = "db_query"             # 数据库查询
    TEMPLATE_EXEC = "template_exec"   # 模板执行


# ============================================================================
# 2. WhitelistConfig — 白名单配置
# ============================================================================
# 类比：
#   AWS IAM Policy Document  — 声明谁可以访问什么资源
#   Firebase Security Rules  — 路径 + 条件的规则集
#
# JS 类比：
#   interface WhitelistRule {
#     domain?: string;
#     table?: string;
#     apiEndpoint?: string;
#     apiKeyScopes?: string[];
#     permission: Permission;
#   }
# ============================================================================

@dataclass
class WhitelistRule:
    """
    单条白名单规则。

    字段：
      domain       : str        — 允许的域名（支持通配符 *.example.com）
      table        : str        — 允许的数据库表名
      api_endpoint : str        — 允许的 API 端点前缀
      api_key_scopes: List[str] — API Key 允许的 scope 列表
      permission   : Permission — 授权的权限级别
      description  : str        — 规则说明
    """
    permission: Permission = Permission.READ
    domain: Optional[str] = None
    table: Optional[str] = None
    api_endpoint: Optional[str] = None
    api_key_scopes: List[str] = field(default_factory=list)
    description: str = ""

    def matches_domain(self, target: str) -> bool:
        """
        域名匹配（支持通配符）。

        示例：
          rule.domain = "*.example.com"
          target = "api.example.com"  → True
          target = "evil.com"         → False

        JS 类比：
          new RegExp('^' + rule.domain.replace(/\*/g, '[^.]+') + '$').test(target)
        """
        if self.domain is None:
            return False
        # 将通配符 * 转为正则：* 匹配除点外的任意字符
        pattern = "^" + re.escape(self.domain).replace(r"\*", r"[^.]+") + "$"
        return bool(re.match(pattern, target, re.IGNORECASE))

    def matches_table(self, target: str) -> bool:
        """精确匹配表名（大小写不敏感）"""
        if self.table is None:
            return False
        return self.table.lower() == target.lower()

    def matches_api(self, target: str) -> bool:
        """API 端点前缀匹配"""
        if self.api_endpoint is None:
            return False
        return target.lower().startswith(self.api_endpoint.lower())

    def matches_scope(self, required_scope: str) -> bool:
        """检查 API Key scope 是否包含所需权限"""
        return required_scope in self.api_key_scopes


class WhitelistConfig:
    """
    白名单配置管理器。

    维护一组 WhitelistRule，提供增删查改 + 批量匹配。

    JS 类比：
      class WhitelistConfig {
        private rules: WhitelistRule[] = [];
        addRule(rule): void;
        match(request): WhitelistRule | null;
      }
    """

    def __init__(self):
        """初始化空白名单"""
        self._rules: List[WhitelistRule] = []
        self._lock = threading.Lock()  # 线程安全 — 类比 Python GIL 不够时的显式锁

    # ---- CRUD ----

    def add_rule(self, rule: WhitelistRule) -> None:
        """添加一条白名单规则"""
        with self._lock:
            self._rules.append(rule)

    def remove_rule(self, index: int) -> bool:
        """按索引删除规则，返回是否成功"""
        with self._lock:
            if 0 <= index < len(self._rules):
                self._rules.pop(index)
                return True
            return False

    def list_rules(self) -> List[Dict[str, Any]]:
        """列出所有规则（只读副本）"""
        with self._lock:
            return [
                {
                    "index": i,
                    "permission": r.permission.value,
                    "domain": r.domain,
                    "table": r.table,
                    "api_endpoint": r.api_endpoint,
                    "api_key_scopes": r.api_key_scopes,
                    "description": r.description,
                }
                for i, r in enumerate(self._rules)
            ]

    def clear(self) -> None:
        """清空白名单"""
        with self._lock:
            self._rules.clear()

    # ---- 匹配 ----

    def find_matching_rules(
        self,
        *,
        domain: Optional[str] = None,
        table: Optional[str] = None,
        api_endpoint: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> List[WhitelistRule]:
        """
        查找所有匹配给定条件的规则。

        返回匹配列表（可能多条），由调用方判断最高权限。
        """
        with self._lock:
            matches: List[WhitelistRule] = []
            for rule in self._rules:
                match = True
                if domain is not None and not rule.matches_domain(domain):
                    match = False
                if table is not None and not rule.matches_table(table):
                    match = False
                if api_endpoint is not None and not rule.matches_api(api_endpoint):
                    match = False
                if scope is not None and not rule.matches_scope(scope):
                    match = False
                if match:
                    matches.append(rule)
            return matches

    def has_permission(
        self,
        required: Permission,
        **kwargs,
    ) -> bool:
        """
        快捷方法：是否有某种权限？
        只要有一条匹配规则满足权限要求即返回 True。
        """
        rules = self.find_matching_rules(**kwargs)
        # 权限优先级：ADMIN > WRITE > READ > NONE
        permission_rank = {
            Permission.NONE: 0,
            Permission.READ: 1,
            Permission.WRITE: 2,
            Permission.ADMIN: 3,
        }
        required_rank = permission_rank[required]
        for rule in rules:
            if permission_rank.get(rule.permission, 0) >= required_rank:
                return True
        return False


# ============================================================================
# 3. TempToken — 临时令牌
# ============================================================================
# 类比：
#   AWS STS (Security Token Service)  — 临时凭证，有过期时间
#   JWT 的 exp claim                  — 到期自动失效
#   One-time pad                      — 用完即销毁
#
# JS 类比：
#   const token = jwt.sign({ scope, exp }, secret);
#   使用后从 Redis 中删除。
# ============================================================================

@dataclass
class TempToken:
    """
    临时令牌：TTL + 用完即焚（one-shot）。

    字段：
      token_id   : str    — 唯一令牌 ID（UUID）
      scope      : str    — 令牌授权范围（如 "read:products"）
      issued_at  : float  — 签发时间戳（epoch seconds）
      ttl_seconds: int    — 存活秒数
      used       : bool   — 是否已被消费（one-shot 标记）
      metadata   : dict   — 附加元数据（请求来源等）
    """
    token_id: str
    scope: str
    issued_at: float
    ttl_seconds: int
    used: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """检查令牌是否已过期"""
        now = time.time()
        return (now - self.issued_at) > self.ttl_seconds

    def is_valid(self) -> bool:
        """令牌是否仍然有效（未过期 + 未使用）"""
        return (not self.used) and (not self.is_expired())

    def consume(self) -> bool:
        """
        消费令牌（one-shot）。

        返回 True 表示消费成功，False 表示已被消费或过期。

        JS 类比：
          if (token.used || token.isExpired()) throw new Error('Token invalid');
          token.used = true;
        """
        if not self.is_valid():
            return False
        self.used = True
        return True

    def remaining_seconds(self) -> float:
        """剩余有效秒数"""
        return max(0.0, self.ttl_seconds - (time.time() - self.issued_at))


class TokenStore:
    """
    令牌存储器（线程安全）。

    类比：
      Redis 的 SETEX + GET + DEL
      生产环境可替换为真正的 Redis 后端

    JS 类比：
      const tokenStore = new Map<string, TempToken>();
    """

    def __init__(self):
        self._tokens: Dict[str, TempToken] = {}
        self._lock = threading.Lock()

    def save(self, token: TempToken) -> None:
        """保存令牌"""
        with self._lock:
            self._tokens[token.token_id] = token

    def get(self, token_id: str) -> Optional[TempToken]:
        """获取令牌（不消费）"""
        with self._lock:
            return self._tokens.get(token_id)

    def consume(self, token_id: str) -> Optional[TempToken]:
        """
        获取并消费令牌（one-shot）。
        返回 None 表示令牌无效或已被消费。
        """
        with self._lock:
            token = self._tokens.get(token_id)
            if token is None:
                return None
            if not token.consume():
                return None
            # 消费后从存储中移除（用完即焚）
            del self._tokens[token_id]
            return token

    def cleanup_expired(self) -> int:
        """清理过期令牌，返回清理数量"""
        with self._lock:
            expired_ids = [
                tid for tid, t in self._tokens.items() if t.is_expired()
            ]
            for tid in expired_ids:
                del self._tokens[tid]
            return len(expired_ids)

    @property
    def active_count(self) -> int:
        """当前活跃令牌数"""
        with self._lock:
            return len(self._tokens)


# ============================================================================
# 4. AuditLog — 结构化审计日志
# ============================================================================
# 关键设计：输出 JSON，不是纯文本！
# 目的：方便存入 Elasticsearch / Splunk / ClickHouse 做分析和告警
#
# JS 类比：
#   const auditLog = {
#     timestamp: new Date().toISOString(),
#     event: 'QUERY_DENIED',
#     details: { ... }
#   };
#   console.log(JSON.stringify(auditLog));
# ============================================================================

class AuditEvent(Enum):
    """审计事件类型"""
    QUERY_ALLOWED = "QUERY_ALLOWED"          # 查询放行
    QUERY_DENIED = "QUERY_DENIED"            # 查询拒绝
    TOKEN_ISSUED = "TOKEN_ISSUED"            # 令牌签发
    TOKEN_CONSUMED = "TOKEN_CONSUMED"        # 令牌消费
    TOKEN_EXPIRED = "TOKEN_EXPIRED"          # 令牌过期
    WHITELIST_MODIFIED = "WHITELIST_MODIFIED" # 白名单变更
    AUTH_ERROR = "AUTH_ERROR"                # 认证异常


@dataclass
class AuditEntry:
    """
    单条审计日志条目 — 全部结构化字段，便于机器处理。

    字段：
      event      : AuditEvent  — 事件类型
      timestamp  : str         — ISO 8601 时间戳
      subject    : str         — 操作主体（API Key ID / 用户 ID）
      action     : str         — 动作描述
      resource   : str         — 目标资源
      result     : str         — "allowed" / "denied" / "error"
      details    : dict        — 附加详情（查询参数等）
      request_id : str         — 请求追踪 ID（用于全链路追踪）
    """
    event: AuditEvent
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    subject: str = "anonymous"
    action: str = ""
    resource: str = ""
    result: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    request_id: str = ""

    def to_json(self) -> str:
        """
        导出为 JSON 字符串（一行，适合日志收集）。

        JS 类比：
          JSON.stringify(auditEntry)
        """
        return json.dumps(
            {
                "event": self.event.value,
                "timestamp": self.timestamp,
                "subject": self.subject,
                "action": self.action,
                "resource": self.resource,
                "result": self.result,
                "details": self.details,
                "request_id": self.request_id,
            },
            ensure_ascii=False,
            separators=(",", ":"),  # 紧凑格式，节省日志存储
        )

    def to_dict(self) -> Dict[str, Any]:
        """导出为 Python dict"""
        return {
            "event": self.event.value,
            "timestamp": self.timestamp,
            "subject": self.subject,
            "action": self.action,
            "resource": self.resource,
            "result": self.result,
            "details": self.details,
            "request_id": self.request_id,
        }


class AuditLogger:
    """
    审计日志记录器。

    生产环境可以：
      - 写入文件（JSON Lines）
      - 发送到 Kafka / Elasticsearch
      - 通过 syslog 或 stdout 让日志采集器拉取

    JS 类比：
      class AuditLogger {
        log(entry: AuditEntry): void {
          process.stdout.write(JSON.stringify(entry) + '\n');
        }
      }
    """

    def __init__(self, output_handler: Optional[Callable] = None):
        """
        参数：
          output_handler : callable  — 自定义输出函数，签名为 (str) -> None
                                      默认 print() 到 stdout
        """
        self._handler = output_handler or (lambda line: print(line, flush=True))
        self._entries: List[AuditEntry] = []  # 内存中保留最近 N 条

    def log(self, entry: AuditEntry) -> None:
        """记录一条审计日志"""
        self._entries.append(entry)
        # 只保留最近 1000 条在内存中
        if len(self._entries) > 1000:
            self._entries = self._entries[-1000:]
        # 输出 JSON 行
        self._handler(entry.to_json())

    def recent_entries(self, n: int = 10) -> List[Dict[str, Any]]:
        """获取最近 N 条日志"""
        return [e.to_dict() for e in self._entries[-n:]]


# ============================================================================
# 5. AuthProxy — 统一权限代理
# ============================================================================
# 这是对外的唯一入口。所有查询请求都走这里。
#
# 流程：
#   Request → check_permission() → 白名单匹配 → 放行/拒绝
#            → issue_token()     → 签发临时令牌
#            → audit_log()       → 无论放行还是拒绝都记日志
#
# JS 类比：
#   class AuthProxy {
#     middleware(req, res, next) {
#       if (!this.checkPermission(req.context)) {
#         return res.status(403).json({ error: 'Forbidden' });
#       }
#       next();
#     }
#   }
# ============================================================================


class AuthProxy:
    """
    权限代理层 — 查询请求的守门人。

    属性：
      whitelist : WhitelistConfig  — 白名单配置
      token_store : TokenStore     — 令牌存储器
      audit_logger : AuditLogger   — 审计日志记录器
      api_secret : str             — HMAC 签名密钥（签发令牌用）
    """

    def __init__(self, api_secret: Optional[str] = None):
        """
        初始化权限代理。

        参数：
          api_secret : str — HMAC 签名密钥；不提供则自动生成（仅开发环境）
        """
        self.whitelist = WhitelistConfig()
        self.token_store = TokenStore()
        self.audit_logger = AuditLogger()
        self.api_secret = api_secret or uuid.uuid4().hex  # 生产环境必须显式提供！
        self._request_counter: int = 0  # 请求计数器

    # ------------------------------------------------------------------
    # 5a. 权限校验 — 白名单检查
    # ------------------------------------------------------------------
    def check_permission(
        self,
        query_context: Dict[str, Any],
        *,
        required_permission: Permission = Permission.READ,
    ) -> Tuple[bool, str]:
        """
        检查查询上下文是否通过白名单校验。

        参数：
          query_context : dict  — 查询上下文，包含：
            {
              "domain": "api.example.com",        # 目标域名
              "table": "products",                 # 目标表（可选）
              "api_endpoint": "/v1/search",        # API 端点（可选）
              "scope": "read:products",            # 请求的 scope
              "api_key": "sk-xxx",                 # API Key（可选）
              "action": "vector_search",           # 动作类型
              "subject": "user_123",               # 操作主体
            }
          required_permission : Permission — 所需最低权限

        返回：
          (allowed: bool, reason: str)
            - (True, "matched rule #2")  — 通过
            - (False, "no matching rule") — 拒绝

        JS 类比：
          function checkPermission(ctx) {
            const rules = whitelist.findMatchingRules(ctx.domain, ctx.table);
            return rules.some(r => r.permission >= required);
          }
        """
        request_id = query_context.get("request_id", str(uuid.uuid4())[:8])
        subject = query_context.get("subject", "anonymous")
        action = query_context.get("action", "unknown")
        domain = query_context.get("domain")
        table = query_context.get("table")
        api_endpoint = query_context.get("api_endpoint")
        scope = query_context.get("scope")

        # ---- 步骤1：查找匹配规则 ----
        matching_rules = self.whitelist.find_matching_rules(
            domain=domain,
            table=table,
            api_endpoint=api_endpoint,
            scope=scope,
        )

        if not matching_rules:
            # 没有任何规则匹配 → 直接拒绝
            reason = f"没有匹配的白名单规则: domain={domain}, table={table}"
            self._audit_deny(subject, action, str(domain or table), reason, request_id)
            return False, reason

        # ---- 步骤2：检查权限级别是否足够 ----
        permission_rank = {
            Permission.NONE: 0,
            Permission.READ: 1,
            Permission.WRITE: 2,
            Permission.ADMIN: 3,
        }
        required_rank = permission_rank[required_permission]

        for rule in matching_rules:
            if permission_rank.get(rule.permission, 0) >= required_rank:
                # 找到一条权限足够的规则 → 放行
                reason = f"匹配规则: {rule.description or rule.domain or rule.table}"
                self._audit_allow(subject, action, str(domain or table), reason, request_id)
                return True, reason

        # ---- 步骤3：有匹配但权限不足 → 拒绝 ----
        reason = f"权限不足: 需要 {required_permission.value}, 最高只有 {matching_rules[0].permission.value}"
        self._audit_deny(subject, action, str(domain or table), reason, request_id)
        return False, reason

    # ------------------------------------------------------------------
    # 5b. 签发临时令牌
    # ------------------------------------------------------------------
    def issue_token(
        self,
        scope: str,
        ttl: int = 300,
        *,
        subject: str = "anonymous",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TempToken:
        """
        签发一个临时令牌。

        参数：
          scope    : str   — 授权范围，如 "read:products"
          ttl      : int   — 存活秒数，默认 300 秒（5 分钟）
          subject  : str   — 操作主体
          metadata : dict  — 附加元数据

        返回：
          TempToken — 已签发的令牌对象

        JS 类比：
          const token = jwt.sign({ scope, sub: subject }, secret, { expiresIn: ttl });
        """
        token = TempToken(
            token_id=str(uuid.uuid4()),
            scope=scope,
            issued_at=time.time(),
            ttl_seconds=ttl,
            used=False,
            metadata=metadata or {},
        )
        self.token_store.save(token)

        # 审计日志
        self.audit_logger.log(AuditEntry(
            event=AuditEvent.TOKEN_ISSUED,
            subject=subject,
            action="issue_token",
            resource=scope,
            result="allowed",
            details={
                "token_id": token.token_id,
                "ttl": ttl,
                "scope": scope,
            },
        ))

        return token

    # ------------------------------------------------------------------
    # 5c. 验证并消费令牌
    # ------------------------------------------------------------------
    def verify_and_consume_token(self, token_id: str) -> Tuple[bool, str]:
        """
        验证令牌有效性并消费（one-shot）。

        参数：
          token_id : str — 令牌 ID

        返回：
          (valid: bool, message: str)
        """
        token = self.token_store.consume(token_id)

        if token is None:
            self.audit_logger.log(AuditEntry(
                event=AuditEvent.TOKEN_EXPIRED,
                action="verify_token",
                resource=token_id,
                result="denied",
                details={"reason": "token not found or already consumed"},
            ))
            return False, "令牌无效或已被消费"

        self.audit_logger.log(AuditEntry(
            event=AuditEvent.TOKEN_CONSUMED,
            action="consume_token",
            resource=token.scope,
            result="allowed",
            details={
                "token_id": token_id,
                "scope": token.scope,
                "remaining_seconds_at_consume": token.remaining_seconds(),
            },
        ))
        return True, f"令牌有效，scope={token.scope}"

    # ------------------------------------------------------------------
    # 5d. 审计日志快捷方法
    # ------------------------------------------------------------------
    def audit_log(self, entry: AuditEntry) -> None:
        """
        手动记录一条审计日志。

        参数：
          entry : AuditEntry — 结构化审计条目
        """
        self.audit_logger.log(entry)

    # ------------------------------------------------------------------
    # 内部辅助
    # ------------------------------------------------------------------
    def _audit_allow(
        self,
        subject: str,
        action: str,
        resource: str,
        reason: str,
        request_id: str,
    ) -> None:
        """快捷记录放行审计"""
        self.audit_logger.log(AuditEntry(
            event=AuditEvent.QUERY_ALLOWED,
            subject=subject,
            action=action,
            resource=resource,
            result="allowed",
            details={"reason": reason},
            request_id=request_id,
        ))

    def _audit_deny(
        self,
        subject: str,
        action: str,
        resource: str,
        reason: str,
        request_id: str,
    ) -> None:
        """快捷记录拒绝审计"""
        self.audit_logger.log(AuditEntry(
            event=AuditEvent.QUERY_DENIED,
            subject=subject,
            action=action,
            resource=resource,
            result="denied",
            details={"reason": reason},
            request_id=request_id,
        ))

    # ------------------------------------------------------------------
    # 5e. 定时清理
    # ------------------------------------------------------------------
    def cleanup_expired_tokens(self) -> int:
        """清理过期令牌，建议在后台线程中定期调用"""
        count = self.token_store.cleanup_expired()
        if count > 0:
            self.audit_logger.log(AuditEntry(
                event=AuditEvent.TOKEN_EXPIRED,
                action="cleanup",
                resource="token_store",
                result="allowed",
                details={"cleaned_count": count},
            ))
        return count


# ============================================================================
# 6. 便捷函数 — 快速搭建默认白名单
# ============================================================================

def create_default_whitelist() -> WhitelistConfig:
    """
    创建一个带常用规则的白名单，方便快速启动。

    规则包括：
      - 本地开发域名
      - 常见公开 API
      - 测试用数据库表
    """
    wl = WhitelistConfig()
    # 规则1：允许本地开发环境所有操作
    wl.add_rule(WhitelistRule(
        permission=Permission.ADMIN,
        domain="localhost",
        description="本地开发环境 — 全部放行",
    ))
    # 规则2：允许读取公开 API
    wl.add_rule(WhitelistRule(
        permission=Permission.READ,
        domain="*.public-api.com",
        description="公开 API — 只读",
    ))
    # 规则3：允许读取 wiki 类站点
    wl.add_rule(WhitelistRule(
        permission=Permission.READ,
        domain="*.wikipedia.org",
        description="Wikipedia — 只读",
    ))
    # 规则4：允许读取测试数据库的 products 表
    wl.add_rule(WhitelistRule(
        permission=Permission.READ,
        table="products",
        description="Products 表 — 只读",
    ))
    return wl


# ============================================================================
# 7. 自测入口
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("AuthProxy 自测")
    print("=" * 60)

    # ---- 初始化 ----
    proxy = AuthProxy(api_secret="test-secret-123")
    proxy.whitelist = create_default_whitelist()

    # ---- 测试1：白名单放行 ----
    print("\n[测试1] check_permission — 白名单放行")
    ctx = {
        "domain": "api.public-api.com",
        "action": "api_call",
        "subject": "test_user",
        "request_id": "req-001",
    }
    allowed, reason = proxy.check_permission(ctx)
    print(f"  结果: {'✓ 放行' if allowed else '✗ 拒绝'} — {reason}")

    # ---- 测试2：白名单拒绝 ----
    print("\n[测试2] check_permission — 未授权域名拒绝")
    ctx_bad = {
        "domain": "evil-hacker.com",
        "action": "web_scrape",
        "subject": "unknown",
        "request_id": "req-002",
    }
    allowed, reason = proxy.check_permission(ctx_bad)
    print(f"  结果: {'✓ 放行' if allowed else '✗ 拒绝'} — {reason}")

    # ---- 测试3：签发并消费令牌 ----
    print("\n[测试3] issue_token + verify_and_consume_token")
    token = proxy.issue_token(
        scope="read:products",
        ttl=60,
        subject="test_user",
        metadata={"purpose": "testing"},
    )
    print(f"  签发令牌: {token.token_id} (scope={token.scope}, ttl={token.ttl_seconds}s)")

    valid, msg = proxy.verify_and_consume_token(token.token_id)
    print(f"  第一次消费: {'✓' if valid else '✗'} — {msg}")

    # 第二次消费同一令牌 → 应失败（one-shot）
    valid2, msg2 = proxy.verify_and_consume_token(token.token_id)
    print(f"  第二次消费: {'✓' if valid2 else '✗'} — {msg2}")

    # ---- 测试4：审计日志 JSON 输出 ----
    print("\n[测试4] 审计日志（JSON 格式）")
    for entry in proxy.audit_logger.recent_entries(5):
        print(f"  {json.dumps(entry, ensure_ascii=False)}")

    # ---- 测试5：令牌过期 ----
    print("\n[测试5] 令牌过期测试")
    token2 = proxy.issue_token(scope="read:test", ttl=1, subject="test")
    print(f"  签发短令牌: {token2.token_id} (ttl=1s)")
    print(f"  等待2秒后...")
    time.sleep(2)
    valid3, msg3 = proxy.verify_and_consume_token(token2.token_id)
    print(f"  消费结果: {'✓' if valid3 else '✗'} — {msg3}")

    # ---- 测试6：白名单规则列表 ----
    print("\n[测试6] 当前白名单规则")
    for rule in proxy.whitelist.list_rules():
        print(f"  [{rule['index']}] {rule['permission']:6s} | "
              f"domain={rule['domain'] or '-':25s} | "
              f"table={rule['table'] or '-':15s} | "
              f"{rule['description']}")

    print("\n" + "=" * 60)
    print("全部测试完成 ✓")
    print("=" * 60)
