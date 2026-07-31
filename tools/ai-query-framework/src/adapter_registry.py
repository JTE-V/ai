"""
ai-query-framework/src/adapter_registry.py

适配器注册中心模块
==================
提供适配器的统一注册、发现、热切换和分组管理功能。

类比说明：
- 注册中心 ≈ Node.js 的 require.cache：已加载模块的集中索引
- 注册中心 ≈ Python 的 importlib：模块发现与加载的枢纽
- 热切换   ≈ Kubernetes 的 Rolling Update：无缝切换后端实例
- AdapterGroup ≈ Docker Compose 的 service 定义：一组协作服务的逻辑打包

设计原则：
1. 单例模式确保全局唯一注册中心，避免多实例导致状态不一致
2. 线程安全（threading.Lock）保证并发场景下所有操作原子性
3. 自动监听器分配：每个适配器注册时自动创建对应的 ConversationListener 实例
4. 热切换：同一类型的适配器可在运行时无缝切换，不影响上游调用方
5. 适配器组：将 LLM + 采集器 + 数据源打包为一个逻辑服务单元

使用示例：
    # 获取单例
    registry = AdapterRegistry()

    # 注册适配器
    gpt4 = GPT4Adapter()
    registry.register(gpt4)

    # 按类型获取活跃适配器
    llm = registry.get_active("llm")

    # 热切换到备用适配器
    registry.switch_active("gpt4_primary", "gpt4_backup")

    # 创建适配器组
    registry.create_group("财报查询组", {
        "llm": "gpt4_finance",
        "collector": "web_collector_v2",
        "source": "bloomberg_terminal"
    })
"""

import threading
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

# 从同包导入基类
from adapter_base import BaseAdapter, AdapterStatus

logger = logging.getLogger(__name__)


# ============================================================================
# 适配器组数据类
# ============================================================================

@dataclass
class AdapterGroup:
    """适配器组数据类

    将一组协作的适配器打包为一个逻辑单元，代表一个完整的业务能力。
    一个典型的适配器组包含三种类型的适配器，协同完成一次查询：

        用户提问
           │
           ▼
        ┌─────────────────────────────┐
        │  LLM 适配器                  │  ← 理解自然语言、生成回答
        │  (如 GPT-4 / Claude)         │
        └──────────────┬──────────────┘
                       │ 需要数据
                       ▼
        ┌─────────────────────────────┐
        │  采集器适配器                │  ← 搜索/爬取/调用 API 获取数据
        │  (如 WebCollector)           │
        └──────────────┬──────────────┘
                       │ 读取数据
                       ▼
        ┌─────────────────────────────┐
        │  数据源适配器                │  ← 访问底层数据库/文件系统
        │  (如 Bloomberg / MySQL)      │
        └─────────────────────────────┘

    使用示例：
        AdapterGroup(
            group_name="财报查询组",
            adapters={
                "llm": "gpt4_finance_v1",
                "collector": "web_collector_finance",
                "source": "bloomberg_terminal"
            }
        )

        AdapterGroup(
            group_name="客服对话组",
            adapters={
                "llm": "ernie_bot_cs",
                "collector": "faq_collector",
                "source": "knowledge_base_v3"
            }
        )

    Attributes:
        group_name: 组名称，语义化标识该组的业务用途
        adapters: 适配器类型到适配器 ID 的映射字典。
                  键为适配器类型（"llm"/"collector"/"source"/"algorithm"），
                  值为对应的适配器 ID。
    """
    group_name: str
    adapters: Dict[str, str] = field(default_factory=dict)


# ============================================================================
# 适配器注册中心（单例模式）
# ============================================================================

class AdapterRegistry:
    """适配器注册中心（线程安全单例）

    全局唯一的适配器管理中心，是整个框架的"适配器黄页"。
    负责适配器的全生命周期管理：注册、检索、切换、分组。

    线程安全保证：
        所有公共方法均使用 threading.Lock 保护临界区，
        并发调用不会导致数据竞争或不一致状态。

    单例保证：
        使用双重检查锁定（Double-Checked Locking）模式，
        确保在多线程环境下也只创建一个实例。

    使用示例：
        # 获取单例（多次调用返回同一实例）
        registry = AdapterRegistry()

        # 注册适配器
        registry.register(my_llm_adapter)

        # 获取适配器
        adapter = registry.get("gpt4_primary")

        # 按类型列出
        llm_adapters = registry.list_by_type("llm")

        # 热切换
        registry.switch_active("gpt4_primary", "gpt4_backup")

        # 获取统计信息
        stats = registry.get_stats()

    类比：
        - 相当于 Node.js 的 require.cache：集中管理已加载模块
        - 相当于 Python 的 importlib：模块发现与索引的枢纽
        - 相当于 Spring 的 ApplicationContext：Bean 的注册与查找
    """

    # ---- 单例相关 ----
    _instance: Optional["AdapterRegistry"] = None
    _class_lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "AdapterRegistry":
        """单例模式 __new__ 方法

        使用双重检查锁定（DCL）确保线程安全的单例创建。
        只有在 _instance 为 None 时才进入锁区创建实例。

        Returns:
            AdapterRegistry: 全局唯一的注册中心实例
        """
        if cls._instance is None:
            with cls._class_lock:
                # 二次检查：在锁内再次确认，防止竞态条件
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """初始化注册中心内部数据结构

        注意：由于单例模式下 __init__ 可能被多次调用
        （Python 在 __new__ 返回实例后总会调用 __init__），
        使用 _initialized 标志确保内部状态只初始化一次。
        """
        if self._initialized:
            return
        self._initialized = True

        # 适配器存储：{adapter_id: BaseAdapter}
        # 核心索引，所有适配器实例的集中存放地
        self._adapters: Dict[str, BaseAdapter] = {}

        # 活跃适配器追踪：{adapter_type: adapter_id}
        # 每种类型同时只能有一个活跃适配器对外提供服务
        self._active: Dict[str, str] = {}

        # 适配器组存储：{group_name: AdapterGroup}
        # 预定义的适配器协作组合
        self._groups: Dict[str, AdapterGroup] = {}

        # 监听器映射：{adapter_id: ConversationListener}
        # 每个适配器注册时自动分配一个监听器实例
        self._listeners: Dict[str, Any] = {}

        # 操作锁：保护所有公共方法临界区的互斥锁
        # 确保 register/unregister/switch_active 等操作的原子性
        self._op_lock: threading.Lock = threading.Lock()

        logger.info("AdapterRegistry 单例已初始化，准备就绪")

    @staticmethod
    def _get_id(adapter) -> str:
        return (getattr(adapter, 'adapter_id', None) or
                getattr(getattr(adapter, 'config', None), 'adapter_id', None) or 'unknown')

    @staticmethod
    def _get_type(adapter) -> str:
        return (getattr(adapter, 'adapter_type', None) or
                getattr(getattr(adapter, 'config', None), 'adapter_type', None) or 'llm')

    # ========================================================================
    # 注册与注销
    # ========================================================================

    def register(self, adapter: BaseAdapter) -> bool:
        """注册适配器到注册中心

        注册是适配器纳入管理的入口操作。成功后自动执行：
        1. 将适配器加入内部索引，使其可被检索
        2. 如果该类型尚无活跃适配器，自动将新适配器设为活跃
        3. 自动为适配器分配 ConversationListener 监听器实例

        Args:
            adapter: 实现了 BaseAdapter 接口的适配器实例

        Returns:
            bool: 注册成功返回 True；如果该 adapter_id 已存在则返回 False

        Raises:
            TypeError: 传入的 adapter 不是 BaseAdapter 的子类

        使用示例：
            gpt4 = GPT4Adapter()
            if registry.register(gpt4):
                print("GPT-4 适配器注册成功")
        """
        # 鸭子类型：检查必要接口（兼容 adapter_base.BaseAdapter 和 llm_adapters.BaseAdapter）
        has_id = hasattr(adapter, 'adapter_id') or (
            hasattr(adapter, 'config') and hasattr(adapter.config, 'adapter_id'))
        if not (has_id and hasattr(adapter, 'execute') and hasattr(adapter, 'health_check')):
            raise TypeError(
                f"register() 要求具有 adapter_id/execute/health_check 的对象，收到: {type(adapter).__name__}"
            )

        # 统一 ID/类型获取（兼容两种 BaseAdapter：直接属性 vs config 存储）
        _id = getattr(adapter, 'adapter_id', None) or (
            getattr(getattr(adapter, 'config', None), 'adapter_id', None) or 'unknown')
        _type = getattr(adapter, 'adapter_type', None) or (
            getattr(getattr(adapter, 'config', None), 'adapter_type', None) or 'llm')

        with self._op_lock:
            if _id in self._adapters:
                logger.warning(f"适配器 ID 冲突: '{_id}' 已存在")
                return False

            self._adapters[_id] = adapter
            if _type not in self._active:
                self._active[_type] = _id

            self._assign_listener(adapter)
            logger.info(f"✓ 适配器已注册: id='{_id}' type='{_type}'")
            return True

    def unregister(self, adapter_id: str) -> bool:
        """注销适配器

        从注册中心移除适配器及其所有关联资源。
        注销流程（按顺序执行）：
        1. 验证适配器存在
        2. 如果该适配器是当前活跃适配器，清除活跃标记
        3. 从内部索引中移除
        4. 移除关联的 ConversationListener
        5. 如果适配器仍可用，调用其 shutdown() 方法优雅关闭

        Args:
            adapter_id: 要注销的适配器唯一标识

        Returns:
            bool: 注销成功返回 True；适配器不存在返回 False

        使用示例：
            if registry.unregister("gpt4_legacy"):
                print("旧版适配器已下线")
        """
        with self._op_lock:
            if adapter_id not in self._adapters:
                logger.warning(f"尝试注销不存在的适配器: '{adapter_id}'")
                return False

            adapter = self._adapters[adapter_id]

            # 如果该适配器是活跃适配器，清除活跃标记
            if (AdapterRegistry._get_type(adapter) in self._active and
                    self._active[AdapterRegistry._get_type(adapter)] == adapter_id):
                del self._active[AdapterRegistry._get_type(adapter)]
                logger.info(
                    f"适配器 '{adapter_id}' 的活跃标记已清除，"
                    f"类型 '{AdapterRegistry._get_type(adapter)}' 当前无活跃适配器"
                )

            # 从索引中移除
            del self._adapters[adapter_id]

            # 移除关联的监听器
            if adapter_id in self._listeners:
                del self._listeners[adapter_id]
                logger.debug(f"适配器 '{adapter_id}' 的监听器已移除")

            # 优雅关闭适配器
            if adapter.is_available():
                try:
                    adapter.shutdown()
                    logger.info(f"适配器 '{adapter_id}' 已优雅关闭")
                except Exception as e:
                    logger.error(f"适配器 '{adapter_id}' shutdown 时异常: {e}")

            logger.info(f"✓ 适配器已注销: '{adapter_id}'")
            return True

    # ========================================================================
    # 检索方法
    # ========================================================================

    def get(self, adapter_id: str) -> Optional[BaseAdapter]:
        """根据 ID 获取适配器实例

        这是最常用的检索方法，通过适配器的唯一标识直接获取实例。

        Args:
            adapter_id: 适配器唯一标识

        Returns:
            Optional[BaseAdapter]: 找到返回适配器实例；未找到返回 None

        使用示例：
            adapter = registry.get("gpt4_primary")
            if adapter and adapter.is_available():
                result = adapter.execute({"prompt": "你好"})
        """
        with self._op_lock:
            return self._adapters.get(adapter_id)

    def list_by_type(self, adapter_type: str) -> List[BaseAdapter]:
        """按适配器类型列出所有适配器

        返回指定类型的所有已注册适配器，不区分是否活跃。

        Args:
            adapter_type: 适配器类型字符串
                          - "llm": 大语言模型适配器
                          - "collector": 数据采集器适配器
                          - "source": 数据源适配器
                          - "algorithm": 算法适配器

        Returns:
            List[BaseAdapter]: 该类型的所有适配器列表（可能为空列表）

        使用示例：
            # 列出所有可用的 LLM 适配器
            for llm in registry.list_by_type("llm"):
                print(f"{llm.adapter_id}: {llm.status.value}")
        """
        with self._op_lock:
            return [
                adapter for adapter in self._adapters.values()
                if AdapterRegistry._get_type(adapter) == adapter_type
            ]

    def list_all(self) -> List[BaseAdapter]:
        """列出所有已注册的适配器

        返回注册中心中所有适配器的完整列表。

        Returns:
            List[BaseAdapter]: 全部适配器列表（可能为空列表）

        使用示例：
            for adapter in registry.list_all():
                print(adapter.get_info())
        """
        with self._op_lock:
            return list(self._adapters.values())

    # ========================================================================
    # 活跃适配器管理（含热切换）
    # ========================================================================

    def get_active(self, adapter_type: str) -> Optional[BaseAdapter]:
        """获取指定类型的当前活跃适配器

        每种类型同时只有一个活跃适配器对外提供服务。
        这是上游调用方获取适配器的推荐方式——
        调用方不需要知道具体是哪个适配器，只需按类型获取。

        Args:
            adapter_type: 适配器类型（"llm"/"collector"/"source"/"algorithm"）

        Returns:
            Optional[BaseAdapter]: 活跃适配器实例；该类型无活跃适配器返回 None

        使用示例：
            llm = registry.get_active("llm")
            if llm:
                answer = llm.execute({"prompt": user_question})
        """
        with self._op_lock:
            active_id = self._active.get(adapter_type)
            if active_id:
                return self._adapters.get(active_id)
            return None

    def switch_active(self, adapter_id: str, target_id: str) -> bool:
        """热切换活跃适配器（同一类型适配器间无缝切换）

        将指定类型的活跃服务从当前适配器切换到目标适配器，
        切换过程原子完成，上游调用方无感知。

        切换前置条件（全部满足才执行）：
        1. 源适配器和目标适配器都已注册
        2. 两个适配器类型一致（如同为 "llm"）
        3. 目标适配器当前状态可用（HEALTHY 或 DEGRADED）

        注意：
        - 即使 adapter_id 不是当前活跃适配器，切换仍会执行（仅发出警告）
        - 切换是原子操作，在锁保护下完成

        类比：
        Kubernetes 的 Rolling Update——新 Pod 就绪后切换 Service 指向，
        旧 Pod 逐步下线，流量无损。

        Args:
            adapter_id: 当前活跃（或期望验证）的适配器 ID
            target_id: 要切换到的目标适配器 ID

        Returns:
            bool: 切换成功返回 True；验证失败（条件不满足）返回 False

        使用示例：
            # 将 LLM 服务从主适配器切换到备用适配器
            success = registry.switch_active("gpt4_primary", "gpt4_backup")
            if success:
                print("已切换至备用 GPT-4 适配器")
        """
        with self._op_lock:
            # 验证源适配器存在
            if adapter_id not in self._adapters:
                logger.error(
                    f"热切换失败: 源适配器 '{adapter_id}' 未注册"
                )
                return False

            # 验证目标适配器存在
            if target_id not in self._adapters:
                logger.error(
                    f"热切换失败: 目标适配器 '{target_id}' 未注册"
                )
                return False

            source = self._adapters[adapter_id]
            target = self._adapters[target_id]

            # 验证类型一致（不同类型间切换没有意义）
            if source.adapter_type != target.adapter_type:
                logger.error(
                    f"热切换失败: 适配器类型不匹配——"
                    f"'{adapter_id}' 是 '{source.adapter_type}' 类型，"
                    f"'{target_id}' 是 '{target.adapter_type}' 类型"
                )
                return False

            # 验证目标适配器可用
            if not target.is_available():
                logger.error(
                    f"热切换失败: 目标适配器 '{target_id}' 不可用，"
                    f"当前状态: {target.status.value}"
                )
                return False

            # 检查源适配器是否确实是当前活跃的（非致命，仅警告）
            current_active = self._active.get(source.adapter_type)
            if current_active != adapter_id:
                logger.warning(
                    f"热切换注意: '{adapter_id}' 不是 "
                    f"'{source.adapter_type}' 类型的当前活跃适配器 "
                    f"(当前活跃: '{current_active}')，仍将执行切换"
                )

            # 执行原子切换
            self._active[source.adapter_type] = target_id

            logger.info(
                f"✓ 热切换完成: [{source.adapter_type}] "
                f"'{adapter_id}' → '{target_id}'"
            )
            return True

    # ========================================================================
    # 适配器组管理
    # ========================================================================

    def create_group(self, group_name: str, adapters: Dict[str, str]) -> AdapterGroup:
        """创建适配器组

        适配器组将多个不同类型的适配器打包为一个逻辑服务单元，
        代表一个完整的业务能力组合。

        典型用法：
        - "财报查询组" = LLM(GPT-4) + 采集器(WebCollector) + 数据源(Bloomberg)
        - "客服对话组" = LLM(文心一言) + 采集器(FAQCollector) + 数据源(知识库)

        Args:
            group_name: 组名称，应具有业务语义，如 "财报查询组"、"客服对话组"
            adapters: 类型到适配器 ID 的映射字典
                      如 {"llm": "gpt4_finance", "collector": "web_collector", "source": "bloomberg"}

        Returns:
            AdapterGroup: 创建的适配器组对象

        Raises:
            ValueError: 组名已存在，或引用了未注册的适配器

        使用示例：
            group = registry.create_group("Q3财报组", {
                "llm": "gpt4_finance_v2",
                "collector": "web_collector_stable",
                "source": "bloomberg_terminal"
            })
            print(f"组 {group.group_name} 创建成功")
        """
        with self._op_lock:
            if group_name in self._groups:
                raise ValueError(
                    f"适配器组 '{group_name}' 已存在，请使用不同的组名或先调用 delete_group()"
                )

            # 验证所有引用的适配器都已注册
            for adapter_type, adapter_id in adapters.items():
                if adapter_id not in self._adapters:
                    raise ValueError(
                        f"无法创建组 '{group_name}': "
                        f"适配器 '{adapter_id}' (类型: {adapter_type}) 尚未注册，"
                        f"请先调用 register() 注册该适配器"
                    )

            group = AdapterGroup(group_name=group_name, adapters=dict(adapters))
            self._groups[group_name] = group

            logger.info(
                f"✓ 适配器组已创建: '{group_name}', "
                f"包含 {len(adapters)} 个适配器: {adapters}"
            )
            return group

    def get_group(self, group_name: str) -> Optional[AdapterGroup]:
        """获取适配器组

        Args:
            group_name: 组名称

        Returns:
            Optional[AdapterGroup]: 找到返回组对象；未找到返回 None

        使用示例：
            group = registry.get_group("财报查询组")
            if group:
                llm_id = group.adapters.get("llm")
        """
        with self._op_lock:
            return self._groups.get(group_name)

    def delete_group(self, group_name: str) -> bool:
        """删除适配器组

        注意：删除组不会影响组内适配器——适配器仍然保留在注册中心中，
        只是移除了这个逻辑分组。

        Args:
            group_name: 组名称

        Returns:
            bool: 删除成功返回 True；组不存在返回 False
        """
        with self._op_lock:
            if group_name not in self._groups:
                logger.warning(f"尝试删除不存在的适配器组: '{group_name}'")
                return False
            del self._groups[group_name]
            logger.info(f"✓ 适配器组已删除: '{group_name}'")
            return True

    def list_groups(self) -> List[AdapterGroup]:
        """列出所有适配器组

        Returns:
            List[AdapterGroup]: 所有适配器组列表（可能为空列表）
        """
        with self._op_lock:
            return list(self._groups.values())

    # ========================================================================
    # 监听器管理（内部方法）
    # ========================================================================

    def _assign_listener(self, adapter: BaseAdapter) -> None:
        """为适配器自动分配会话监听器（内部方法）

        每个新注册的适配器都会自动创建一个 ConversationListener 实例。
        监听器用于追踪该适配器相关的会话事件：
        - 会话切换（SESSION_SWITCHED）
        - 历史引用（HISTORY_REFERENCED）
        - 对话轮次新增（TURN_ADDED）
        - 会话压缩检查（COMPRESSION_CHECK）

        监听器与适配器生命周期绑定：
        - 适配器注册时自动创建监听器
        - 适配器注销时自动移除监听器

        如果 ConversationListener 导入失败（如模块不存在），
        不会阻塞注册流程，仅记录警告日志。

        Args:
            adapter: 已注册的适配器实例
        """
        try:
            # 延迟导入以避免模块加载时的循环依赖问题
            # conversation_listener 可能会引用 adapter_registry，
            # 因此在方法内部导入而非模块顶部导入
            from conversation_listener import ConversationListener

            listener = ConversationListener()
            self._listeners[AdapterRegistry._get_id(adapter)] = listener
            logger.debug(
                f"已为适配器 '{AdapterRegistry._get_id(adapter)}' 分配 ConversationListener"
            )
        except ImportError as e:
            logger.warning(
                f"无法为适配器 '{AdapterRegistry._get_id(adapter)}' 分配监听器: "
                f"ConversationListener 导入失败 ({e})。适配器仍正常注册。"
            )
        except Exception as e:
            logger.error(
                f"为适配器 '{AdapterRegistry._get_id(adapter)}' 分配监听器时发生未预期错误: {e}"
            )

    def get_listener(self, adapter_id: str) -> Optional[Any]:
        """获取适配器关联的 ConversationListener

        Args:
            adapter_id: 适配器 ID

        Returns:
            Optional[ConversationListener]: 监听器实例；不存在返回 None
        """
        with self._op_lock:
            return self._listeners.get(adapter_id)

    # ========================================================================
    # 诊断与统计
    # ========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """获取注册中心统计信息

        提供注册中心当前状态的快照，用于：
        - 管理面板展示
        - 监控告警
        - 调试排查

        Returns:
            Dict[str, Any]: 统计信息字典，包含：
                - total_adapters (int): 已注册适配器总数
                - type_distribution (dict): 按类型分布 {类型: 数量}
                - active_adapters (dict): 当前活跃适配器 {类型: adapter_id}
                - total_groups (int): 适配器组总数
                - total_listeners (int): 监听器总数
        """
        with self._op_lock:
            # 计算按类型分布
            type_distribution: Dict[str, int] = {}
            for adapter in self._adapters.values():
                t = AdapterRegistry._get_type(adapter)
                type_distribution[t] = type_distribution.get(t, 0) + 1

            return {
                "total_adapters": len(self._adapters),
                "type_distribution": type_distribution,
                "active_adapters": dict(self._active),
                "total_groups": len(self._groups),
                "total_listeners": len(self._listeners),
            }

    def __repr__(self) -> str:
        """注册中心的可读字符串表示"""
        with self._op_lock:
            return (
                f"<AdapterRegistry("
                f"adapters={len(self._adapters)}, "
                f"active={len(self._active)}, "
                f"groups={len(self._groups)}, "
                f"listeners={len(self._listeners)})>"
            )
