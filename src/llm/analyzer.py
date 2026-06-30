"""LLM分析引擎

整合LLM Provider、Prompt模板和缓存管理，提供高层分析接口
"""

import json
import logging
import platform
from typing import Dict, Any, Optional, List, Generator

from src.llm.provider import LLMProvider, get_llm_provider, CacheManager
from src.llm.prompts import (
    build_analysis_prompt,
    build_remediation_prompt,
    build_chat_system_prompt,
    build_log_analysis_prompt,
    get_quick_answer,
)

logger = logging.getLogger("ebpf-diagnoser.llm.analyzer")


class LLMAnalyzer:
    """LLM分析引擎

    提供以下分析能力:
    - 智能分析报告
    - 自动修复建议
    - 交互式问答
    - 日志智能分析
    """

    def __init__(self, provider: LLMProvider, cache_enabled: bool = True,
                 cache_dir: str = "~/.cache/ebpf-diagnoser/llm",
                 max_input_tokens: int = 8000):
        """初始化LLM分析引擎

        Args:
            provider: LLM Provider实例
            cache_enabled: 是否启用缓存
            cache_dir: 缓存目录
            max_input_tokens: 单次最大输入token数
        """
        self.provider = provider
        self.cache = CacheManager(cache_dir, cache_enabled)
        self.max_input_tokens = max_input_tokens

    def _call_llm(self, messages: List[Dict[str, str]], use_cache: bool = True) -> str:
        """调用LLM，带缓存和错误处理"""
        # 检查缓存
        if use_cache:
            cached = self.cache.get(messages, self.provider.model)
            if cached:
                return cached

        # 截断超长输入
        messages = self.provider.truncate_messages(messages, self.max_input_tokens)

        try:
            response = self.provider.chat(messages)
            # 保存缓存
            if use_cache:
                self.cache.set(messages, self.provider.model, response)
            return response
        except Exception as e:
            logger.error("LLM调用失败: %s", e)
            raise

    def _call_llm_stream(self, messages: List[Dict[str, str]]) -> Generator[str, None, None]:
        """流式调用LLM"""
        messages = self.provider.truncate_messages(messages, self.max_input_tokens)
        return self.provider.chat_stream(messages)

    def analyze_diagnosis(self, diagnosis_data: Dict[str, Any],
                         system_context: Optional[Dict[str, Any]] = None) -> str:
        """生成智能分析报告

        Args:
            diagnosis_data: 诊断数据（JSON格式的异常信息）
            system_context: 系统上下文信息

        Returns:
            分析报告文本（Markdown格式）
        """
        messages = build_analysis_prompt(diagnosis_data, system_context)
        return self._call_llm(messages)

    def generate_remediation(self, anomaly_data: Dict[str, Any],
                            os_info: Optional[str] = None,
                            kernel_version: Optional[str] = None) -> str:
        """生成自动修复建议

        Args:
            anomaly_data: 异常数据
            os_info: 操作系统信息
            kernel_version: 内核版本

        Returns:
            修复建议（JSON格式）
        """
        if not os_info:
            os_info = platform.platform()
        if not kernel_version:
            kernel_version = platform.release()

        messages = build_remediation_prompt(anomaly_data, os_info, kernel_version)
        return self._call_llm(messages)

    def chat(self, query: str, context_data: Optional[Dict[str, Any]] = None,
             history: Optional[List[Dict[str, str]]] = None) -> str:
        """交互式问答

        Args:
            query: 用户问题
            context_data: 诊断数据上下文
            history: 对话历史

        Returns:
            回答文本
        """
        # 检查是否有快捷回答
        quick_answer = get_quick_answer(query)
        if quick_answer and not context_data:
            return quick_answer

        # 构建消息
        system_prompt = build_chat_system_prompt(context_data)
        messages = [{"role": "system", "content": system_prompt}]

        # 添加对话历史
        if history:
            messages.extend(history[-10:])  # 保留最近10轮

        # 添加当前问题
        messages.append({"role": "user", "content": query})

        return self._call_llm(messages, use_cache=False)

    def chat_stream(self, query: str, context_data: Optional[Dict[str, Any]] = None,
                    history: Optional[List[Dict[str, str]]] = None) -> Generator[str, None, None]:
        """流式交互式问答

        Args:
            query: 用户问题
            context_data: 诊断数据上下文
            history: 对话历史

        Yields:
            回答文本片段
        """
        system_prompt = build_chat_system_prompt(context_data)
        messages = [{"role": "system", "content": system_prompt}]

        if history:
            messages.extend(history[-10:])

        messages.append({"role": "user", "content": query})

        return self._call_llm_stream(messages)

    def analyze_logs(self, diagnosis_data: Dict[str, Any], log_content: str,
                    line_count: int) -> str:
        """日志智能分析

        Args:
            diagnosis_data: 诊断数据
            log_content: 日志内容
            line_count: 日志行数

        Returns:
            分析报告（Markdown格式）
        """
        messages = build_log_analysis_prompt(diagnosis_data, log_content, line_count)
        return self._call_llm(messages)


def create_analyzer(config: Any = None) -> Optional[LLMAnalyzer]:
    """根据配置创建LLMAnalyzer实例

    Args:
        config: 应用配置对象

    Returns:
        LLMAnalyzer实例，如果配置不完整则返回None
    """
    provider = get_llm_provider(config)
    if not provider:
        return None

    cache_enabled = True
    cache_dir = "~/.cache/ebpf-diagnoser/llm"
    max_input_tokens = 8000

    if config and hasattr(config, 'llm'):
        llm_config = config.llm
        cache_enabled = getattr(llm_config, 'cache_enabled', True)
        cache_dir = getattr(llm_config, 'cache_dir', cache_dir)
        max_input_tokens = getattr(llm_config, 'max_input_tokens', max_input_tokens)

    return LLMAnalyzer(
        provider=provider,
        cache_enabled=cache_enabled,
        cache_dir=cache_dir,
        max_input_tokens=max_input_tokens,
    )
