"""LLM Provider抽象层

统一的LLM调用接口，支持多后端切换(OpenAI/Claude)
"""

import os
import json
import hashlib
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Generator, Any
from pathlib import Path

logger = logging.getLogger("ebpf-diagnoser.llm")


class LLMProvider(ABC):
    """LLM Provider抽象基类"""

    def __init__(self, api_key: str, model: str, base_url: Optional[str] = None,
                 temperature: float = 0.7, max_tokens: int = 4096, timeout: int = 60):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

    @abstractmethod
    def chat(self, messages: List[Dict[str, str]], temperature: Optional[float] = None,
             max_tokens: Optional[int] = None) -> str:
        """发送对话请求

        Args:
            messages: 对话历史 [{"role": "user/assistant/system", "content": "..."}]
            temperature: 覆盖默认温度
            max_tokens: 覆盖默认最大token

        Returns:
            模型响应文本
        """
        pass

    @abstractmethod
    def chat_stream(self, messages: List[Dict[str, str]], temperature: Optional[float] = None,
                    max_tokens: Optional[int] = None) -> Generator[str, None, None]:
        """流式对话请求

        Args:
            messages: 对话历史
            temperature: 覆盖默认温度
            max_tokens: 覆盖默认最大token

        Yields:
            模型响应的文本片段
        """
        pass

    def estimate_tokens(self, text: str) -> int:
        """估算文本的token数量（粗略估算：中文2字符/token，英文4字符/token）"""
        chinese_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
        other_chars = len(text) - chinese_chars
        return chinese_chars // 2 + other_chars // 4 + 10  # +10 for message overhead

    def truncate_messages(self, messages: List[Dict[str, str]], max_input_tokens: int) -> List[Dict[str, str]]:
        """智能截断消息历史，保留system消息和最近的对话"""
        if not messages:
            return messages

        # 计算当前总token
        total_tokens = sum(self.estimate_tokens(m["content"]) for m in messages)

        if total_tokens <= max_input_tokens:
            return messages

        # 保留system消息
        system_msgs = [m for m in messages if m["role"] == "system"]
        other_msgs = [m for m in messages if m["role"] != "system"]

        system_tokens = sum(self.estimate_tokens(m["content"]) for m in system_msgs)
        remaining_tokens = max_input_tokens - system_tokens

        if remaining_tokens <= 0:
            # system消息太长，截断最后一个
            truncated = system_msgs[-1]["content"][:max_input_tokens * 4]
            return [{"role": "system", "content": truncated}]

        # 从最新的消息开始保留
        kept_msgs = []
        for msg in reversed(other_msgs):
            msg_tokens = self.estimate_tokens(msg["content"])
            if remaining_tokens - msg_tokens >= 0:
                kept_msgs.insert(0, msg)
                remaining_tokens -= msg_tokens
            else:
                break

        return system_msgs + kept_msgs


class CacheManager:
    """LLM结果缓存管理"""

    def __init__(self, cache_dir: str, enabled: bool = True):
        self.enabled = enabled
        self.cache_dir = Path(os.path.expanduser(cache_dir))
        if enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_key(self, messages: List[Dict[str, str]], model: str) -> str:
        """生成缓存键"""
        content = json.dumps(messages, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(f"{model}:{content}".encode()).hexdigest()

    def get(self, messages: List[Dict[str, str]], model: str) -> Optional[str]:
        """获取缓存的响应"""
        if not self.enabled:
            return None

        key = self._get_key(messages, model)
        cache_file = self.cache_dir / f"{key}.json"

        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    logger.debug("LLM缓存命中: %s", key[:16])
                    return data.get("response")
            except Exception:
                pass
        return None

    def set(self, messages: List[Dict[str, str]], model: str, response: str):
        """保存响应到缓存"""
        if not self.enabled:
            return

        key = self._get_key(messages, model)
        cache_file = self.cache_dir / f"{key}.json"

        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump({"response": response, "model": model}, f, ensure_ascii=False)
            logger.debug("LLM缓存保存: %s", key[:16])
        except Exception as e:
            logger.warning("LLM缓存保存失败: %s", e)


# Provider注册表
_PROVIDERS = {}


def register_provider(name: str):
    """注册Provider的装饰器"""
    def decorator(cls):
        _PROVIDERS[name] = cls
        return cls
    return decorator


def get_llm_provider(config: Any = None) -> Optional[LLMProvider]:
    """根据配置创建LLM Provider实例

    优先级: 环境变量 > 配置文件
    环境变量:
        EBPF_DIAGNOSER_API_KEY: API密钥
        EBPF_DIAGNOSER_LLM_PROVIDER: Provider名称
        EBPF_DIAGNOSER_LLM_MODEL: 模型名称
    """
    # 获取配置值（环境变量优先）
    provider_name = os.environ.get("EBPF_DIAGNOSER_LLM_PROVIDER")
    api_key = os.environ.get("EBPF_DIAGNOSER_API_KEY")
    model = os.environ.get("EBPF_DIAGNOSER_LLM_MODEL")
    base_url = os.environ.get("EBPF_DIAGNOSER_BASE_URL")

    if config and hasattr(config, 'llm'):
        llm_config = config.llm
        provider_name = provider_name or getattr(llm_config, 'provider', 'openai')
        api_key = api_key or getattr(llm_config, 'api_key', None)
        model = model or getattr(llm_config, 'model', 'gpt-4o-mini')
        base_url = base_url or getattr(llm_config, 'base_url', None)
    else:
        provider_name = provider_name or 'openai'
        model = model or 'gpt-4o-mini'

    if not api_key:
        logger.warning("未配置LLM API密钥，请设置 EBPF_DIAGNOSER_API_KEY 环境变量或在配置文件中设置")
        return None

    if provider_name not in _PROVIDERS:
        logger.error("未知的LLM Provider: %s, 可用: %s", provider_name, list(_PROVIDERS.keys()))
        return None

    # 获取额外配置
    temperature = 0.7
    max_tokens = 4096
    timeout = 60

    if config and hasattr(config, 'llm'):
        llm_config = config.llm
        temperature = getattr(llm_config, 'temperature', temperature)
        max_tokens = getattr(llm_config, 'max_tokens', max_tokens)
        timeout = getattr(llm_config, 'timeout', timeout)

    provider_cls = _PROVIDERS[provider_name]
    return provider_cls(
        api_key=api_key,
        model=model,
        base_url=base_url,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
    )
