"""Anthropic Claude API Provider实现"""

import logging
from typing import List, Dict, Optional, Generator

from src.llm.provider import LLMProvider, register_provider

logger = logging.getLogger("ebpf-diagnoser.llm.anthropic")


@register_provider("anthropic")
class AnthropicProvider(LLMProvider):
    """Anthropic Claude API Provider"""

    def __init__(self, api_key: str, model: str = "claude-3-haiku-20240307",
                 base_url: Optional[str] = None, **kwargs):
        super().__init__(api_key=api_key, model=model, base_url=base_url, **kwargs)

        try:
            from anthropic import Anthropic
            client_kwargs = {"api_key": api_key, "timeout": self.timeout}
            if base_url:
                client_kwargs["base_url"] = base_url
            self.client = Anthropic(**client_kwargs)
        except ImportError:
            raise ImportError(
                "请安装anthropic库: pip install anthropic"
            )

    def _convert_messages(self, messages: List[Dict[str, str]]) -> tuple:
        """转换消息格式，分离system消息"""
        system_prompt = ""
        chat_messages = []

        for msg in messages:
            if msg["role"] == "system":
                system_prompt = msg["content"]
            else:
                chat_messages.append({"role": msg["role"], "content": msg["content"]})

        # Claude要求至少有一条用户消息
        if not chat_messages:
            chat_messages = [{"role": "user", "content": "请分析以下系统诊断数据。"}]

        return system_prompt, chat_messages

    def chat(self, messages: List[Dict[str, str]], temperature: Optional[float] = None,
             max_tokens: Optional[int] = None) -> str:
        """发送对话请求"""
        try:
            system_prompt, chat_messages = self._convert_messages(messages)

            kwargs = {
                "model": self.model,
                "messages": chat_messages,
                "max_tokens": max_tokens or self.max_tokens,
                "temperature": temperature or self.temperature,
            }
            if system_prompt:
                kwargs["system"] = system_prompt

            response = self.client.messages.create(**kwargs)
            return response.content[0].text
        except Exception as e:
            logger.error("Anthropic API调用失败: %s", e)
            raise

    def chat_stream(self, messages: List[Dict[str, str]], temperature: Optional[float] = None,
                    max_tokens: Optional[int] = None) -> Generator[str, None, None]:
        """流式对话请求"""
        try:
            system_prompt, chat_messages = self._convert_messages(messages)

            kwargs = {
                "model": self.model,
                "messages": chat_messages,
                "max_tokens": max_tokens or self.max_tokens,
                "temperature": temperature or self.temperature,
            }
            if system_prompt:
                kwargs["system"] = system_prompt

            with self.client.messages.stream(**kwargs) as stream:
                for text in stream.text_stream:
                    yield text
        except Exception as e:
            logger.error("Anthropic API流式调用失败: %s", e)
            raise
