"""OpenAI API Provider实现

支持OpenAI官方API及兼容OpenAI格式的第三方服务
"""

import logging
from typing import List, Dict, Optional, Generator

from src.llm.provider import LLMProvider, register_provider

logger = logging.getLogger("ebpf-diagnoser.llm.openai")


@register_provider("openai")
class OpenAIProvider(LLMProvider):
    """OpenAI API Provider"""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini",
                 base_url: Optional[str] = None, **kwargs):
        super().__init__(api_key=api_key, model=model, base_url=base_url, **kwargs)

        try:
            from openai import OpenAI
            client_kwargs = {"api_key": api_key, "timeout": self.timeout}
            if base_url:
                client_kwargs["base_url"] = base_url
            self.client = OpenAI(**client_kwargs)
        except ImportError:
            raise ImportError(
                "请安装openai库: pip install openai"
            )

    def chat(self, messages: List[Dict[str, str]], temperature: Optional[float] = None,
             max_tokens: Optional[int] = None) -> str:
        """发送对话请求"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature or self.temperature,
                max_tokens=max_tokens or self.max_tokens,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error("OpenAI API调用失败: %s", e)
            raise

    def chat_stream(self, messages: List[Dict[str, str]], temperature: Optional[float] = None,
                    max_tokens: Optional[int] = None) -> Generator[str, None, None]:
        """流式对话请求"""
        try:
            stream = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature or self.temperature,
                max_tokens=max_tokens or self.max_tokens,
                stream=True,
            )
            for chunk in stream:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            logger.error("OpenAI API流式调用失败: %s", e)
            raise
