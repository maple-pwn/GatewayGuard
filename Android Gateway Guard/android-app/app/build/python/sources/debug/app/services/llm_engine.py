"""LLM service layer with optional OpenAI SDK and HTTP fallback."""

from __future__ import annotations

import json
import re
from typing import List, Optional

import httpx

from app.config import settings
from app.models.anomaly import AnomalyEvent
from app.utils.prompt_templates import (
    ANOMALY_ANALYSIS_PROMPT,
    REPORT_GENERATION_PROMPT,
    SYSTEM_PROMPT,
)
from app.utils.tools import CHAT_TOOLS


class LLMEngine:
    @staticmethod
    def _parse_json_response(content: str) -> dict:
        text = content.strip()
        match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
        if match:
            text = match.group(1).strip()
        return json.loads(text)

    def __init__(self):
        self.client = None
        self._sdk_enabled = False
        self._init_client()

    def _init_client(self):
        cfg = settings.llm
        if cfg.provider == "ollama":
            self.base_url = f"{cfg.ollama_base_url.rstrip('/')}/v1"
            self.api_key = "ollama"
            self.model = cfg.ollama_model
        else:
            self.base_url = cfg.openai_base_url.rstrip("/")
            self.api_key = cfg.openai_api_key
            self.model = cfg.openai_model

        try:
            from openai import AsyncOpenAI  # Optional for Android builds

            self.client = AsyncOpenAI(base_url=self.base_url, api_key=self.api_key)
            self._sdk_enabled = True
        except Exception:
            self.client = None
            self._sdk_enabled = False

    async def _call_llm(self, messages: list, **kwargs):
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": settings.llm.temperature,
            "max_tokens": settings.llm.max_tokens,
        }
        payload.update(kwargs)

        if self._sdk_enabled and self.client is not None:
            return await self.client.chat.completions.create(**payload)

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        endpoint = f"{self.base_url.rstrip('/')}/chat/completions"
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(endpoint, headers=headers, json=payload)
            response.raise_for_status()
            return response.json()

    @staticmethod
    def _extract_message_content(response) -> str:
        if isinstance(response, dict):
            return (
                response.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                or ""
            )
        return response.choices[0].message.content or ""

    @staticmethod
    def _extract_tool_calls(response) -> Optional[list]:
        if isinstance(response, dict):
            raw = (
                response.get("choices", [{}])[0]
                .get("message", {})
                .get("tool_calls")
            )
            if not raw:
                return None
            result = []
            for call in raw:
                function_data = call.get("function", {})
                arguments = function_data.get("arguments", "{}")
                try:
                    parsed_args = json.loads(arguments)
                except Exception:
                    parsed_args = {"raw": arguments}
                result.append(
                    {
                        "name": function_data.get("name", ""),
                        "arguments": parsed_args,
                    }
                )
            return result

        if not response.choices[0].message.tool_calls:
            return None
        result = []
        for tool_call in response.choices[0].message.tool_calls:
            result.append(
                {
                    "name": tool_call.function.name,
                    "arguments": json.loads(tool_call.function.arguments),
                }
            )
        return result

    @staticmethod
    def _extract_usage(response) -> dict:
        if isinstance(response, dict):
            usage = response.get("usage", {})
            return {
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
            }
        usage = response.usage
        return {
            "prompt_tokens": usage.prompt_tokens if usage else 0,
            "completion_tokens": usage.completion_tokens if usage else 0,
        }

    async def analyze_anomaly(self, event: AnomalyEvent) -> dict:
        prompt = ANOMALY_ANALYSIS_PROMPT.format(
            timestamp=event.timestamp,
            protocol=event.protocol,
            anomaly_type=event.anomaly_type,
            severity=event.severity,
            confidence=event.confidence,
            source_node=event.source_node,
            target_node=event.target_node,
            detection_method=event.detection_method,
            description=event.description,
        )

        response = await self._call_llm(
            [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]
        )
        content = self._extract_message_content(response)
        try:
            return self._parse_json_response(content)
        except (json.JSONDecodeError, ValueError):
            return {"analyze_raw": content}

    async def generate_report(self, events: List[AnomalyEvent]) -> dict:
        events_data = [
            {
                "timestamp": event.timestamp,
                "anomaly_type": event.anomaly_type,
                "severity": event.severity,
                "protocol": event.protocol,
                "source_node": event.source_node,
                "description": event.description,
            }
            for event in events
        ]
        prompt = REPORT_GENERATION_PROMPT.format(
            events_json=json.dumps(events_data, ensure_ascii=False, indent=2)
        )

        response = await self._call_llm(
            [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]
        )
        content = self._extract_message_content(response)
        try:
            return self._parse_json_response(content)
        except (json.JSONDecodeError, ValueError):
            return {"report_raw": content}

    async def chat(self, messages: List[dict], use_tools: bool = True) -> dict:
        full_messages = [{"role": "system", "content": SYSTEM_PROMPT}, *messages]
        kwargs = {"tools": CHAT_TOOLS} if use_tools else {}

        response = await self._call_llm(full_messages, **kwargs)
        return {
            "content": self._extract_message_content(response),
            "tool_calls": self._extract_tool_calls(response),
            "usage": self._extract_usage(response),
        }

