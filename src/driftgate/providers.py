"""Model access, provider-agnostic.

driftgate must not care who serves the model. Two backends cover essentially
everything, and neither is privileged:

  openai_compat  zero lock-in. Any /v1/chat/completions endpoint: OpenAI,
                 Anthropic's compat layer, Gemini's, Groq, Together, Mistral,
                 DeepSeek, OpenRouter, vLLM, Ollama, LM Studio, llama.cpp, or
                 your own gateway. Needs only httpx.

  litellm        optional extra. Normalises 100+ providers including Bedrock,
                 Vertex, Azure, and Cohere, for the ones that are not
                 OpenAI-shaped.

The OpenAI tool-call wire format is used as the internal normal form because
it is the de facto standard every provider and local runtime now speaks --
that is an interop decision, not an endorsement.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class ToolCallRequest:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ChatResponse:
    content: str = ""
    tool_calls: list[ToolCallRequest] = field(default_factory=list)
    raw: Any = None
    input_tokens: int = 0
    output_tokens: int = 0


@runtime_checkable
class ChatModel(Protocol):
    """Implement this to support a provider driftgate has never heard of."""

    id: str

    async def chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> ChatResponse: ...


# -- parsing (shared: both backends return OpenAI-shaped payloads) ----------


def parse_openai_response(data: dict[str, Any]) -> ChatResponse:
    try:
        msg = data["choices"][0]["message"]
    except (KeyError, IndexError) as exc:
        raise ValueError(f"unexpected response shape: {json.dumps(data)[:300]}") from exc

    calls = []
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function", {})
        raw_args = fn.get("arguments") or "{}"
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
        except json.JSONDecodeError:
            # A model emitting malformed tool arguments is a real, observable
            # behaviour -- record it rather than crashing the run.
            args = {"__unparsed__": raw_args}
        calls.append(ToolCallRequest(id=tc.get("id", ""), name=fn.get("name", ""), arguments=args))

    usage = data.get("usage") or {}
    return ChatResponse(
        content=msg.get("content") or "",
        tool_calls=calls,
        raw=data,
        input_tokens=int(usage.get("prompt_tokens") or 0),
        output_tokens=int(usage.get("completion_tokens") or 0),
    )


# -- backends ---------------------------------------------------------------


class OpenAICompatModel:
    """Any endpoint exposing POST {base_url}/chat/completions."""

    def __init__(
        self,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        api_key: str | None = None,
        api_key_env: str = "OPENAI_API_KEY",
        *,
        id: str | None = None,
        timeout: float = 120.0,
        temperature: float | None = None,
        extra_body: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        # Local runtimes (Ollama, llama.cpp) need no key; absent is not an error.
        self.api_key = api_key or os.environ.get(api_key_env) or ""
        self.id = id or model
        self.timeout = timeout
        self.temperature = temperature
        self.extra_body = extra_body or {}
        self.extra_headers = extra_headers or {}

    async def chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> ChatResponse:
        import httpx

        body: dict[str, Any] = {"model": self.model, "messages": messages, **self.extra_body}
        if tools:
            body["tools"] = tools
        if self.temperature is not None:
            body["temperature"] = self.temperature

        headers = {"Content-Type": "application/json", **self.extra_headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            r = await client.post(
                f"{self.base_url}/chat/completions", json=body, headers=headers
            )
            if r.status_code >= 400:
                raise RuntimeError(f"{self.id}: HTTP {r.status_code} {r.text[:300]}")
            return parse_openai_response(r.json())


class LiteLLMModel:
    """Anything LiteLLM can route to, e.g. 'bedrock/anthropic.claude-...'."""

    def __init__(self, model: str, *, id: str | None = None, **kwargs: Any) -> None:
        self.model = model
        self.id = id or model
        self.kwargs = kwargs

    async def chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> ChatResponse:
        try:
            import litellm
        except ImportError as exc:
            raise RuntimeError(
                "provider 'litellm' requires the extra: pip install 'driftgate[litellm]'"
            ) from exc

        resp = await litellm.acompletion(
            model=self.model, messages=messages, tools=tools or None, **self.kwargs
        )
        data = resp.model_dump() if hasattr(resp, "model_dump") else dict(resp)
        return parse_openai_response(data)


class EchoModel:
    """Offline stand-in for tests and `driftgate demo`. Never calls out."""

    def __init__(self, id: str = "echo", script: list[ChatResponse] | None = None) -> None:
        self.id = id
        self.script = list(script or [])

    async def chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> ChatResponse:
        if self.script:
            return self.script.pop(0)
        return ChatResponse(content="ok")


# -- construction from config ----------------------------------------------

# Convenience base URLs. These are shortcuts, not a supported-provider list --
# any OpenAI-compatible endpoint works by passing base_url directly.
KNOWN_BASE_URLS = {
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "anthropic": ("https://api.anthropic.com/v1", "ANTHROPIC_API_KEY"),
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY"),
    "together": ("https://api.together.xyz/v1", "TOGETHER_API_KEY"),
    "mistral": ("https://api.mistral.ai/v1", "MISTRAL_API_KEY"),
    "deepseek": ("https://api.deepseek.com/v1", "DEEPSEEK_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY"),
    "xai": ("https://api.x.ai/v1", "XAI_API_KEY"),
    "ollama": ("http://localhost:11434/v1", "OLLAMA_API_KEY"),
    "vllm": ("http://localhost:8000/v1", "VLLM_API_KEY"),
    "lmstudio": ("http://localhost:1234/v1", "LMSTUDIO_API_KEY"),
}


def from_config(spec: dict[str, Any] | str) -> ChatModel:
    """Build a ChatModel from driftgate.yaml.

    Shorthand string:  "openai:gpt-4o", "ollama:llama3.1", "litellm:bedrock/..."
    Full dict form supports base_url, api_key_env, temperature, extra_body.
    """
    if isinstance(spec, str):
        if ":" not in spec:
            raise ValueError(
                f"model shorthand must be 'provider:model' (e.g. 'openai:gpt-4o', "
                f"'ollama:llama3.1', 'self:my-model@http://host/v1'), got {spec!r}"
            )
        provider, model = spec.split(":", 1)
        # 'anything:model@http://host/v1' points at a self-hosted or gateway
        # endpoint without needing the dict form -- keeps the CLI usable for
        # people whose model is not behind a named vendor.
        if "@" in model:
            model, base_url = model.rsplit("@", 1)
            spec = {"provider": provider, "model": model, "base_url": base_url}
        else:
            spec = {"provider": provider, "model": model}

    spec = dict(spec)
    provider = spec.pop("provider", "openai")
    model = spec.pop("model", None)
    if not model:
        raise ValueError(f"model spec missing 'model': {spec}")
    model_id = spec.pop("id", None)

    if provider == "litellm":
        return LiteLLMModel(model, id=model_id, **spec)
    if provider == "echo":
        return EchoModel(id=model_id or "echo")

    base_url = spec.pop("base_url", None)
    api_key_env = spec.pop("api_key_env", None)
    if base_url is None:
        if provider not in KNOWN_BASE_URLS:
            raise ValueError(
                f"unknown provider {provider!r}. Either use one of "
                f"{sorted(KNOWN_BASE_URLS)}, pass an explicit base_url for any "
                f"OpenAI-compatible endpoint, or use provider: litellm."
            )
        default_url, default_env = KNOWN_BASE_URLS[provider]
        base_url = default_url
        api_key_env = api_key_env or default_env

    return OpenAICompatModel(
        model, base_url=base_url, api_key_env=api_key_env or "OPENAI_API_KEY",
        id=model_id or f"{provider}:{model}", **spec
    )
