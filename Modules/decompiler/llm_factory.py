import os

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI

from .runtime_settings import get_decompiler_config

try:
    from langchain_anthropic import ChatAnthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    ChatAnthropic = None

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False
    ChatGoogleGenerativeAI = None

try:
    from langchain_ollama import ChatOllama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    ChatOllama = None


def get_chat_model(
    provider_name=None,
    model_name=None,
    temperature=None,
    **kwargs
):
    """
    Factory function to instantiate a LangChain chat model for any supported provider.

    This is the ONLY place where provider-specific logic exists. All graph nodes
    call this function and receive a unified BaseChatModel interface.

    Args:
        provider_name: One of "openrouter", "anthropic", "google", "ollama", "openai"
                      Defaults to centralized `wise_config.py` decompiler provider
        model_name: The model identifier (provider-specific)
                   Defaults to centralized `wise_config.py` decompiler model
        temperature: Sampling temperature (0.0 = deterministic, 1.0 = creative)
                    Defaults to centralized `wise_config.py` decompiler temperature
        **kwargs: Additional provider-specific arguments

    Returns:
        BaseChatModel: A LangChain chat model instance

    Raises:
        ValueError: If provider is not supported or required package is missing

    Environment Variables Required:
        - openrouter: OPENROUTER_API_KEY
        - anthropic:  ANTHROPIC_API_KEY
        - google:     GOOGLE_API_KEY
        - ollama:     (none, but Ollama server must be running)
        - openai:     OPENAI_API_KEY
    """

    config = get_decompiler_config()
    provider = (provider_name or config["provider"]).lower().strip()
    model = model_name or config["model"]
    temp = temperature if temperature is not None else config["temperature"]

    if provider == "openrouter":
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENROUTER_API_KEY is required for OpenRouter.\n"
                "Set it as an environment variable.\n"
                "Get your API key at: https://openrouter.ai/keys"
            )

        return ChatOpenAI(
            model=model,
            temperature=temp,
            openai_api_key=api_key,
            openai_api_base="https://openrouter.ai/api/v1",
            default_headers={
                "HTTP-Referer": "https://github.com/wise-decompiler",
                "X-Title": "WISE WASM Decompiler",
            },
            **kwargs
        )

    elif provider == "anthropic":
        if not ANTHROPIC_AVAILABLE:
            raise ValueError(
                "Anthropic provider requires langchain-anthropic package.\n"
                "Install with: pip install langchain-anthropic"
            )

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable is required for Anthropic.\n"
                "Get your API key at: https://console.anthropic.com/"
            )

        return ChatAnthropic(
            model=model,
            temperature=temp,
            anthropic_api_key=api_key,
            **kwargs
        )

    elif provider == "google":
        if not GOOGLE_AVAILABLE:
            raise ValueError(
                "Google provider requires langchain-google-genai package.\n"
                "Install with: pip install langchain-google-genai"
            )

        api_key = os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError(
                "GOOGLE_API_KEY environment variable is required for Google AI Studio.\n"
                "Get your API key at: https://aistudio.google.com/app/apikey"
            )

        return ChatGoogleGenerativeAI(
            model=model,
            temperature=temp,
            google_api_key=api_key,
            **kwargs
        )

    elif provider == "ollama":
        if not OLLAMA_AVAILABLE:
            raise ValueError(
                "Ollama provider requires langchain-ollama package.\n"
                "Install with: pip install langchain-ollama"
            )

        base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")

        return ChatOllama(
            model=model,
            temperature=temp,
            base_url=base_url,
            **kwargs
        )

    elif provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY is required for OpenAI.\n"
                "Set it as an environment variable.\n"
                "Get your API key at: https://platform.openai.com/api-keys"
            )

        return ChatOpenAI(
            model=model,
            temperature=temp,
            openai_api_key=api_key,
            **kwargs
        )

    else:
        supported = ["openrouter", "anthropic", "google",
                     "ollama", "openai"]
        raise ValueError(
            f"Unknown provider: '{provider_name}'.\n"
            f"Supported providers: {', '.join(supported)}"
        )


def get_available_providers():
    """
    Check which providers are available (packages installed + API keys set).

    Returns:
        dict: Provider name -> availability status and details
    """
    providers = {}

    providers["openrouter"] = {
        "available": True,
        "package": "langchain-openai (included)",
        "api_key_set": bool(os.environ.get("OPENROUTER_API_KEY")),
        "api_key_var": "OPENROUTER_API_KEY"
    }
    providers["anthropic"] = {
        "available": ANTHROPIC_AVAILABLE,
        "package": "langchain-anthropic",
        "api_key_set": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "api_key_var": "ANTHROPIC_API_KEY"
    }
    providers["google"] = {
        "available": GOOGLE_AVAILABLE,
        "package": "langchain-google-genai",
        "api_key_set": bool(os.environ.get("GOOGLE_API_KEY")),
        "api_key_var": "GOOGLE_API_KEY"
    }
    providers["ollama"] = {
        "available": OLLAMA_AVAILABLE,
        "package": "langchain-ollama",
        "api_key_set": True,
        "api_key_var": "(none required)"
    }
    providers["openai"] = {
        "available": True,
        "package": "langchain-openai (included)",
        "api_key_set": bool(os.environ.get("OPENAI_API_KEY")),
        "api_key_var": "OPENAI_API_KEY"
    }

    return providers
