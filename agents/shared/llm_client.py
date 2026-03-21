"""
Shared LLM Client Factory
==========================
Returns a LangChain chat model for the Critic Agent's reasoning.

NOTE: This is separate from embeddings. The LLM is used ONLY by the
Critic Agent to generate lessons in natural language. Embeddings
(ChromaDB semantic search) are handled by agents/shared/embedding.py
and require no API key at all.

LLM options (set LLM_PROVIDER in .env):

  PROVIDER       COST    NOTES
  ─────────────  ──────  ──────────────────────────────────────────────
  anthropic      Paid    Best reasoning quality. Recommended for prod.
  openai         Paid    Good alternative if you have OpenAI credits.
  ollama         FREE    Runs a model locally. No API key. Needs Ollama
                         installed: https://ollama.com
                         Set OLLAMA_MODEL=llama3.2 (or any model you've
                         pulled). Quality depends on the local model.
  huggingface    FREE    HuggingFace Inference API free tier (rate-limited).
                         Set HF_API_TOKEN and HF_MODEL in .env.
                         Best free option if you don't want to run Ollama.

For zero-cost local operation: use ollama with llama3.2 or mistral.
For best lesson quality: use anthropic.
"""
import logging
import os
from functools import lru_cache

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_llm():
    provider = os.getenv("LLM_PROVIDER", "anthropic").lower()
    logger.info("LLM provider: %s", provider)

    # ── Anthropic (paid, best quality) ───────────────────────────────────────
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            max_tokens=1024,
            temperature=0.1,
        )

    # ── OpenAI (paid) ─────────────────────────────────────────────────────────
    if provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            api_key=os.getenv("OPENAI_API_KEY"),
            max_tokens=1024,
            temperature=0.1,
        )

    # ── Ollama (FREE — runs fully locally) ───────────────────────────────────
    # Install Ollama: https://ollama.com
    # Pull a model first: ollama pull llama3.2
    # Then start: ollama serve
    # Good free models for reasoning: llama3.2, mistral, qwen2.5, gemma2
    if provider == "ollama":
        try:
            from langchain_ollama import ChatOllama
        except ImportError:
            raise ImportError(
                "langchain-ollama is not installed. Run: poetry add langchain-ollama"
            )
        model = os.getenv("OLLAMA_MODEL", "llama3.2")
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        logger.info("Ollama: model=%s base_url=%s", model, base_url)
        return ChatOllama(
            model=model,
            base_url=base_url,
            temperature=0.1,
            num_predict=1024,
        )

    # ── HuggingFace Inference API (FREE tier, rate-limited) ──────────────────
    # Get a free token at: https://huggingface.co/settings/tokens
    # Free tier allows ~1000 requests/day. Fine for development.
    # Recommended model: mistralai/Mistral-7B-Instruct-v0.3
    if provider == "huggingface":
        try:
            from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint
        except ImportError:
            raise ImportError(
                "langchain-huggingface is not installed. "
                "Run: poetry add langchain-huggingface"
            )
        hf_token = os.getenv("HF_API_TOKEN")
        if not hf_token:
            raise ValueError(
                "LLM_PROVIDER=huggingface requires HF_API_TOKEN in your .env file. "
                "Get a free token at: https://huggingface.co/settings/tokens"
            )
        model_id = os.getenv("HF_MODEL", "mistralai/Mistral-7B-Instruct-v0.3")
        logger.info("HuggingFace Inference API: model=%s", model_id)
        llm = HuggingFaceEndpoint(
            repo_id=model_id,
            huggingfacehub_api_token=hf_token,
            max_new_tokens=1024,
            temperature=0.1,
        )
        return ChatHuggingFace(llm=llm)

    raise ValueError(
        f"Unknown LLM_PROVIDER: {provider!r}. "
        f"Valid options: anthropic, openai, ollama, huggingface"
    )
