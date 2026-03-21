"""
Embedding Function Factory
==========================
Provides a single place to configure which embedding model ASOC uses
for ChromaDB vector storage and semantic search.

All models here are FREE and run entirely on your local machine.
No API keys required. No per-call costs. No rate limits.

Model choices (set EMBEDDING_MODEL in .env):

  MODEL NAME                          DIMS   SIZE    NOTES
  ─────────────────────────────────── ────── ─────── ────────────────────────────
  all-MiniLM-L6-v2           (DEFAULT) 384    ~80MB   Fast. ChromaDB's own default.
                                                       Good quality for short texts.
                                                       Best choice for low-RAM systems.

  BAAI/bge-small-en-v1.5              384    ~130MB  Excellent retrieval quality.
                                                       Specifically trained for
                                                       semantic search tasks.
                                                       Recommended for production.

  BAAI/bge-base-en-v1.5               768    ~440MB  Higher quality than bge-small.
                                                       Good if you have 8GB+ RAM.

  all-mpnet-base-v2                   768    ~420MB  Strong general-purpose model.
                                                       Good balance of quality/speed.

  thenlper/gte-small                  384    ~70MB   Very fast. Good for high
                                                       throughput environments.

IMPORTANT: Whichever model you pick, use it consistently forever.
Changing the model after lessons are stored means the old vectors and
new vectors live in different embedding spaces — semantic search breaks.
If you change models, you must delete the ChromaDB collections and
re-seed using: python scripts/seed_topology.py

Dimensions are set automatically from the chosen model.
"""
import logging
import os
from functools import lru_cache

logger = logging.getLogger(__name__)

# ── Model selection ───────────────────────────────────────────────────────────

# These are the validated model names. Any HuggingFace sentence-transformers
# model will work — add more here as needed.
SUPPORTED_MODELS = {
    "all-MiniLM-L6-v2":       {"dims": 384,  "notes": "Fast, 80MB, ChromaDB default"},
    "BAAI/bge-small-en-v1.5": {"dims": 384,  "notes": "Best retrieval quality at small size"},
    "BAAI/bge-base-en-v1.5":  {"dims": 768,  "notes": "Higher quality, needs more RAM"},
    "all-mpnet-base-v2":       {"dims": 768,  "notes": "Strong general-purpose model"},
    "thenlper/gte-small":      {"dims": 384,  "notes": "Very fast, good for high throughput"},
}

DEFAULT_MODEL = "all-MiniLM-L6-v2"


def get_model_name() -> str:
    """Read EMBEDDING_MODEL from env, fall back to default."""
    model = os.getenv("EMBEDDING_MODEL", DEFAULT_MODEL).strip()
    if model not in SUPPORTED_MODELS:
        logger.warning(
            "EMBEDDING_MODEL=%r is not in the validated list. "
            "It will still work if it's a valid sentence-transformers model name, "
            "but dims will be auto-detected. Validated options: %s",
            model,
            list(SUPPORTED_MODELS.keys()),
        )
    return model


@lru_cache(maxsize=1)
def get_embedding_function():
    """
    Returns a ChromaDB-compatible embedding function backed by a local
    HuggingFace sentence-transformers model.

    The model is downloaded from HuggingFace Hub on first use (~80-440MB
    depending on model), then cached in ~/.cache/huggingface/.
    Subsequent starts load from cache — no internet required after first run.

    This function is cached with @lru_cache so the model is only loaded
    once per process, regardless of how many collections use it.
    """
    from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

    model_name = get_model_name()
    info = SUPPORTED_MODELS.get(model_name, {})

    logger.info(
        "Loading embedding model: %s (%s)",
        model_name,
        info.get("notes", "custom model"),
    )

    # SentenceTransformerEmbeddingFunction is ChromaDB's built-in wrapper
    # around the sentence-transformers library. It handles batching,
    # normalisation, and the ChromaDB EmbeddingFunction interface.
    ef = SentenceTransformerEmbeddingFunction(
        model_name=model_name,
        device=_get_device(),       # cuda if available, else cpu
        normalize_embeddings=True,  # cosine similarity works best normalised
    )

    logger.info("Embedding model loaded successfully on device: %s", _get_device())
    return ef


def _get_device() -> str:
    """
    Use GPU if available (dramatically faster for batch embedding at scale).
    Falls back to CPU — works fine for development and low-throughput production.

    To force CPU even if GPU is available: set EMBEDDING_DEVICE=cpu in .env
    """
    forced = os.getenv("EMBEDDING_DEVICE", "").strip().lower()
    if forced in ("cpu", "cuda", "mps"):
        return forced

    try:
        import torch
        if torch.cuda.is_available():
            logger.info("CUDA GPU detected — embeddings will run on GPU")
            return "cuda"
        if torch.backends.mps.is_available():  # Apple Silicon
            logger.info("Apple MPS detected — embeddings will run on MPS")
            return "mps"
    except ImportError:
        pass

    return "cpu"


def embed_texts(texts: list[str]) -> list[list[float]]:
    """
    Convenience function: embed a list of strings directly.
    Used by the Critic Agent to embed lessons before storing them.

    Returns a list of float vectors, one per input text.
    """
    ef = get_embedding_function()
    return ef(texts)


def warm_up():
    """
    Pre-load the embedding model at startup so the first alert
    isn't slow. Call this from api/main.py on startup.
    """
    logger.info("Warming up embedding model...")
    embed_texts(["security alert warmup ping"])
    logger.info("Embedding model warm-up complete.")
