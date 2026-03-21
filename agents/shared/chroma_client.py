"""
Shared ChromaDB Client
=======================
Three collections per the PRD spec:
  - trade_lessons:   Missed threat post-mortems (queried every Triage call)
  - tactic_patterns: MITRE ATT&CK technique descriptions (queried by Forensics)
  - analyst_context: Analyst-added manual annotations (queried at Decision node)

Embeddings are provided by a local HuggingFace sentence-transformers model.
No OpenAI key required. No API costs. No rate limits.

To change the embedding model, set EMBEDDING_MODEL in your .env file.
See agents/shared/embedding.py for the full list of supported models.

IMPORTANT: Never change EMBEDDING_MODEL after you have stored lessons.
The old and new vectors live in incompatible spaces. If you must change,
delete ChromaDB collections and re-seed: python scripts/seed_topology.py
"""
import logging
import os
from functools import lru_cache

import chromadb
from chromadb.config import Settings

from agents.shared.embedding import get_embedding_function

logger = logging.getLogger(__name__)

COLLECTION_LESSONS = "trade_lessons"
COLLECTION_TACTICS = "tactic_patterns"
COLLECTION_ANALYST = "analyst_context"


@lru_cache(maxsize=1)
def get_chroma_client() -> chromadb.Client:
    use_persistent = os.getenv("CHROMADB_PERSISTENT", "false").lower() == "true"

    if use_persistent:
        persist_path = os.getenv("CHROMADB_PERSIST_PATH", "./chroma_data")
        logger.info("ChromaDB: persistent mode at %s", persist_path)
        return chromadb.PersistentClient(path=persist_path)

    chroma_host = os.getenv("CHROMADB_HOST", "localhost")
    chroma_port = int(os.getenv("CHROMADB_PORT", "8000"))
    logger.info("ChromaDB: HTTP client at %s:%s", chroma_host, chroma_port)
    return chromadb.HttpClient(
        host=chroma_host,
        port=chroma_port,
        settings=Settings(anonymized_telemetry=False),
    )


def get_lessons_collection():
    """Queried by Triage Agent, written by Critic Agent."""
    return get_chroma_client().get_or_create_collection(
        name=COLLECTION_LESSONS,
        embedding_function=get_embedding_function(),
        metadata={"hnsw:space": "cosine"},
    )


def get_tactics_collection():
    """MITRE ATT&CK patterns, seeded at startup, queried by Forensics Agent."""
    return get_chroma_client().get_or_create_collection(
        name=COLLECTION_TACTICS,
        embedding_function=get_embedding_function(),
        metadata={"hnsw:space": "cosine"},
    )


def get_analyst_collection():
    """Manual analyst annotations, queried at Decision node."""
    return get_chroma_client().get_or_create_collection(
        name=COLLECTION_ANALYST,
        embedding_function=get_embedding_function(),
        metadata={"hnsw:space": "cosine"},
    )


def add_analyst_lesson(text: str, metadata: dict) -> str:
    """Add a manual analyst lesson. Available to Triage Agent immediately."""
    from uuid import uuid4
    collection = get_analyst_collection()
    lesson_id  = f"analyst_{uuid4().hex[:12]}"
    collection.add(
        documents=[text],
        metadatas=[metadata],
        ids=[lesson_id],
    )
    logger.info("Analyst lesson stored: %s", lesson_id)
    return lesson_id
