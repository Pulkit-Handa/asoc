"""
Lessons Router
==============
GET  /lessons          — list all lessons from ChromaDB
GET  /lessons/search   — semantic similarity search
POST /lessons          — analyst manually adds a lesson
DELETE /lessons/{id}   — remove a lesson (admin only)
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter()


class LessonCreate(BaseModel):
    text:        str
    category:    str
    analyst_id:  str = "analyst"
    alert_id:    Optional[str] = None


class LessonOut(BaseModel):
    id:          str
    text:        str
    category:    str
    source:      str        # "critic" or "analyst"
    created_at:  Optional[str]


@router.get("", response_model=list[LessonOut])
def list_lessons(
    category: Optional[str] = Query(None, description="Filter by MITRE tactic category"),
    limit:    int            = Query(50, le=200),
):
    """List lessons stored in ChromaDB, optionally filtered by category."""
    try:
        from agents.shared.chroma_client import get_lessons_collection
        collection = get_lessons_collection()

        where = {"category": category} if category else None
        results = collection.get(
            where=where,
            limit=limit,
            include=["documents", "metadatas"],
        )

        lessons = []
        for doc_id, doc, meta in zip(
            results.get("ids", []),
            results.get("documents", []),
            results.get("metadatas", []),
        ):
            lessons.append(LessonOut(
                id=doc_id,
                text=doc,
                category=meta.get("category", "Unknown"),
                source=meta.get("source", "critic"),
                created_at=meta.get("created_at"),
            ))
        return lessons

    except Exception as exc:
        logger.error("Failed to list lessons: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/search", response_model=list[LessonOut])
def search_lessons(
    q:          str = Query(..., description="Natural language search query"),
    n_results:  int = Query(5, le=20),
    category:   Optional[str] = Query(None),
):
    """
    Semantic similarity search over the lesson library.
    Uses the same local embedding model as the Triage Agent (see EMBEDDING_MODEL in .env).
    """
    try:
        from agents.shared.chroma_client import get_lessons_collection
        collection = get_lessons_collection()

        where = {"category": category} if category else None
        results = collection.query(
            query_texts=[q],
            n_results=n_results,
            where=where,
            include=["documents", "metadatas", "distances"],
        )

        lessons = []
        ids       = results.get("ids",       [[]])[0]
        docs      = results.get("documents", [[]])[0]
        metas     = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        for doc_id, doc, meta, dist in zip(ids, docs, metas, distances):
            lessons.append(LessonOut(
                id=doc_id,
                text=doc,
                category=meta.get("category", "Unknown"),
                source=meta.get("source", "critic"),
                created_at=meta.get("created_at"),
            ))
        return lessons

    except Exception as exc:
        logger.error("Lesson search failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("", status_code=201)
def create_lesson(payload: LessonCreate):
    """
    Analyst manually adds a lesson to the vector store.
    These are immediately available to the Triage Agent on the next alert.
    """
    try:
        from uuid import uuid4
        from agents.shared.chroma_client import get_lessons_collection

        collection = get_lessons_collection()
        lesson_id  = f"analyst_{uuid4().hex[:12]}"

        collection.add(
            documents=[payload.text],
            metadatas=[{
                "category":   payload.category,
                "source":     "analyst",
                "analyst_id": payload.analyst_id,
                "alert_id":   payload.alert_id or "",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }],
            ids=[lesson_id],
        )

        logger.info("Analyst lesson created: %s by %s", lesson_id, payload.analyst_id)
        return {"lesson_id": lesson_id, "status": "stored"}

    except Exception as exc:
        logger.error("Failed to create lesson: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.delete("/{lesson_id}", status_code=204)
def delete_lesson(lesson_id: str):
    """Remove a lesson from ChromaDB. Use with caution — this is permanent."""
    try:
        from agents.shared.chroma_client import get_lessons_collection
        collection = get_lessons_collection()
        collection.delete(ids=[lesson_id])
        logger.warning("Lesson deleted: %s", lesson_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
