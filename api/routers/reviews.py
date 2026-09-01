"""
Lesson Review Router
====================
GET  /reviews              — list pending lesson reviews (SOC_MANAGER+)
POST /reviews/{id}/approve — approve lesson → stored in ChromaDB + Lesson table
POST /reviews/{id}/reject  — reject lesson → discarded, never affects triage

This is the quality gate the scalability analysis identified as missing.
A bad lesson in ChromaDB poisons every future alert retrieval.
This router ensures a human sees every Critic Agent lesson before it
changes the system's behaviour.

When cfg.lesson_review_required=False (e.g. in dev/staging), lessons
are auto-approved and this workflow is bypassed.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.routers.auth import UserRole, require_role
from config.settings import cfg
from data.postgres.models import LessonReview, LessonReviewStatus
from data.postgres.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()


class ReviewDecision(BaseModel):
    note: Optional[str] = None


class ReviewOut(BaseModel):
    id:           int
    alert_id:     str
    category:     str
    lesson_text:  str
    source:       str
    status:       str
    created_at:   datetime
    reviewed_at:  Optional[datetime]
    reviewer_id:  Optional[str]
    review_note:  Optional[str]

    class Config:
        from_attributes = True


@router.get("", response_model=list[ReviewOut])
def list_pending_reviews(
    status: str = "PENDING",
    limit:  int = 50,
    db:     Session = Depends(get_db),
    _user: dict = Depends(require_role(UserRole.SOC_MANAGER, UserRole.ADMIN)),
):
    """List lesson reviews. Defaults to PENDING — the queue that needs attention."""
    rows = db.execute(
        select(LessonReview)
        .where(LessonReview.status == status.upper())
        .order_by(LessonReview.created_at.asc())
        .limit(limit)
    ).scalars().all()
    return rows


@router.post("/{review_id}/approve", status_code=200)
def approve_review(
    review_id: int,
    decision:  ReviewDecision,
    db:        Session = Depends(get_db),
    user: dict = Depends(require_role(UserRole.SOC_MANAGER, UserRole.ADMIN)),
):
    """
    Approve a lesson: write it to ChromaDB and the Lesson table.
    The lesson is now live and will influence the next Triage Agent call.
    """
    row = _get_review_or_404(review_id, db)
    _store_to_chromadb(row)
    _store_to_postgres(row, db)

    row.status      = LessonReviewStatus.APPROVED
    row.reviewer_id = user["username"]
    row.review_note = decision.note
    row.reviewed_at = datetime.now(timezone.utc)
    db.commit()

    logger.info(
        "LESSON APPROVED: review_id=%d category=%s by=%s",
        review_id, row.category, user["username"],
    )
    return {"status": "approved", "lesson_id": f"critic_{row.id}"}


@router.post("/{review_id}/reject", status_code=200)
def reject_review(
    review_id: int,
    decision:  ReviewDecision,
    db:        Session = Depends(get_db),
    user: dict = Depends(require_role(UserRole.SOC_MANAGER, UserRole.ADMIN)),
):
    """
    Reject a lesson: discard it. It will never reach ChromaDB.
    Useful when the Critic Agent generated an inaccurate or misleading lesson.
    """
    row = _get_review_or_404(review_id, db)

    row.status      = LessonReviewStatus.REJECTED
    row.reviewer_id = user["username"]
    row.review_note = decision.note
    row.reviewed_at = datetime.now(timezone.utc)
    db.commit()

    logger.info(
        "LESSON REJECTED: review_id=%d category=%s by=%s reason=%s",
        review_id, row.category, user["username"], decision.note,
    )
    return {"status": "rejected"}


def _get_review_or_404(review_id: int, db: Session) -> LessonReview:
    row = db.execute(
        select(LessonReview).where(LessonReview.id == review_id)
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail=f"Review {review_id} not found")
    if row.status != LessonReviewStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Review {review_id} is already {row.status} — cannot change",
        )
    return row


def _store_to_chromadb(row: LessonReview) -> None:
    from agents.shared.chroma_client import get_lessons_collection
    from uuid import uuid4

    collection = get_lessons_collection()
    lesson_id  = f"critic_{uuid4().hex[:12]}"
    collection.add(
        documents=[row.lesson_text],
        metadatas=[{
            "category":   row.category,
            "source":     row.source,
            "alert_id":   row.alert_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }],
        ids=[lesson_id],
    )


def _store_to_postgres(row: LessonReview, db: Session) -> None:
    from data.postgres.models import Lesson
    from uuid import uuid4

    lesson_id = f"critic_{uuid4().hex[:12]}"
    db.add(Lesson(
        lesson_id=lesson_id,
        alert_id=row.alert_id,
        category=row.category,
        lesson_text=row.lesson_text,
        source=row.source,
        created_by="critic_agent",
    ))
