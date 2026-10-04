"""
Backfill Lessons Script
========================
Imports historical incident lessons from PostgreSQL into ChromaDB.
Run this when setting up a new ChromaDB instance against an existing
PostgreSQL database that already has analyst feedback records.

Usage:
    python scripts/backfill_lessons.py
    python scripts/backfill_lessons.py --days 30   # only last 30 days
"""
import argparse
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def backfill(days: int = 365):
    from sqlalchemy import select
    from data.postgres.session import get_session
    from data.postgres.models import Lesson
    from agents.shared.chroma_client import get_lessons_collection

    collection = get_lessons_collection()
    since = datetime.now(timezone.utc) - timedelta(days=days)

    with get_session() as session:
        rows = session.execute(
            select(Lesson).where(Lesson.created_at >= since)
        ).scalars().all()

    if not rows:
        logger.info("No lessons found in PostgreSQL (last %d days)", days)
        return

    logger.info("Backfilling %d lessons from PostgreSQL → ChromaDB...", len(rows))
    success = 0

    # Fetch all existing IDs in a single query to avoid N+1 queries in the loop
    all_ids = [row.lesson_id for row in rows]
    existing = collection.get(ids=all_ids)
    existing_ids = set(existing.get("ids", []))

    for row in rows:
        try:
            # Skip if already exists
            if row.lesson_id in existing_ids:
                continue

            collection.add(
                documents=[row.lesson_text],
                metadatas=[{
                    "category":   row.category,
                    "source":     row.source,
                    "alert_id":   row.alert_id,
                    "created_at": row.created_at.isoformat() if row.created_at else "",
                }],
                ids=[row.lesson_id],
            )
            success += 1
        except Exception as exc:
            logger.warning("Failed to backfill lesson %s: %s", row.lesson_id, exc)

    logger.info("Backfill complete: %d/%d lessons added to ChromaDB", success, len(rows))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=365)
    args = parser.parse_args()
    backfill(args.days)
