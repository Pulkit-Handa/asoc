"""
PostgreSQL Session Manager
==========================
Single source of truth for database connections.
All agents and API routers import from here.
"""
import os
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from data.postgres.models import Base

# Read DATABASE_URL from environment, fall back to local dev default
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://asoc:asoc_dev_password@localhost:5432/asoc",
)

engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,   # reconnect if connection dropped
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Create all tables if they don't exist. Called at API startup."""
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_session() -> Session:
    """
    Context manager for database sessions.
    Always commits on success, rolls back on any exception.

    Usage:
        with get_session() as session:
            session.add(my_object)
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# FastAPI dependency (for use with Depends())
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
