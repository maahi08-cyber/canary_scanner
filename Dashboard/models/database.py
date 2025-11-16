"""
Database Configuration and Session Management
============================================

Handles database connection, session management, and initialization
for the Canary Dashboard application.

Features:
- PostgreSQL connection with SQLAlchemy ORM
- Environment-based configuration
- Automatic table creation
- Session dependency injection for FastAPI
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator
import os
import logging

logger = logging.getLogger(__name__)

# Database configuration from environment variables
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:password@localhost:5432/canary_dashboard"
)

# Create SQLAlchemy engine
engine = create_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL query logging
    pool_pre_ping=True,  # Verify connections before use
    pool_recycle=3600,   # Recycle connections after 1 hour
)

# Create SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create Base class for models
Base = declarative_base()

def get_db() -> Generator[Session, None, None]:
    """
    Dependency to get database session.
    Used with FastAPI's Depends() for dependency injection.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db() -> None:
    """Initialize database tables."""
    try:
        # Import all models to ensure they're registered
        from .scan import Scan
        from .finding import Finding

        # Create all tables
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Database tables created/verified successfully")

    except Exception as e:
        logger.error(f"❌ Error initializing database: {str(e)}")
        raise
