"""Database setup using SQLAlchemy.

This module provides a SQLAlchemy engine and session factory. The database
URL is read from the environment variable defined in `.env`. Using SQLite
for development is supported out of the box. For production deployments
PostgreSQL is recommended.

All models should use the declarative base defined here.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


from dotenv import load_dotenv
from typing import Generator


# Load environment variables from a .env file if present. This happens at
# module import time which makes configuration available early in the
# application lifecycle.
load_dotenv()


# Read the database URL from the environment with a sensible default. When
# deploying to production ensure that DATABASE_URL points to your
# PostgreSQL instance.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./vault.db")

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    # SQLite needs special flags for thread safety when used with SQLAlchemy.
    connect_args = {"check_same_thread": False}


# Create the SQLAlchemy engine. The `future=True` flag enables SQLAlchemy 2.0
# style usage. Pool pre_ping ensures connections are validated before use.
engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)


# The session factory used throughout the application. Sessions should be
# created with `SessionLocal()` and closed after use to release database
# connections back to the pool.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Base class for models. All ORM models should subclass this.
Base = declarative_base()

# FastAPI dependency: yield a database session and ensure it's closed
def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()