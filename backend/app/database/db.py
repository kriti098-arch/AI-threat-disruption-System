import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Uses SQLite by default so this runs anywhere (Render, Railway, your laptop)
# with zero setup. If you ever want to point at a real MySQL/Postgres server
# (e.g. on Render), set a DATABASE_URL environment variable and it'll be used
# instead automatically.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./atds.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
Base = declarative_base()