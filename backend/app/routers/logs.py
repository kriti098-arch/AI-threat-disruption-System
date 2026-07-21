from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.db import SessionLocal
from app import schemas, crud

router = APIRouter(prefix="/logs", tags=["Logs"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/", response_model=schemas.SystemLogResponse)
def create_system_log(
    log: schemas.SystemLogCreate,
    db: Session = Depends(get_db)
):
    return crud.create_log(db, log)
