import secrets
from datetime import date, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
from .models import User, Task, Worklog

def gen_token() -> str:
    return secrets.token_urlsafe(32)

def auth_by_token(db: Session, token: str) -> User:
    user = db.query(User).filter(User.token == token, User.is_active == True).first()
    return user

def week_start(d: date) -> date:
    # Monday as start
    return d - timedelta(days=d.weekday())

def daterange(d0: date, days: int):
    for i in range(days):
        yield d0 + timedelta(days=i)

def actual_hours_for_task(db: Session, task_id: int) -> float:
    v = db.query(func.coalesce(func.sum(Worklog.hours), 0.0)).filter(Worklog.task_id == task_id).scalar()
    return float(v or 0.0)

def actual_hours_for_user_day(db: Session, user_id: int, d: date) -> float:
    v = db.query(func.coalesce(func.sum(Worklog.hours), 0.0)).filter(
        Worklog.user_id == user_id,
        Worklog.date == d
    ).scalar()
    return float(v or 0.0)
