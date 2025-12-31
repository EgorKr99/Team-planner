from fastapi import Request, HTTPException
from sqlalchemy.orm import Session

from .models import User, Session as DbSession

SESSION_COOKIE_NAME = "session"

def get_current_user(request: Request, db: Session) -> User:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    s = db.query(DbSession).filter(DbSession.session_token == token).first()
    if not s:
        raise HTTPException(status_code=401, detail="Invalid session")

    user = db.query(User).filter(User.id == s.user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not active")

    return user

def require_role(user: User, allowed: set[str]):
    if user.role not in allowed:
        raise HTTPException(status_code=403, detail="Forbidden")
