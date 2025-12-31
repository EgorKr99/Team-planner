from sqlalchemy import Column, Integer, String, Date, DateTime, Float, Boolean, ForeignKey
from datetime import datetime
from .db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)

    name = Column(String, nullable=False)
    role = Column(String, nullable=False)  # admin/employee/viewer

    login = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

    is_active = Column(Boolean, default=True)


class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True)
    parent_id = Column(Integer, ForeignKey("tasks.id"), nullable=True)
    title = Column(String, nullable=False)
    assignee_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    start_date = Column(Date, nullable=False)
    end_date = Column(Date, nullable=False)
    planned_hours = Column(Float, default=0.0)
    priority = Column(Integer, default=3)
    status = Column(String, default="todo")  # todo/in_progress/done
    current_progress = Column(Integer, default=0)

class Worklog(Base):
    __tablename__ = "worklogs"
    id = Column(Integer, primary_key=True)
    date = Column(Date, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False)
    hours = Column(Float, default=0.0)
    comment = Column(String, default="")
    progress = Column(Integer, default=0)
    is_done = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Session(Base):
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True)
    session_token = Column(String, unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

