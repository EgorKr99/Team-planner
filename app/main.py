from .auth import verify_password, hash_password, gen_session_token
from .deps import get_current_user, require_role, SESSION_COOKIE_NAME
from .models import Session as DbSession
from fastapi import FastAPI, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import date, timedelta

from .db import Base, engine, get_db
from .models import User, Task, Worklog
from .services import week_start, daterange, actual_hours_for_task, actual_hours_for_user_day

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
def login_post(
    request: Request,
    login: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.login == login.strip(), User.is_active == True).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Неверный логин или пароль",
        }, status_code=401)

    # создать сессию
    st = gen_session_token()
    s = DbSession(session_token=st, user_id=user.id)
    db.add(s)
    db.commit()

    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=st,
        httponly=True,
        samesite="lax",
    )
    return resp

@app.get("/")
def index(request: Request, db: Session = Depends(get_db)):
    # если не залогинен — на login
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse(url="/login", status_code=303)

    s = db.query(DbSession).filter(DbSession.session_token == token).first()
    if not s:
        return RedirectResponse(url="/login", status_code=303)

    user = db.query(User).filter(User.id == s.user_id, User.is_active == True).first()
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # по роли
    if user.role == "admin":
        return RedirectResponse(url="/admin", status_code=303)
    if user.role == "viewer":
        return RedirectResponse(url="/week", status_code=303)
    return RedirectResponse(url="/day", status_code=303)



@app.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        db.query(DbSession).filter(DbSession.session_token == token).delete()
        db.commit()

    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp


# ---------- Admin ----------
@app.get("/admin", response_class=HTMLResponse)
def admin_view(request: Request, db: Session = Depends(get_db)):
    admin = get_current_user(request, db)
    require_role(admin, {"admin"})

    users = db.query(User).order_by(User.role.asc(), User.name.asc()).all()
    tasks = db.query(Task).order_by(Task.end_date.asc(), Task.priority.desc()).all()

    user_map = {u.id: u for u in users}
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "admin": admin,
        "current": admin,
        "users": users,
        "tasks": tasks,
        "user_map": user_map,
    })

@app.post("/admin/users/create")
def admin_create_user(
    request: Request,
    name: str = Form(...),
    login: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    db: Session = Depends(get_db),
):
    admin = get_current_user(request, db)
    require_role(admin, {"admin"})

    role = role.strip().lower()
    if role not in ("admin", "employee", "viewer"):
        raise HTTPException(status_code=400, detail="Bad role")

    name = name.strip()
    login = login.strip()

    # простая защита от пустых значений
    if not name or not login or not password:
        raise HTTPException(status_code=400, detail="Empty fields")

    # проверка уникальности логина
    exists = db.query(User).filter(User.login == login).first()
    if exists:
        # можно вернуть страницу с ошибкой, но пока просто 400
        raise HTTPException(status_code=400, detail="Login already exists")

    u = User(
        name=name,
        login=login,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
    )
    db.add(u)
    db.commit()

    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/users/toggle_active")
def admin_toggle_active(
    request: Request,
    user_id: int = Form(...),
    db: Session = Depends(get_db),
):
    admin = get_current_user(request, db)
    require_role(admin, {"admin"})

    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404)

    # нельзя деактивировать самого себя (по желанию)
    if u.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")

    u.is_active = not bool(u.is_active)
    db.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/tasks/create")
def admin_create_task(
    request: Request,
    title: str = Form(...),
    assignee_id: str = Form(...),
    start_date: str = Form(...),
    end_date: str = Form(...),
    planned_hours: float = Form(0.0),
    priority: int = Form(3),
    db: Session = Depends(get_db),
):
    admin = get_current_user(request, db)
    require_role(admin, {"admin"})

    from datetime import date as ddate
    sd = ddate.fromisoformat(start_date)
    ed = ddate.fromisoformat(end_date)
    assignee = int(assignee_id) if assignee_id.strip() else None

    t = Task(
        title=title.strip(),
        assignee_id=assignee,
        start_date=sd,
        end_date=ed,
        planned_hours=float(planned_hours or 0.0),
        priority=int(priority),
        status="todo",
        current_progress=0,
    )
    db.add(t)
    db.commit()

    return RedirectResponse(url="/admin", status_code=303)


# ---------- Employee day plan ----------
@app.get("/day", response_class=HTMLResponse)
def day_view(request: Request, d: str | None = None, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    require_role(user, {"admin", "employee"})

    the_date = date.fromisoformat(d) if d else date.today()

    tasks = (
        db.query(Task)
        .filter(Task.assignee_id == user.id)
        .filter(Task.start_date <= the_date, Task.end_date >= the_date)
        .order_by(Task.priority.desc(), Task.end_date.asc())
        .all()
    )

    # одна запись на задачу в день
    logs = db.query(Worklog).filter(
        Worklog.user_id == user.id,
        Worklog.date == the_date
    ).all()
    log_by_task = {wl.task_id: wl for wl in logs}

    stats = {}
    for t in tasks:
        actual = actual_hours_for_task(db, t.id)
        planned = float(t.planned_hours or 0.0)
        stats[t.id] = {"actual": actual, "planned": planned}

    day_total = float(
        db.query(func.coalesce(func.sum(Worklog.hours), 0.0))
        .filter(Worklog.user_id == user.id, Worklog.date == the_date)
        .scalar() or 0.0
    )

    return templates.TemplateResponse("day.html", {
        "request": request,
        "user": user,
        "current": user,
        "date": the_date,
        "tasks": tasks,
        "stats": stats,
        "log_by_task": log_by_task,
        "day_total": day_total,
    })


@app.post("/day/log")
def day_log(
    request: Request,
    d: str = Form(...),
    task_id: int = Form(...),
    hours: float = Form(0.0),
    comment: str = Form(""),
    progress: int = Form(0),
    is_done: str | None = Form(None),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    require_role(user, {"admin", "employee"})

    the_date = date.fromisoformat(d)

    # clamp progress
    try:
        progress_int = int(progress)
    except Exception:
        progress_int = 0
    progress_int = max(0, min(100, progress_int))

    done = is_done is not None
    final_progress = 100 if done else progress_int

    h = float(hours or 0.0)
    c = (comment or "").strip()

    # если всё пусто — просто вернуться
    if h <= 0 and not c and final_progress == 0 and not done:
        return RedirectResponse(url=f"/day?d={the_date.isoformat()}", status_code=303)

    # защита: нельзя логировать чужую задачу
    task = db.query(Task).filter(Task.id == task_id, Task.assignee_id == user.id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found or not assigned to you")

    # upsert: одна запись на задачу в день
    existing = db.query(Worklog).filter(
        Worklog.user_id == user.id,
        Worklog.task_id == task_id,
        Worklog.date == the_date
    ).first()

    if existing:
        existing.hours = h
        existing.comment = c
        existing.progress = final_progress
        existing.is_done = done
    else:
        wl = Worklog(
            date=the_date,
            user_id=user.id,
            task_id=task_id,
            hours=h,
            comment=c,
            progress=final_progress,
            is_done=done,
        )
        db.add(wl)

    # обновляем карточку задачи
    task.current_progress = final_progress
    task.status = "done" if done else ("in_progress" if final_progress > 0 else "todo")

    db.commit()
    return RedirectResponse(url=f"/day?d={the_date.isoformat()}", status_code=303)


# ---------- Week plan ----------
@app.get("/week", response_class=HTMLResponse)
def week_view(request: Request, d: str | None = None, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    user_map = {u.id: u for u in db.query(User).all()}
    require_role(user, {"admin", "employee", "viewer"})

    the_date = date.fromisoformat(d) if d else date.today()
    ws = week_start(the_date)
    days = list(daterange(ws, 7))

    tasks = db.query(Task).order_by(Task.priority.desc(), Task.end_date.asc()).all()

    users = db.query(User).filter(User.role.in_(("admin","employee")), User.is_active == True).all()
    load = {u.id: {day: {"actual": 0.0} for day in days} for u in users}

    for u in users:
        for day in days:
            load[u.id][day]["actual"] = actual_hours_for_user_day(db, u.id, day)

    return templates.TemplateResponse("week.html", {
        "request": request,
        "user": user,
        "current": user,
        "date": the_date,
        "week_start": ws,
        "days": days,
        "tasks": tasks,
        "users": users,
        "load": load,
        "user_map": user_map,  # <-- добавили
    })


# ---------- Reports ----------
@app.get("/reports/daily", response_class=HTMLResponse)
def report_daily(request: Request, d: str, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    require_role(user, {"admin", "viewer"})

    the_date = date.fromisoformat(d)

    users = db.query(User).filter(
        User.role.in_(("admin","employee")),
        User.is_active == True
    ).order_by(User.name.asc()).all()

    task_map = {t.id: t for t in db.query(Task).all()}

    logs = db.query(Worklog).filter(
        Worklog.date == the_date
    ).order_by(Worklog.created_at.asc()).all()

    logs_by_user = {u.id: [] for u in users}
    for wl in logs:
        if wl.user_id in logs_by_user:
            logs_by_user[wl.user_id].append((wl, task_map.get(wl.task_id)))

    return templates.TemplateResponse("report_daily.html", {
        "request": request,
        "current": user,
        "date": the_date,
        "users": users,
        "logs_by_user": logs_by_user,
        "viewer": user,   # если в шаблоне ждёшь viewer
    })

