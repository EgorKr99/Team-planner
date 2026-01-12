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
from pathlib import Path
from .db import Base, engine, get_db
from .models import User, Task, Worklog
from .services import week_start, daterange, actual_hours_for_task, actual_hours_for_user_day
from datetime import date as ddate
from datetime import datetime
import re


Base.metadata.create_all(bind=engine)

BASE_DIR = Path(__file__).resolve().parent          # .../app
app = FastAPI()
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def base_ctx(request: Request, current, nav_date=None):
    return {
        "request": request,
        "current": current,
        "nav_date": nav_date or ddate.today(),
        "title": None,
    }

def parse_date_any(s: str) -> date:
    s = (s or "").strip()
    if not s:
        raise HTTPException(status_code=400, detail="Missing date")
    # ISO: 2026-01-04
    try:
        return date.fromisoformat(s)
    except ValueError:
        pass
    # RU: 04.01.26 или 04.01.2026
    for fmt in ("%d.%m.%y", "%d.%m.%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    raise HTTPException(status_code=400, detail="Bad date format. Use YYYY-MM-DD or DD.MM.YY")

def fmt_ddmmyy(d: date) -> str:
    return d.strftime("%d.%m.%y")


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
    group_tasks = db.query(Task).filter(Task.is_group == True).order_by(Task.end_date.asc()).all()

    all_tasks = db.query(Task).order_by(Task.end_date.asc(), Task.priority.desc()).all()
    children_by_parent = {}
    for t in all_tasks:
        if t.parent_id:
            children_by_parent.setdefault(t.parent_id, []).append(t)

    root_tasks = [t for t in all_tasks if not t.parent_id]

    # упорядочиваем: группы первыми, потом одиночные
    root_tasks.sort(key=lambda x: (0 if x.is_group else 1, x.end_date, -int(x.priority or 0)))

    task_rows = []
    for rt in root_tasks:
        task_rows.append((rt, 0))  # level 0
        if rt.is_group:
            kids = children_by_parent.get(rt.id, [])
            # сортировка внутри группы — позже подключим по параметрам
            kids.sort(key=lambda x: (x.end_date, -int(x.priority or 0), x.title.lower()))
            for k in kids:
                task_rows.append((k, 1))  # level 1

    user_map = {u.id: u for u in users}
    ctx = base_ctx(request, admin, nav_date=date.today())
    ctx.update({
        "admin": admin,
        "users": users,
        "group_tasks": group_tasks,
        "task_rows": task_rows,
        "user_map": user_map,
    })
    return templates.TemplateResponse("admin.html", ctx)

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
    description: str = Form(""),
    is_group: str | None = Form(None),
    parent_id: str = Form(""),
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
    sd = parse_date_any(start_date)
    ed = parse_date_any(end_date)
    assignee = int(assignee_id) if assignee_id.strip() else None

    group_flag = (is_group is not None)
    pid = int(parent_id) if parent_id.strip() else None

    # если задача — общая, она не должна быть чьей-то подзадачей
    if group_flag:
        pid = None

    # если задача — подзадача, родитель должен быть is_group=True
    if pid:
        parent = db.query(Task).filter(Task.id == pid).first()
        if not parent or not parent.is_group:
            raise HTTPException(400, detail="Parent must be a group task")

    t = Task(
        title=title.strip(),
        description=(description or "").strip(),
        is_group=group_flag,
        parent_id=pid,
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

    if pid:
        recompute_group_progress(db, pid)
        db.commit()

    return RedirectResponse(url="/admin", status_code=303)


def recompute_group_progress(db: Session, group_task_id: int) -> None:
    children = db.query(Task).filter(Task.parent_id == group_task_id, Task.is_group == False).all()
    if not children:
        grp = db.query(Task).filter(Task.id == group_task_id).first()
        if grp:
            grp.current_progress = 0
            grp.status = "todo"
        return

    weights = [float(c.planned_hours or 0.0) for c in children]
    total_w = sum(weights)
    if total_w <= 0:
        avg = sum(int(c.current_progress or 0) for c in children) / len(children)
    else:
        avg = sum((int(c.current_progress or 0) * w) for c, w in zip(children, weights)) / total_w

    grp = db.query(Task).filter(Task.id == group_task_id).first()
    if not grp:
        return

    grp.current_progress = int(round(avg))
    grp.status = "done" if grp.current_progress >= 100 else ("in_progress" if grp.current_progress > 0 else "todo")


# ---------- Task edit ----------

def parse_any_date(s: str) -> ddate:
    """
    Принимает:
      - YYYY-MM-DD (из <input type="date">)
      - DD.MM.YY
      - DD.MM.YYYY
    """
    s = (s or "").strip()
    if not s:
        raise ValueError("empty date")
    try:
        return ddate.fromisoformat(s)
    except Exception:
        pass

    m = re.match(r"^(\d{2})\.(\d{2})\.(\d{2}|\d{4})$", s)
    if not m:
        raise ValueError("bad date format")

    dd, mm, yy = m.groups()
    year = int(yy)
    if year < 100:
        year += 2000
    return ddate(year, int(mm), int(dd))


@app.post("/admin/tasks/update")
def admin_update_task(
        request: Request,
        task_id: int = Form(...),

        title: str = Form(...),
        description: str = Form(""),

        assignee_id: str = Form(""),
        start_date: str = Form(...),
        end_date: str = Form(...),

        planned_hours: float = Form(0.0),
        priority: int = Form(3),

        status: str = Form("todo"),
        current_progress: int = Form(0),

        is_group: str | None = Form(None),
        parent_id: str = Form(""),

        db: Session = Depends(get_db),
):
    admin = get_current_user(request, db)
    require_role(admin, {"admin"})

    t = db.query(Task).filter(Task.id == task_id).first()
    if not t:
        raise HTTPException(404, detail="Task not found")

    old_parent = t.parent_id
    old_is_group = bool(t.is_group)

    # parse dates
    try:
        sd = parse_any_date(start_date)
        ed = parse_any_date(end_date)
    except Exception:
        raise HTTPException(status_code=400, detail="Bad date format")

    if ed < sd:
        raise HTTPException(status_code=400, detail="End date must be >= start date")

    # assignee
    assignee = int(assignee_id) if (assignee_id or "").strip() else None

    # group / parent rules
    group_flag = (is_group is not None)
    pid = int(parent_id) if (parent_id or "").strip() else None

    # normalize status/progress
    try:
        prog = int(current_progress)
    except Exception:
        prog = 0
    prog = max(0, min(100, prog))

    status = (status or "todo").strip().lower()
    allowed_status = {"todo", "in_progress", "done"}
    if status not in allowed_status:
        status = "todo"

    # if group -> no parent; progress/status computed
    if group_flag:
        pid = None
        # если задача раньше была подзадачей — отвязываем
        t.parent_id = None
    else:
        # если указан parent_id — он должен быть группой
        if pid:
            if pid == t.id:
                raise HTTPException(400, detail="Task cannot be parent of itself")
            parent = db.query(Task).filter(Task.id == pid).first()
            if not parent or not parent.is_group:
                raise HTTPException(400, detail="Parent must be a group task")

    # если снимаем флаг группы, а у задачи есть дети — отвяжем детей (чтобы не ломать структуру)
    if old_is_group and (not group_flag):
        children = db.query(Task).filter(Task.parent_id == t.id).all()
        for ch in children:
            ch.parent_id = None

    # apply changes
    t.title = title.strip()
    t.description = (description or "").strip()

    t.assignee_id = assignee
    t.start_date = sd
    t.end_date = ed

    t.planned_hours = float(planned_hours or 0.0)
    t.priority = int(priority or 3)

    t.is_group = group_flag
    t.parent_id = pid

    if group_flag:
        # прогресс/статус пересчитаем от детей
        recompute_group_progress(db, t.id)
    else:
        # согласуем статус и прогресс
        if status == "done":
            prog = 100
        elif prog == 100:
            status = "done"
        elif prog > 0 and status == "todo":
            status = "in_progress"

        t.current_progress = prog
        t.status = status

        # если у подзадачи есть родитель — пересчитаем
        if t.parent_id:
            recompute_group_progress(db, t.parent_id)

    db.commit()

    # если поменяли родителя — пересчитать и старого, и нового
    if old_parent and old_parent != t.parent_id:
        recompute_group_progress(db, old_parent)
        db.commit()

    return RedirectResponse(url="/admin", status_code=303)


# ---------- Task delete ----------

@app.post("/admin/tasks/delete")
def admin_delete_task(
        request: Request,
        task_id: int = Form(...),
        db: Session = Depends(get_db),
):
    admin = get_current_user(request, db)
    require_role(admin, {"admin"})

    t = db.query(Task).filter(Task.id == task_id).first()
    if not t:
        return RedirectResponse(url="/admin", status_code=303)

    parent_id = t.parent_id

    # Собираем subtree (если удаляем группу — удаляем и все подзадачи/внуков)
    ids_to_delete = []
    queue = [task_id]
    seen = set()

    while queue:
        cur = queue.pop(0)
        if cur in seen:
            continue
        seen.add(cur)
        ids_to_delete.append(cur)

        child_ids = db.query(Task.id).filter(Task.parent_id == cur).all()
        queue.extend([cid for (cid,) in child_ids])

    # Удаляем сначала логи, потом задачи
    db.query(Worklog).filter(Worklog.task_id.in_(ids_to_delete)).delete(synchronize_session=False)
    db.query(Task).filter(Task.id.in_(ids_to_delete)).delete(synchronize_session=False)
    db.commit()

    # Если удаляли подзадачу — пересчитаем прогресс у группы-родителя
    if parent_id and parent_id not in ids_to_delete:
        recompute_group_progress(db, parent_id)
        db.commit()

    return RedirectResponse(url="/admin", status_code=303)



# ---------- Employee day plan ----------
@app.get("/day", response_class=HTMLResponse)
def day_view(request: Request, d: str | None = None, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    require_role(user, {"admin", "employee"})

    the_date = parse_date_any(d) if d else date.today()

    tasks = (
        db.query(Task)
        .filter(Task.assignee_id == user.id)
        .filter(Task.is_group == False)
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

    ctx = base_ctx(request, user, nav_date=the_date)
    ctx.update({
        "user": user,
        "date": the_date,
        "tasks": tasks,
        "stats": stats,
        "log_by_task": log_by_task,
        "day_total": day_total,
    })
    return templates.TemplateResponse("day.html", ctx)


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

    the_date = parse_date_any(d)

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
        return RedirectResponse(url=f"/day?d={fmt_ddmmyy(the_date)}", status_code=303)

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
    if task.parent_id:
        recompute_group_progress(db, task.parent_id)

    db.commit()
    return RedirectResponse(url=f"/day?d={fmt_ddmmyy(the_date)}", status_code=303)


# ---------- Week plan ----------
@app.get("/week", response_class=HTMLResponse)
def week_view(request: Request, d: str | None = None, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    user_map = {u.id: u for u in db.query(User).all()}
    require_role(user, {"admin", "employee", "viewer"})

    the_date = parse_date_any(d) if d else date.today()
    ws = week_start(the_date)
    days = list(daterange(ws, 7))

    tasks = db.query(Task).order_by(Task.priority.desc(), Task.end_date.asc()).all()

    users = db.query(User).filter(User.role.in_(("admin","employee")), User.is_active == True).all()
    load = {u.id: {day: {"actual": 0.0} for day in days} for u in users}

    for u in users:
        for day in days:
            load[u.id][day]["actual"] = actual_hours_for_user_day(db, u.id, day)

    ctx = base_ctx(request, user, nav_date=the_date)
    ctx.update({
        "user": user,
        "date": the_date,
        "week_start": ws,
        "days": days,
        "tasks": tasks,
        "users": users,
        "load": load,
        "user_map": user_map,
    })
    return templates.TemplateResponse("week.html", ctx)


# ---------- Reports ----------
@app.get("/reports/daily", response_class=HTMLResponse)
def report_daily(request: Request, d: str, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    require_role(user, {"admin", "viewer"})

    the_date = parse_date_any(d)

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

    ctx = base_ctx(request, user, nav_date=the_date)
    ctx.update({
        "date": the_date,
        "users": users,
        "logs_by_user": logs_by_user,
        "viewer": user,
    })
    return templates.TemplateResponse("report_daily.html", ctx)


