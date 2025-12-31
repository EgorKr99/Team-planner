from app.db import SessionLocal, engine, Base
from app.models import User
from app.auth import hash_password

Base.metadata.create_all(bind=engine)

db = SessionLocal()

login = "admin"
password = "qaws3412"  # поменяй сразу на своё

# если админ уже есть — не создаём второй раз
exists = db.query(User).filter(User.login == login).first()
if exists:
    print("Admin already exists:", login)
else:
    u = User(
        name="Егор",
        login=login,
        password_hash=hash_password(password),
        role="admin",
        is_active=True,
    )
    db.add(u)
    db.commit()
    print("Created admin:")
    print(" login:", login)
    print(" password:", password)

db.close()
