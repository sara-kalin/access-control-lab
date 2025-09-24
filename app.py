from datetime import datetime
import os
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from passlib.hash import bcrypt
from dotenv import load_dotenv
from sqlalchemy import func

load_dotenv()

app = Flask(__name__, template_folder="templates")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "devkey")
# За замовчуванням SQLite, щоб все завелось без дод. сервісів.
# Для Postgres встанови: DATABASE_URL=postgresql+psycopg://ac_user:ac_password@localhost:5432/ac_db
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# --------------------- МОДЕЛІ ---------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")  # admin / moderator / user
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def hash_password(pw: str) -> str:
        return bcrypt.hash(pw)

    def verify(self, pw: str) -> bool:
        return bcrypt.verify(pw, self.password_hash)

    def has_role(self, name: str) -> bool:
        return self.role == name


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, nullable=True)  # може бути None (failed login)
    actor_username = db.Column(db.String(80))        # зручно мати рядком
    event = db.Column(db.String(120), nullable=False)  # login_success, assign_role...
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


# --------------------- ХЕЛПЕРИ ---------------------
def current_user():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None

def audit(event: str, details: str = "", *, actor: User | None = None, actor_username: str | None = None):
    log = AuditLog(
        actor_id=(actor.id if actor else None),
        actor_username=(actor.username if actor else actor_username),
        event=event,
        details=details
    )
    db.session.add(log)
    db.session.commit()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Будь ласка, увійдіть.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def role_required(role_name: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u or u.role != role_name:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# робимо, щоб у ВСІХ шаблонах завжди був доступний змінний `user`
@app.context_processor
def inject_user():
    return {"user": current_user()}

# --------------------- РОУТИ ---------------------
@app.get("/")
@login_required
def index():
    # Підготовка даних для діаграми: скільки користувачів у кожній ролі
    rows = db.session.query(User.role, func.count(User.id)).group_by(User.role).all()
    order = ["admin", "moderator", "user"]
    counts_map = {r: 0 for r in order}
    for role, cnt in rows:
        if role in counts_map:
            counts_map[role] = int(cnt)
    labels = order
    counts = [counts_map[r] for r in order]

    return render_template("dashboard.html", chart_labels=labels, chart_counts=counts)

@app.get("/register")
def register():
    return render_template("register.html")

@app.post("/register")
def register_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # елементарна валідація
    if len(username) < 3:
        flash("Username має містити ≥ 3 символів.", "danger")
        return redirect(url_for("register"))
    if len(password) < 8:
        flash("Пароль має містити ≥ 8 символів.", "danger")
        return redirect(url_for("register"))
    if db.session.scalar(db.select(User).filter_by(username=username)):
        flash("Такий username вже існує.", "danger")
        return redirect(url_for("register"))

    u = User(username=username, password_hash=User.hash_password(password), role="user")
    db.session.add(u)
    db.session.commit()
    audit("register", f"Користувач {username} зареєстрований.", actor=u)
    flash("Реєстрація успішна. Увійдіть.", "success")
    return redirect(url_for("login"))

@app.get("/login")
def login():
    return render_template("login.html")

@app.post("/login")
def login_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    u = db.session.scalar(db.select(User).filter_by(username=username))
    if not u or not u.verify(password):
        audit("login_failed", "Невдала спроба входу", actor_username=username)
        flash("Невірні облікові дані.", "danger")
        return redirect(url_for("login"))
    session["uid"] = u.id
    audit("login_success", f"Користувач {u.username} увійшов.", actor=u)
    flash("Вітаємо у системі!", "success")
    return redirect(url_for("index"))

@app.get("/logout")
def logout():
    u = current_user()
    session.clear()
    if u:
        audit("logout", f"Користувач {u.username} вийшов із системи.", actor=u)
    flash("Ви вийшли із системи.", "info")
    return redirect(url_for("login"))

# -------- Users (ЛИШЕ ДЛЯ АДМІНА): управління ролями --------
@app.get("/users")
@role_required("admin")
def users_page():
    users = db.session.scalars(db.select(User).order_by(User.id)).all()
    return render_template("users.html", users=users)

@app.post("/users/assign-role")
@role_required("admin")
def assign_role():
    user_id = request.form.get("user_id", type=int)
    role_name = request.form.get("role", "").strip()
    if role_name not in {"admin", "moderator", "user"}:
        flash("Невідома роль.", "danger")
        return redirect(url_for("users_page"))

    target = db.session.get(User, user_id)
    if not target:
        flash("Користувача не знайдено.", "danger")
        return redirect(url_for("users_page"))

    old = target.role
    target.role = role_name
    db.session.commit()
    actor = current_user()
    audit("assign_role",
          f"Користувач {actor.username} змінив рівень доступу користувача {target.username} з «{old}» на «{role_name}».",
          actor=actor)
    flash(f"Роль користувача {target.username} змінено на {role_name}.", "success")
    return redirect(url_for("users_page"))

# -------- Audit (admin + moderator можуть переглядати) --------
@app.get("/audit")
@login_required
def audit_list():
    u = current_user()
    if not (u.role in ("admin", "moderator")):
        abort(403)
    logs = db.session.scalars(db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(500)).all()
    return render_template("audit.html", logs=logs)

# --------------------- ПЕРШИЙ ЗАПУСК ---------------------
def seed_admin_if_needed():
    # Створення адміна, якщо його немає
    if not db.session.scalar(db.select(User).filter_by(username="admin")):
        admin = User(
            username="admin",
            password_hash=User.hash_password("administrator"),
            role="admin",
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Створено адміністратора: admin / administrator")

if __name__ == "__main__":
    with app.app_context():
        # якщо в старій БД не було колонки role — додамо (SQLite-safe)
        if "role" not in [c.name for c in User.__table__.columns]:
            # ця гілка майже не спрацює, бо колонка описана в моделі; залишено як підказку
            pass
        db.create_all()
        # якщо таблиця вже була без 'role', то додай її вручну через SQL у своїй СУБД.
        # див. інструкції у попередньому повідомленні з ALTER TABLE.

        seed_admin_if_needed()
    app.run(host="0.0.0.0", port=8000, debug=True)