"""ENU Lab Shop API v1 — учебный REST API (УЯЗВИМАЯ ВЕРСИЯ, тег v1-vulnerable).

Намеренно оставлены две уязвимости из OWASP API Security Top 10 (2023):
  * API1 — Broken Object Level Authorization (BOLA): профиль и заказ выдаются по ID из URL
    без проверки, что объект принадлежит вызывающему пользователю;
  * API3 — Broken Object Property Level Authorization (Mass Assignment): регистрация и
    обновление профиля переносят в модель любые поля JSON, совпадающие со столбцами таблицы
    (в т. ч. role, is_admin, balance).
Остальные меры из ПР6 (параметризованные запросы, секрет из окружения, PBKDF2) сохранены.
"""
import logging
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

from . import db

app = Flask(__name__)
log = logging.getLogger("shop")


def load_secret() -> str:
    secret = os.environ.get("SHOP_SECRET_KEY", "")
    if len(secret) < 32:
        raise RuntimeError("SHOP_SECRET_KEY не задан или короче 32 символов")
    return secret


SECRET_KEY = load_secret()
TOKEN_TTL = timedelta(minutes=30)
PUBLIC_FIELDS = ("id", "username", "full_name", "email", "phone", "card_last4", "iin", "balance", "role", "is_admin")


def init_app_db() -> None:
    db.init_db(hasher=db.hash_password)


# ------------------------------------------------------------------ аутентификация
def issue_token(row) -> str:
    now = datetime.now(timezone.utc)
    claims = {"sub": str(row["id"]), "role": row["role"], "iat": now, "exp": now + TOKEN_TTL}
    return jwt.encode(claims, SECRET_KEY, algorithm="HS256")


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="unauthorized"), 401
        try:
            claims = jwt.decode(header[7:], SECRET_KEY, algorithms=["HS256"], options={"require": ["exp", "sub"]})
        except jwt.PyJWTError:
            return jsonify(error="unauthorized"), 401
        row = db.get_conn().execute("SELECT id, role, is_admin FROM users WHERE id = ?",
                                    (int(claims["sub"]),)).fetchone()
        if row is None:
            return jsonify(error="unauthorized"), 401
        g.user_id, g.role, g.is_admin = row["id"], row["role"], bool(row["is_admin"])
        return f(*args, **kwargs)

    return wrapper


def require_admin(f):
    @wraps(f)
    @require_auth
    def wrapper(*args, **kwargs):
        if not (g.role == "admin" or g.is_admin):
            return jsonify(error="forbidden"), 403
        return f(*args, **kwargs)

    return wrapper


def public(row) -> dict:
    return {k: row[k] for k in PUBLIC_FIELDS}


# ------------------------------------------------------------------ маршруты
@app.post("/api/v1/login")
def login():
    data = request.get_json(silent=True) or {}
    username, password = str(data.get("username", "")), str(data.get("password", ""))
    row = db.get_conn().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None or not db.verify_password(password, row["password"]):
        return jsonify(error="invalid credentials"), 401
    return jsonify(token=issue_token(row), id=row["id"], user=row["username"], role=row["role"])


@app.post("/api/v1/register")
def register():
    data = request.get_json(silent=True) or {}
    if not data.get("username") or not data.get("password"):
        return jsonify(error="username and password required"), 400
    data["password"] = db.hash_password(str(data["password"]))
    # УЯЗВИМОСТЬ API3 (Mass Assignment): в INSERT попадают ВСЕ поля запроса,
    # совпадающие со столбцами модели, — включая role, is_admin и balance.
    fields = {k: v for k, v in data.items() if k in db.USER_COLUMNS and k != "id"}
    cols = ", ".join(fields)
    marks = ", ".join("?" for _ in fields)
    conn = db.get_conn()
    try:
        cur = conn.execute(f"INSERT INTO users ({cols}) VALUES ({marks})", tuple(fields.values()))
        conn.commit()
    except db.sqlite3.IntegrityError:
        return jsonify(error="username already exists"), 409
    row = conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
    return jsonify(public(row)), 201


@app.get("/api/v1/products")
def products():
    q = request.args.get("q", "")[:100]
    rows = db.get_conn().execute(
        "SELECT id, name, description, price FROM products WHERE name LIKE ?", (f"%{q}%",)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/v1/users/<int:user_id>/profile")
@require_auth
def get_profile(user_id):
    # УЯЗВИМОСТЬ API1 (BOLA): нет проверки, что user_id == g.user_id
    row = db.get_conn().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(public(row)) if row else (jsonify(error="not found"), 404)


@app.patch("/api/v1/users/<int:user_id>/profile")
@require_auth
def update_profile(user_id):
    data = request.get_json(silent=True) or {}
    # УЯЗВИМОСТИ API1 + API3: чужой профиль и любые поля модели
    fields = {k: v for k, v in data.items() if k in db.USER_COLUMNS and k not in ("id", "password")}
    if not fields:
        return jsonify(error="nothing to update"), 400
    assignments = ", ".join(f"{k} = ?" for k in fields)
    conn = db.get_conn()
    conn.execute(f"UPDATE users SET {assignments} WHERE id = ?", (*fields.values(), user_id))
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(public(row)) if row else (jsonify(error="not found"), 404)


@app.get("/api/v1/orders/<int:order_id>")
@require_auth
def order(order_id):
    # УЯЗВИМОСТЬ API1 (BOLA): заказ любого пользователя
    row = db.get_conn().execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    return jsonify(dict(row)) if row else (jsonify(error="not found"), 404)


@app.get("/api/v1/admin/users")
@require_admin
def admin_users():
    rows = db.get_conn().execute("SELECT * FROM users").fetchall()
    return jsonify([public(r) for r in rows])


# ------------------------------------------------------------------ ошибки и заголовки
@app.errorhandler(HTTPException)
def on_http_error(exc):
    return jsonify(error=exc.name), exc.code


@app.errorhandler(Exception)
def on_error(exc):
    log.exception("unhandled error")
    return jsonify(error="internal server error"), 500


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return resp


def main():
    init_app_db()
    host = os.environ.get("SHOP_HOST", "127.0.0.1")
    app.run(host=host, port=int(os.environ.get("SHOP_PORT", "5000")), debug=False)


if __name__ == "__main__":
    main()
