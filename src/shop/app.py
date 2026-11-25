"""ENU Lab Shop API v1 — учебный REST API (ИСПРАВЛЕННАЯ ВЕРСИЯ, тег v2-fixed).

Исправления по результатам SAST (Semgrep), security-тестов и тестирования через WAF:
  * API1 BOLA — проверка владельца объекта (can_access) во всех обработчиках с ID в пути;
    для чужого объекта всегда 403 до обращения к данным (нет оракула существования);
  * API3 Mass Assignment — явные схемы запросов (allowlist полей, проверка типов и длины),
    лишние поля → 400; SQL-запросы статические, без имён столбцов из запроса;
  * API3 Excessive Data Exposure — в ответе нет is_admin, ИИН и хеша пароля.
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
PUBLIC_FIELDS = ("id", "username", "full_name", "email", "phone", "card_last4", "balance", "role")

# Схемы запросов (соответствуют openapi.yaml, additionalProperties: false): поле → максимальная длина
REGISTER_SCHEMA = {"username": 32, "password": 128, "full_name": 100, "email": 100, "phone": 20}
PROFILE_SCHEMA = {"full_name": 100, "email": 100, "phone": 20}


def validate(data, schema, required=()):
    """Возвращает текст ошибки или None. Неизвестные поля не игнорируются, а отклоняются."""
    if not isinstance(data, dict):
        return "JSON object expected"
    unknown = sorted(set(data) - set(schema))
    if unknown:
        log.warning("mass assignment attempt: unexpected fields %s from %s", unknown, request.remote_addr)
        return "unexpected fields: " + ", ".join(unknown)
    for name in required:
        if not data.get(name):
            return f"{name} is required"
    for name, value in data.items():
        if not isinstance(value, str) or len(value) > schema[name]:
            return f"invalid value for {name}"
    return None


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
        if g.role != "admin":
            log.warning("access denied: user=%s path=%s", g.user_id, request.path)
            return jsonify(error="forbidden"), 403
        return f(*args, **kwargs)

    return wrapper


def can_access(owner_id: int) -> bool:
    """Правило авторизации на уровне объекта: владелец или администратор."""
    allowed = owner_id == g.user_id or g.role == "admin"
    if not allowed:
        log.warning("BOLA attempt: user=%s object_owner=%s path=%s", g.user_id, owner_id, request.path)
    return allowed


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
    data = request.get_json(silent=True)
    error = validate(data, REGISTER_SCHEMA, required=("username", "password"))
    if error:
        return jsonify(error=error), 400
    conn = db.get_conn()
    try:
        # роль, флаг администратора и баланс задаёт сервер, а не клиент
        cur = conn.execute(
            "INSERT INTO users (username, password, role, is_admin, full_name, email, phone, balance) "
            "VALUES (?, ?, 'user', 0, ?, ?, ?, 0)",
            (data["username"], db.hash_password(data["password"]),
             data.get("full_name"), data.get("email"), data.get("phone")),
        )
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
    if not can_access(user_id):
        return jsonify(error="forbidden"), 403
    row = db.get_conn().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(public(row)) if row else (jsonify(error="not found"), 404)


@app.patch("/api/v1/users/<int:user_id>/profile")
@require_auth
def update_profile(user_id):
    if not can_access(user_id):
        return jsonify(error="forbidden"), 403
    data = request.get_json(silent=True)
    error = validate(data, PROFILE_SCHEMA) or (None if data else "nothing to update")
    if error:
        return jsonify(error=error), 400
    conn = db.get_conn()
    conn.execute(
        "UPDATE users SET full_name = COALESCE(?, full_name), email = COALESCE(?, email), "
        "phone = COALESCE(?, phone) WHERE id = ?",
        (data.get("full_name"), data.get("email"), data.get("phone"), user_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(public(row)) if row else (jsonify(error="not found"), 404)


@app.get("/api/v1/orders/<int:order_id>")
@require_auth
def order(order_id):
    row = db.get_conn().execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    if not can_access(row["user_id"]):
        return jsonify(error="forbidden"), 403
    return jsonify(dict(row))


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
