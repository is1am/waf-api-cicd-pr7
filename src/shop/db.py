"""Учебная база данных SQLite для стенда «ENU Lab Shop API v1».

Создаётся заново при каждом запуске, содержит только вымышленные данные.
Идентификаторы пользователей начинаются со 101 (как в методических указаниях: ID=101 → ID=102).
"""
import hashlib
import hmac
import os
import sqlite3

DB_PATH = os.environ.get("SHOP_DB", os.path.join(os.path.dirname(__file__), "shop.db"))

# Все столбцы модели пользователя (внутреннее представление).
USER_COLUMNS = ("id", "username", "password", "role", "is_admin", "full_name", "email", "phone",
                "card_last4", "iin", "balance")

USERS = [
    # id, username, password, role, is_admin, full_name, email, phone, card_last4, iin, balance
    (100, "admin", "Adm1n!Secure2026", "admin", 1, "Администратор системы", "admin@lab.local",
     "+7 700 000 01 00", "4242", "800101300100", 0),
    (101, "aliya", "Aliya#2026", "user", 0, "Алия Серикова", "aliya@lab.local",
     "+7 700 000 01 01", "1111", "990215450101", 15000),
    (102, "timur", "Timur#2026", "user", 0, "Тимур Ахметов", "timur@lab.local",
     "+7 700 000 01 02", "2222", "010330500102", 42000),
    (103, "dana", "Dana#2026", "user", 0, "Дана Касымова", "dana@lab.local",
     "+7 700 000 01 03", "3333", "000712600103", 8000),
    (104, "erlan", "Erlan#2026", "user", 0, "Ерлан Жумабеков", "erlan@lab.local",
     "+7 700 000 01 04", "4444", "970101350104", 120000),
]

PRODUCTS = [
    (1, "Ноутбук Lab-14", "Учебный ноутбук", 450000),
    (2, "Мышь беспроводная", "Оптическая мышь", 7500),
    (3, "Клавиатура механическая", "Клавиатура для разработчика", 32000),
    (4, "USB-токен", "Аппаратный ключ для 2FA", 18000),
    (5, "Монитор 27\"", "IPS-монитор", 120000),
]

ORDERS = [
    (5001, 101, "Ноутбук Lab-14", 450000, "Астана, ул. Сатпаева, 2"),
    (5002, 102, "USB-токен", 18000, "Астана, пр. Мангилик Ел, 55"),
    (5003, 103, "Монитор 27\"", 120000, "Алматы, ул. Абая, 10"),
    (5004, 101, "Мышь беспроводная", 7500, "Астана, ул. Сатпаева, 2"),
]


def hash_password(password: str, salt: bytes | None = None) -> str:
    """PBKDF2-HMAC-SHA256, 200 000 итераций, соль 16 байт."""
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    salt_hex, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, bytes.fromhex(salt_hex)), stored)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(hasher=hash_password) -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT,
                            role TEXT DEFAULT 'user', is_admin INTEGER DEFAULT 0,
                            full_name TEXT, email TEXT, phone TEXT, card_last4 TEXT,
                            iin TEXT, balance INTEGER DEFAULT 0);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, description TEXT, price INTEGER);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, total INTEGER,
                             address TEXT);
        """
    )
    conn.executemany(
        "INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [(u[0], u[1], hasher(u[2]), *u[3:]) for u in USERS],
    )
    conn.executemany("INSERT INTO products VALUES (?,?,?,?)", PRODUCTS)
    conn.executemany("INSERT INTO orders VALUES (?,?,?,?,?)", ORDERS)
    conn.commit()
    conn.close()
