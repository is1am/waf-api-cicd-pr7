"""Регрессионные security-тесты API (OWASP API Security Top 10, 2023).

API1 — BOLA, API3 — Mass Assignment. На уязвимой версии (v1-vulnerable) тесты этих
категорий падают, на исправленной (v2-fixed) — проходят. Функциональные тесты проходят всегда.
"""
import os
import tempfile

import pytest

os.environ.setdefault("SHOP_SECRET_KEY", "test-only-secret-key-with-at-least-32-chars!")
os.environ["SHOP_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

from src.shop import app as shop  # noqa: E402
from src.shop import db  # noqa: E402

PASSWORDS = {u[1]: u[2] for u in db.USERS}
ALIYA, TIMUR = 101, 102


@pytest.fixture()
def client():
    shop.init_app_db()
    shop.app.config["TESTING"] = True
    return shop.app.test_client()


def login(client, username, password=None):
    r = client.post("/api/v1/login", json={"username": username, "password": password or PASSWORDS[username]})
    assert r.status_code == 200, r.get_json()
    return {"Authorization": "Bearer " + r.get_json()["token"]}


# ---------- функциональность ----------
def test_own_profile_is_available(client):
    r = client.get(f"/api/v1/users/{ALIYA}/profile", headers=login(client, "aliya"))
    assert r.status_code == 200 and r.get_json()["username"] == "aliya"


def test_profile_requires_token(client):
    assert client.get(f"/api/v1/users/{ALIYA}/profile").status_code == 401


def test_admin_can_read_any_profile(client):
    r = client.get(f"/api/v1/users/{TIMUR}/profile", headers=login(client, "admin"))
    assert r.status_code == 200 and r.get_json()["username"] == "timur"


def test_regular_registration_works(client):
    r = client.post("/api/v1/register", json={"username": "newbie", "password": "Newbie#2026",
                                              "full_name": "Новый пользователь", "email": "newbie@lab.local"})
    assert r.status_code == 201 and r.get_json()["role"] == "user"


def test_own_profile_update_works(client):
    r = client.patch(f"/api/v1/users/{ALIYA}/profile", json={"phone": "+7 701 111 11 11"},
                     headers=login(client, "aliya"))
    assert r.status_code == 200 and r.get_json()["phone"] == "+7 701 111 11 11"


# ---------- API1:2023 — BOLA ----------
def test_bola_foreign_profile_is_forbidden(client):
    r = client.get(f"/api/v1/users/{TIMUR}/profile", headers=login(client, "aliya"))
    assert r.status_code == 403
    assert "timur" not in r.get_data(as_text=True)


@pytest.mark.parametrize("victim", [100, 102, 103, 104])
def test_bola_enumeration_leaks_nothing(client, victim):
    r = client.get(f"/api/v1/users/{victim}/profile", headers=login(client, "aliya"))
    assert r.status_code == 403


def test_bola_foreign_order_is_forbidden(client):
    r = client.get("/api/v1/orders/5002", headers=login(client, "aliya"))   # заказ Тимура
    assert r.status_code == 403


def test_bola_foreign_profile_update_is_forbidden(client):
    r = client.patch(f"/api/v1/users/{TIMUR}/profile", json={"email": "attacker@evil.test"},
                     headers=login(client, "aliya"))
    assert r.status_code == 403


# ---------- API3:2023 — Mass Assignment ----------
def test_mass_assignment_on_register_is_rejected(client):
    r = client.post("/api/v1/register", json={"username": "mallory", "password": "Mallory#2026",
                                              "role": "admin", "is_admin": True, "balance": 999999})
    assert r.status_code == 400
    assert client.post("/api/v1/login", json={"username": "mallory", "password": "Mallory#2026"}).status_code == 401


def test_mass_assignment_on_profile_update_is_rejected(client):
    h = login(client, "aliya")
    r = client.patch(f"/api/v1/users/{ALIYA}/profile", json={"is_admin": 1, "role": "admin"}, headers=h)
    assert r.status_code == 400
    assert client.get("/api/v1/admin/users", headers=h).status_code == 403


def test_balance_cannot_be_changed_by_owner(client):
    h = login(client, "aliya")
    client.patch(f"/api/v1/users/{ALIYA}/profile", json={"balance": 10_000_000}, headers=h)
    assert client.get(f"/api/v1/users/{ALIYA}/profile", headers=h).get_json().get("balance", 15000) == 15000


def test_response_does_not_expose_internal_fields(client):
    r = client.get(f"/api/v1/users/{ALIYA}/profile", headers=login(client, "aliya"))
    body = r.get_json()
    assert "password" not in body and "is_admin" not in body and "iin" not in body
