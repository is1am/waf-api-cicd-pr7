#!/usr/bin/env bash
# Снимки консоли для отчёта: команды из методических указаний (cURL) и их вывод.
# Результат: evidence/console/*.txt (затем report/render.py term ... → PNG).
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd); cd "$REPO"
OUT=$REPO/evidence/console; mkdir -p "$OUT"
PY=/opt/pr7venv/bin/python
MS=/etc/nginx/modsec
P='root@enu-lab:~/pr7#'
run() { echo "$P $*"; bash -c "$*" 2>&1; }

# ------------------------------------------------------------ окружение
{
run 'lsb_release -ds; uname -r'
run 'nginx -v; dpkg -l | awk "/libmodsecurity3t64|libnginx-mod-http-modsecurity/{print \$2, \$3}"'
run 'git -C /etc/nginx/modsec/crs describe --tags; docker --version; /opt/pr7venv/bin/python --version'
run 'git log --oneline --decorate | cat'
} > "$OUT/env.txt"

# ------------------------------------------------------------ часть 1: WAF
{
run 'grep -E "^(SecRuleEngine|SecRequestBodyAccess|SecAuditEngine|SecAuditLog |SecAuditLogParts)" /etc/nginx/modsec/modsecurity.conf'
run 'cat /etc/nginx/modsec/main.conf | grep -v "^#"'
run 'cat /etc/nginx/sites-enabled/api.local | grep -v "^ *#"'
run 'nginx -t'
} > "$OUT/waf_setup.txt"

# ------------------------------------------------------------ API v1 за WAF с правилами проекта
rm -f "$MS"/custom/*.conf; cp waf/rules/api-custom.conf "$MS/custom/"; nginx -s reload; sleep 1
pkill -f "python -m src[.]shop[.]app"; sleep 1
(cd /opt/pr7v1 && SHOP_SECRET_KEY=$(openssl rand -hex 32) SHOP_DB=/tmp/pr7_cap.db nohup $PY -m src.shop.app >/tmp/pr7_cap.log 2>&1 &)
timeout 30 sh -c 'until curl -sf http://127.0.0.1:5000/api/v1/products >/dev/null; do sleep 0.5; done'
: > /var/log/modsec_audit.log

TOKEN=$(curl -s http://127.0.0.1:5000/api/v1/login -H 'Content-Type: application/json' \
        -d '{"username":"aliya","password":"Aliya#2026"}' | $PY -c 'import json,sys; print(json.load(sys.stdin)["token"])')
export TOKEN
{
echo "$P TOKEN=\$(curl -s http://api.local/api/v1/login -d '{\"username\":\"aliya\",\"password\":\"…\"}' | jq -r .token)"
echo "$P # 1) напрямую в API (без WAF), aliya (ID=101) запрашивает профиль ID=102"
run 'curl -s -w "\nHTTP %{http_code}\n" http://127.0.0.1:5000/api/v1/users/102/profile -H "Authorization: Bearer $TOKEN"'
echo "$P # 2) тот же запрос через WAF (Nginx + ModSecurity, правило 1006)"
run 'curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "Host: api.local" http://127.0.0.1/api/v1/users/102/profile -H "Authorization: Bearer $TOKEN"'
echo "$P # 3) свой профиль через WAF — пропускается"
run 'curl -s -w "\nHTTP %{http_code}\n" -H "Host: api.local" http://127.0.0.1/api/v1/users/101/profile -H "Authorization: Bearer $TOKEN"'
} > "$OUT/curl_bola.txt"

{
echo "$P # Mass Assignment: регистрация с привилегированными полями — напрямую в API"
run "curl -s -w '\nHTTP %{http_code}\n' http://127.0.0.1:5000/api/v1/register -H 'Content-Type: application/json' -d '{\"username\":\"mallory\",\"password\":\"Mallory#2026\",\"role\":\"admin\",\"is_admin\":true,\"balance\":1000000}'"
echo "$P # тот же запрос через WAF (правило 1010)"
run "curl -s -o /dev/null -w 'HTTP %{http_code}\n' -H 'Host: api.local' http://127.0.0.1/api/v1/register -H 'Content-Type: application/json' -d '{\"username\":\"mallory2\",\"password\":\"Mallory#2026\",\"role\":\"admin\",\"is_admin\":true}'"
echo "$P # обход через \\u-экранирование имени поля"
run "curl -s -o /dev/null -w 'HTTP %{http_code}\n' -H 'Host: api.local' -X PATCH http://127.0.0.1/api/v1/users/101/profile -H \"Authorization: Bearer \$TOKEN\" -H 'Content-Type: application/json' -d '{\"\\u0069s_admin\":1}'"
} > "$OUT/curl_mass_assignment.txt"
sleep 1
{
echo "$P grep -E 'id \"10[0-9]{2}\"' /var/log/nginx/api.local.error.log | sed -E 's/.*(\\[id[^]]*\\]).*(\\[msg[^]]*\\]).*(\\[data[^]]*\\]).*(\\[uri[^]]*\\]).*/\\1 \\2 \\3 \\4/' | tail -4"
grep -E 'id "10[0-9]{2}"' /var/log/nginx/api.local.error.log | sed -E 's/.*(\[id[^]]*\]).*(\[msg[^]]*\]).*(\[data[^]]*\]).*(\[uri[^]]*\]).*/\1 \2 \3 \4/' | tail -4
} > "$OUT/error_log.txt"
cp /var/log/modsec_audit.log "$OUT/modsec_audit_curl.log"
pkill -f "python -m src[.]shop[.]app"
echo done
