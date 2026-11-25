#!/usr/bin/env bash
# Части 2–3 методических указаний: атаки на API напрямую и через WAF с разными наборами правил.
# Этапы:
#   0-direct   — API v1 без WAF (http://127.0.0.1:5000)
#   1-crs      — Nginx + ModSecurity + OWASP CRS (без собственных правил)
#   2-naive    — + правило 1001 из методических указаний (deny)
#   3-custom   — + собственные правила waf/rules/api-custom.conf
#   4-v2-waf   — исправленное API v2 за WAF с собственными правилами (эшелонированная защита)
# Запуск (WSL, root): bash scripts/waf_lab.sh [этапы...]   результаты → evidence/waf_lab/<этап>/
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=$REPO/evidence/waf_lab
PY=${PY:-/opt/pr7venv/bin/python}
MS=/etc/nginx/modsec
AUDIT=/var/log/modsec_audit.log
export SHOP_SECRET_KEY=${SHOP_SECRET_KEY:-$(openssl rand -hex 32)}
mkdir -p "$OUT"

checkout() {   # $1 — тег, $2 — каталог
  rm -rf "$2"; mkdir -p "$2"
  git -C "$REPO" archive "$1" src requirements.txt | tar -x -C "$2"
}

start_api() {  # $1 — каталог с кодом
  pkill -f "src.shop.app" 2>/dev/null; sleep 1
  (cd "$1" && SHOP_DB=/tmp/pr7_shop.db nohup "$PY" -m src.shop.app >/tmp/pr7_api.log 2>&1 &)
  for _ in $(seq 30); do curl -sf http://127.0.0.1:5000/api/v1/products >/dev/null && return 0; sleep 0.5; done
  echo "API не запустилось"; cat /tmp/pr7_api.log; exit 1
}

waf_rules() {  # $1 — файл правил проекта для каталога custom/
  rm -f "$MS"/custom/*.conf
  cp "$1" "$MS/custom/"
  nginx -t 2>&1 | tail -1
  nginx -s reload; sleep 1
  : > "$AUDIT"
}

stage() {      # $1 — имя, $2 — base, $3 — Host
  local d=$OUT/$1
  rm -rf "$d"; mkdir -p "$d"
  echo; echo "################ Этап $1"
  "$PY" "$REPO/scripts/api_attack.py" --base "$2" --host "$3" --out "$d/dumps" --label "$1" | tee "$d/console.txt"
  sleep 1
  cp "$AUDIT" "$d/modsec_audit.log" 2>/dev/null
}

checkout v1-vulnerable /opt/pr7v1
STAGES=${*:-0-direct 1-crs 2-naive 3-custom 4-v2-waf}
for s in $STAGES; do
  case $s in
    0-direct) start_api /opt/pr7v1; : > "$AUDIT"; stage "$s" http://127.0.0.1:5000 "" ;;
    1-crs)    start_api /opt/pr7v1; waf_rules "$REPO/waf/stages/crs-only.conf";   stage "$s" http://127.0.0.1 api.local ;;
    2-naive)  start_api /opt/pr7v1; waf_rules "$REPO/waf/stages/naive-1001.conf"; stage "$s" http://127.0.0.1 api.local ;;
    3-custom) start_api /opt/pr7v1; waf_rules "$REPO/waf/rules/api-custom.conf";  stage "$s" http://127.0.0.1 api.local ;;
    4-v2-waf) checkout v2-fixed /opt/pr7v2; start_api /opt/pr7v2
              waf_rules "$REPO/waf/rules/api-custom.conf"; stage "$s" http://127.0.0.1 api.local ;;
  esac
done
echo; echo "################ Сводка"
for s in $STAGES; do grep -h "^ИТОГ" "$OUT/$s/console.txt"; done | tee "$OUT/summary.txt"
