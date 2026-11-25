#!/usr/bin/env bash
# Локальный прогон задания waf-regression из конвейера CI (те же команды, что в GitHub Actions).
# Использование: bash scripts/ci_waf_local.sh <метка> [каталог результатов]
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd); cd "$REPO"
LABEL=${1:-ci-local}; OUT=${2:-evidence/ci_local/$LABEL}
PY=${PY:-/opt/pr7venv/bin/python}
export SHOP_SECRET_KEY=$(openssl rand -hex 32)
mkdir -p waf/logs "$OUT" && chmod 777 waf/logs && rm -f waf/logs/*
{
  echo "$ docker compose -f docker-compose.waf.yml up -d --wait"
  docker compose -f docker-compose.waf.yml down -v >/dev/null 2>&1
  docker compose -f docker-compose.waf.yml up -d --wait 2>&1 | tail -2
  echo "$ docker compose exec waf nginx -t"
  docker compose -f docker-compose.waf.yml exec -T waf nginx -t 2>&1 | tail -1
  echo "$ python scripts/api_attack.py --base http://127.0.0.1:8080 --label $LABEL --gate"
  "$PY" scripts/api_attack.py --base http://127.0.0.1:8080 --out "$OUT/dumps" --label "$LABEL" --gate
  echo "exit code: $?"
  sleep 1
  echo "$ grep -o 'id \"10[0-9][0-9]\"' modsec_audit.log | sort | uniq -c"
  cp waf/logs/audit.log "$OUT/modsec_audit.log" 2>/dev/null
  grep -o 'id "10[0-9][0-9]"' "$OUT/modsec_audit.log" | sort | uniq -c
} 2>&1 | tee "$OUT/console.txt"
docker compose -f docker-compose.waf.yml down -v >/dev/null 2>&1
