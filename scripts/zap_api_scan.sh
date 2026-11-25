#!/usr/bin/env bash
# DAST по спецификации OpenAPI: OWASP ZAP API scan (как задание dast-zap-api в CI).
# Использование: bash scripts/zap_api_scan.sh <тег> <каталог результатов>
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
TAG=${1:-v2-fixed}; OUT=${2:-$REPO/evidence/zap_api/$TAG}
PY=${PY:-/opt/pr7venv/bin/python}
D=/tmp/pr7zap-$TAG; rm -rf "$D"; mkdir -p "$D" "$OUT"
git -C "$REPO" archive "$TAG" | tar -x -C "$D"
pkill -f "python -m src[.]shop[.]app"; sleep 1
(cd "$D" && SHOP_SECRET_KEY=$(openssl rand -hex 32) SHOP_DB=/tmp/pr7zap.db nohup "$PY" -m src.shop.app >/tmp/pr7zap_api.log 2>&1 &)
timeout 30 sh -c 'until curl -sf http://127.0.0.1:5000/api/v1/products >/dev/null; do sleep 1; done'
chmod a+w "$D"
docker run --rm --network host -v "$D:/zap/wrk:rw" zaproxy/zap-stable \
  zap-api-scan.py -t /zap/wrk/openapi.yaml -f openapi -O http://127.0.0.1:5000 \
  -c zap-api-rules.tsv -r zap-api.html -J zap-api.json -I \
  -z "-config scanner.maxRuleDurationInMins=2 -config scanner.maxScanDurationInMins=10" > "$OUT/console.txt" 2>&1
echo "exit code: $?" >> "$OUT/console.txt"
cp "$D"/zap-api.* "$OUT/" 2>/dev/null
pkill -f "python -m src[.]shop[.]app"
tail -25 "$OUT/console.txt"
