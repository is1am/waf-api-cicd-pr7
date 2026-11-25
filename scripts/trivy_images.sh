#!/usr/bin/env bash
# SCA контейнерных образов стенда (WAF и среда выполнения API): Trivy image.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd); OUT=$REPO/evidence/trivy_images; mkdir -p "$OUT"
for img in owasp/modsecurity-crs:nginx python:3.12-slim; do
  f=$(echo "$img" | tr '/:' '__')
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache aquasec/trivy:latest \
    image --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed -f table "$img" > "$OUT/$f.txt" 2>&1
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache aquasec/trivy:latest \
    image --quiet --scanners vuln -f json "$img" > "$OUT/$f.json" 2>/dev/null
  echo "== $img"; grep -E "^Total|Total:" "$OUT/$f.txt" | head -5
done
