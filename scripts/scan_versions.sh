#!/usr/bin/env bash
# Прогон всех проверок конвейера (scripts/run_scans.sh) на версиях v1-vulnerable и v2-fixed.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
for tag in ${*:-v1-vulnerable v2-fixed}; do
  d=/tmp/pr7scan-$tag; rm -rf "$d"; git clone -q "$REPO" "$d"; git -C "$d" checkout -q "$tag"
  mkdir -p "$d/scripts"; cp "$REPO/scripts/run_scans.sh" "$d/scripts/"
  APP_PY=/opt/pr7venv/bin/python bash "$d/scripts/run_scans.sh" "$REPO/evidence/scans/$tag" > "$REPO/evidence/scans/$tag.console.txt" 2>&1
  echo "== $tag"; cat "$REPO/evidence/scans/$tag/summary.txt"
done
