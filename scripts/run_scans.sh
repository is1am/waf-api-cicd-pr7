#!/usr/bin/env bash
# Локальный прогон тех же проверок, что и в конвейере CI (для отчёта и отладки).
# Использование: scripts/run_scans.sh <каталог-для-результатов>
# Требуется: docker; bandit, pip-audit, pytest (переменные TOOLS_BIN и APP_PY указывают, где их взять).
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$REPO/evidence/scan}
TOOLS_BIN=${TOOLS_BIN:-/opt/pr7venv/bin}
APP_PY=${APP_PY:-python3}
mkdir -p "$OUT"
cd "$REPO"
declare -A RC

step() { echo; echo "=================== $1 ==================="; }

step "Gitleaks (секреты в истории git)"
docker run --rm -v "$REPO:/repo" zricethezav/gitleaks:latest git /repo --redact -v \
  --report-format json --report-path /repo/.gl.json --exit-code 1 >"$OUT/gitleaks.txt" 2>&1
RC[gitleaks]=$?; mv -f .gl.json "$OUT/gitleaks.json" 2>/dev/null; tail -5 "$OUT/gitleaks.txt"

step "SAST: Semgrep"
docker run --rm -v "$REPO:/src" -w /src semgrep/semgrep:latest semgrep scan \
  --config .semgrep/rules.yml --config p/python --config p/flask --config p/owasp-top-ten --config p/secrets \
  --metrics off --json-output /src/.sg.json --sarif --output /src/.sg.sarif \
  --severity ERROR --error src >"$OUT/semgrep.txt" 2>&1
RC[semgrep]=$?
# отдельный прогон всех уровней (ERROR+WARNING+INFO) — для статистики в отчёте
docker run --rm -v "$REPO:/src" -w /src semgrep/semgrep:latest semgrep scan \
  --config .semgrep/rules.yml --config p/python --config p/flask --config p/owasp-top-ten --config p/secrets \
  --metrics off --json --quiet src >"$OUT/semgrep_all.json" 2>/dev/null
mv -f .sg.json "$OUT/semgrep.json"; mv -f .sg.sarif "$OUT/semgrep.sarif"
tail -15 "$OUT/semgrep.txt"

step "SAST: Bandit"
"$TOOLS_BIN/bandit" -r src -f json -o "$OUT/bandit.json" --exit-zero -q
"$TOOLS_BIN/bandit" -r src --severity-level medium --confidence-level medium >"$OUT/bandit.txt" 2>&1
RC[bandit]=$?; grep -A12 "Run metrics" "$OUT/bandit.txt" | head -14

step "SCA: pip-audit"
"$TOOLS_BIN/pip-audit" -r requirements.txt --no-deps --disable-pip -f json -o "$OUT/pip-audit.json" >/dev/null 2>&1
"$TOOLS_BIN/pip-audit" -r requirements.txt --no-deps --disable-pip -f cyclonedx-json -o "$OUT/sbom.cdx.json" >/dev/null 2>&1
"$TOOLS_BIN/pip-audit" -r requirements.txt --no-deps --disable-pip >"$OUT/pip-audit.txt" 2>&1
RC[pip_audit]=$?; cat "$OUT/pip-audit.txt"

step "SCA: Trivy"
docker run --rm -v "$REPO:/repo" -v trivy-cache:/root/.cache aquasec/trivy:latest fs --quiet \
  --scanners vuln -f json -o /repo/.tv.json /repo >/dev/null 2>&1; mv -f .tv.json "$OUT/trivy.json"
docker run --rm -v "$REPO:/repo" -v trivy-cache:/root/.cache aquasec/trivy:latest fs --quiet \
  --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 /repo >"$OUT/trivy.txt" 2>&1
RC[trivy]=$?; head -30 "$OUT/trivy.txt"

step "Security regression tests (pytest)"
SHOP_DB=/tmp/pr7_test.db "$APP_PY" -m pytest -v -p no:cacheprovider tests >"$OUT/pytest.txt" 2>&1
RC[pytest]=$?; tail -25 "$OUT/pytest.txt"

step "ИТОГ (0 — проверка пройдена, иначе сборка остановлена)"
{
  for k in gitleaks semgrep bandit pip_audit trivy pytest; do
    if [ "${RC[$k]}" = 0 ]; then s=PASS; else s=FAIL; fi
    printf "%-10s exit=%-3s %s\n" "$k" "${RC[$k]}" "$s"
  done
} | tee "$OUT/summary.txt"
