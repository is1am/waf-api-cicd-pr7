#!/usr/bin/env bash
# Часть 1 методических указаний: Nginx + ModSecurity v3 (libmodsecurity) + OWASP CRS (Ubuntu 24.04).
# Запуск: sudo bash scripts/waf_setup.sh
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
MS=/etc/nginx/modsec

echo "== 1. Пакеты: Nginx, модуль ModSecurity-nginx, libmodsecurity3"
apt-get update -qq
apt-get install -y -qq nginx libnginx-mod-http-modsecurity git curl >/dev/null
dpkg -l | awk '/modsecurity|nginx-core|^ii  nginx /{print $2, $3}'

echo "== 2. Базовая конфигурация ModSecurity"
mkdir -p "$MS/custom"
# файл рекомендаций берётся из той же версии, что и установленная libmodsecurity
LIBVER=$(dpkg -l 2>/dev/null | awk '/^ii  libmodsecurity3/{print $3}' | head -1 | cut -d- -f1)
RAW=https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v$LIBVER
echo "libmodsecurity $LIBVER"
curl -fsSL "$RAW/modsecurity.conf-recommended" -o "$MS/modsecurity.conf"
curl -fsSL "$RAW/unicode.mapping" -o "$MS/unicode.mapping"
# режим блокировки и журнал аудита
sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' "$MS/modsecurity.conf"
sed -i 's#^SecAuditLog .*#SecAuditLog /var/log/modsec_audit.log#' "$MS/modsecurity.conf"
sed -i 's/^SecAuditLogParts .*/SecAuditLogParts ABIJDEFHZ/' "$MS/modsecurity.conf"
grep -E '^(SecRuleEngine|SecRequestBodyAccess|SecAuditEngine|SecAuditLog |SecAuditLogParts)' "$MS/modsecurity.conf"

echo "== 3. OWASP Core Rule Set (git, последний выпуск v4)"
if [ ! -d "$MS/crs/.git" ]; then
  TAG=$(git ls-remote --tags --refs https://github.com/coreruleset/coreruleset.git 'v4.*' \
        | awk -F/ '{print $3}' | grep -E '^v4\.[0-9]+\.[0-9]+$' | sort -V | tail -1)
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$TAG" https://github.com/coreruleset/coreruleset.git "$MS/crs"
fi
cp --update=none "$MS/crs/crs-setup.conf.example" "$MS/crs/crs-setup.conf"
echo "CRS: $(git -C "$MS/crs" describe --tags)"

echo "== 4. Конфигурация проекта"
cp "$REPO/waf/modsec/main.conf" "$MS/main.conf"
cp "$REPO/waf/rules/api-custom.conf" "$MS/custom/api-custom.conf"
cp "$REPO/waf/nginx/api.local.conf" /etc/nginx/sites-available/api.local
ln -sf /etc/nginx/sites-available/api.local /etc/nginx/sites-enabled/api.local
touch /var/log/modsec_audit.log
nginx -t
systemctl reload nginx 2>/dev/null || nginx -s reload
echo "WAF готов: http://api.local → 127.0.0.1:5000"
