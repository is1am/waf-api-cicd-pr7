# ПР7 — Настройка WAF. Тестирование API на уязвимости

Практическая работа №7 по дисциплине «Клиент-серверные технологии и их безопасность».
Тема мини-проекта — CI/CD Security Pipeline: SAST и SCA в GitHub Actions / GitLab CI;
в этой работе к конвейеру добавлены WAF-as-code (ModSecurity + OWASP CRS), правила SAST
для уязвимостей API, security-тесты и DAST по спецификации OpenAPI.

| Тег | Состояние | Конвейер |
| --- | --- | --- |
| `v1-vulnerable` | API с BOLA (API1:2023) и Mass Assignment (API3:2023) | падает (Semgrep, Bandit, тесты) |
| `v1.1-waf` | + правила WAF и задание `waf-regression` | падает: WAF отражает 20/21 атак, перебор заказов проходит |
| `v2-fixed` | проверка владельца объекта, схемы запросов | проходит |

## Запуск (Ubuntu / WSL, root)

```bash
bash scripts/waf_setup.sh                 # Nginx + ModSecurity v3 + OWASP CRS v4, сайт api.local
bash scripts/waf_lab.sh                   # атаки на 6 конфигурациях → evidence/waf_lab/
bash scripts/ci_waf_local.sh waf-local    # задание waf-regression из CI (docker compose)
bash scripts/scan_versions.sh             # Gitleaks, Semgrep, Bandit, pip-audit, Trivy, pytest на v1 и v2
bash scripts/zap_api_scan.sh v2-fixed     # OWASP ZAP API scan по openapi.yaml
```

Учётные записи стенда (вымышленные): `aliya / Aliya#2026` (ID 101), `timur / Timur#2026` (ID 102),
`admin / Adm1n!Secure2026` (ID 100).
