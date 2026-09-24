# Интеграция с CI/CD

Документ описывает фактическую интеграцию с GitHub Actions: триггеры, права,
секреты, таймауты, артефакты и обработку кодов завершения.

Навигация: [README](README.md) · [DECISION_ENGINE](DECISION_ENGINE.md) ·
[REPORT_FORMAT](REPORT_FORMAT.md) · [CICD_INTEGRATION](CICD_INTEGRATION.md) ·
[CI_API](CI_API.md)

---

## Три независимых пути интеграции

| Путь | Файл | Объём анализа | Enforcement |
|---|---|---|---|
| A. Workflow «под ключ» | [examples/ai-security.yml](../examples/ai-security.yml) | весь репозиторий | блокирует |
| B. Composite action | [action.yml](../action.yml) | по умолчанию только изменённые файлы | блокирует |
| C. GitHub webhook | [cicd.service.ts](../backend/src/cicd/cicd.service.ts) | весь репозиторий | публикует commit status |

Отдельно — самопроверка репозитория агента:
[.github/workflows/security-scan.yml](../.github/workflows/security-scan.yml).

---

## Путь A — workflow «под ключ»

Этот путь соответствует требованиям п. 4.4 ТЗ по полноте анализа.

```
Push / Pull Request
      ↓
Checkout                            actions/checkout@v4
      ↓
Упаковка репозитория                tar -czf /tmp/code.tar.gz --exclude=… .
      ↓
POST /api/ci/scan                   Bearer KMG_TOKEN, Content-Type: application/gzip
      ↓                             --max-time 900
Ответ: SARIF 2.1.0 + заголовки X-KMG-*
      ↓
Загрузка SARIF в Code Scanning      github/codeql-action/upload-sarif@v3   (if: always())
      ↓
Сохранение артефакта                actions/upload-artifact@v4             (if: always())
      ↓
Комментарий в pull request          actions/github-script@v7               (if: always())
      ↓
Проверка вердикта                   exit 0 | exit 1                        (if: always())
```

Порядок шагов выбран намеренно: проверка вердикта стоит **последней**, поэтому
SARIF, артефакт и комментарий публикуются до падения сборки. Требование п. 4.3.4
ТЗ — отчёт доступен вне зависимости от результата пайплайна — выполняется за счёт
`if: always()` на всех трёх публикующих шагах.

### Триггер

```yaml
on: [push, pull_request]
```

### Права

```yaml
permissions:
  contents: read
  security-events: write   # обязательно для выгрузки SARIF
  pull-requests: write     # для комментария в PR
```

### Секреты

| Секрет | Назначение |
|---|---|
| `KMG_API_URL` | адрес backend, например `https://kmg.example.com/api` |
| `KMG_TOKEN` | сессионный токен KMG (JWT) |

Отсутствие любого из них — немедленный `exit 1` с сообщением
`::error::Не заданы секреты KMG_API_URL и KMG_TOKEN`. Fail-open по умолчанию нет.

### Таймауты

| Уровень | Значение |
|---|---|
| Job | `timeout-minutes: 20` |
| HTTP-запрос `curl` | `--max-time 900` (15 минут) |
| Движок сканирования (сервер) | `SECURITY_ENGINE_TIMEOUT_MS`, по умолчанию 600 000 мс |

### Исключения при упаковке

`.git`, `node_modules` (в том числе вложенные), `dist`, `build`, `.next`,
`vendor`, `__pycache__`, `.venv`, `venv`, `target`, а также `*.zip`, `*.jar`,
`*.png`, `*.jpg`, `*.gif`, `*.pdf`, `*.mp4`, `*.woff*`.

Ограничение размера на сервере — `CI_MAX_ARCHIVE_BYTES`, по умолчанию 80 МБ;
превышение даёт HTTP 413.

### Вердикт из заголовков

Разбирать SARIF в workflow не требуется:

| Заголовок | Содержимое |
|---|---|
| `X-KMG-Verdict` | `PASS` / `REVIEW` / `BLOCK` / `INCOMPLETE` |
| `X-KMG-Critical`, `X-KMG-High`, `X-KMG-Medium`, `X-KMG-Low`, `X-KMG-Total` | счётчики |
| `X-KMG-Risk-Score` | оценка риска 0–10 |
| `X-KMG-Files-Scanned` | число проанализированных файлов |
| `X-KMG-Ai-Analysis` | `true` / `false` — выполнялся ли AI-анализ |
| `X-KMG-Scan-Id` | идентификатор скана в KMG |

---

## Путь B — composite action

```
Push / Pull Request
      ↓
Prepare git history                 git fetch --deepen=50   (только при paths: changed)
      ↓
KMG security scan                   node kmg-guard.mjs ci
      │                                 ├── отбор файлов через git
      │                                 ├── POST /api/prepush/check
      │                                 ├── kmg-scan-report.json
      │                                 ├── kmg-results.sarif
      │                                 ├── GITHUB_STEP_SUMMARY (Markdown)
      │                                 └── GITHUB_OUTPUT (verdict, critical, …)
      ↓  код завершения 0 или 1
Upload SARIF                        github/codeql-action/upload-sarif@v3   (if: always())
```

### Входы

| Вход | По умолчанию | Назначение |
|---|---|---|
| `api-url` | — (обязателен) | адрес KMG API |
| `token` | — (обязателен) | сессионный токен |
| `block-on` | `policy` | `CRITICAL` / `HIGH` / `ANY` / `policy` |
| `fail-open` | `false` | `true` разрешает сборку **только** при недоступном API |
| `paths` | `changed` | `changed` или `all` |
| `max-files` | `400` | предел числа файлов |
| `upload-sarif` | `true` | выгружать ли в Code Scanning |

**Замечание по соответствию ТЗ.** Значение по умолчанию `paths: changed`
противоречит п. 4.4.1, требующему анализа проекта целиком. Для соответствия
требованию шаг должен вызываться с `paths: all`:

```yaml
- uses: ./
  with:
    api-url: ${{ secrets.KMG_API_URL }}
    token: ${{ secrets.KMG_TOKEN }}
    paths: all          # требуется п. 4.4.1 ТЗ
```

### Выходы

`verdict`, `critical`, `report` (путь к JSON), `sarif` (путь к SARIF).

---

## Путь C — GitHub webhook

`POST /api/cicd/webhook` с подписью `GITHUB_WEBHOOK_SECRET`.

* `push` в ветку из `CICD_BRANCHES` (по умолчанию `main,master,develop`) →
  `ScanService.startScan` с `trigger: 'push'`.
* `pull_request` (`opened`, `synchronize`, `reopened`) → скан головного коммита
  PR с `trigger: 'pull_request'`.

Вердикт публикуется обратно в GitHub как commit status
([github-status.service.ts](../backend/src/github/github-status.service.ts)):

| Вердикт | `state` commit status |
|---|---|
| `PASS`, `REVIEW` | `success` |
| `BLOCK` | `failure` |
| Незавершённая проверка, сбой конвейера | `error` |

Блокировка слияния обеспечивается настройкой branch protection на стороне
GitHub: проверка KMG должна быть отмечена как обязательная.

Ограничения этого пути: репозиторий должен быть подключён к KMG через OAuth,
должен существовать пользователь со связанным GitHub-аккаунтом, а сам backend
должен быть доступен из интернета. Для локальной разработки путь неприменим.

---

## Самопроверка репозитория агента

[.github/workflows/security-scan.yml](../.github/workflows/security-scan.yml)

Триггер: `push` в `main`/`develop`, `pull_request` в `main`.
`timeout-minutes: 30` — соответствует п. 4.7.1 ТЗ.

Сервис `postgres:16-alpine` с проверкой готовности. Переменные окружения job-а:
`DATABASE_URL`, `NODE_ENV=test`, `JWT_SECRET` (тестовое значение),
`GROQ_API_KEY` и `ENCRYPTION_KEY` из секретов, `GROQ_MODEL`.

Последовательность шагов:

1. Checkout.
2. Node.js 20 с кешем npm.
3. `npm ci` → `prisma generate` → `prisma migrate deploy` → `npm run build` →
   `npm run test`.
4. Python 3.11, установка зависимостей `security-engine`.
5. Установка сканеров: Semgrep через `pipx`, Gitleaks 8.18.1, Trivy.
6. Запуск движка `uvicorn app.main:app --port 8000`.
7. `POST /scan` по собственному рабочему каталогу → `scan_results.json`.
8. **Гейт 1:** `Enforce KMG AI security policy` — шаг через `action.yml`.
9. **Гейт 2:** `Check local engine results` — проверка `scan_results.json`.
10. Сборка фронтенда.
11. Выгрузка артефакта `security-scan-results` (`if: always()`).
12. Комментарий в PR.

### Почему Semgrep ставится через pipx

Комментарий в workflow и в [security-engine/Dockerfile](../security-engine/Dockerfile)
фиксирует реальную причину: общий интерпретатор с `requirements.txt`, где
закреплён `pydantic==2.5.2`, ломал импорты Semgrep — инструмент падал на каждом
запуске с `No module named 'pydantic._internal._signature'`, то есть SAST молча
не выполнялся вообще. `pipx` разводит деревья зависимостей.

### Логика гейта 2

```bash
FAILED_SCANNERS=$(... сканеры со статусом != COMPLETED ...)
if [ -n "$FAILED_SCANNERS" ]; then
  echo "::error::Scan incomplete - these scanners did not complete: $FAILED_SCANNERS"
  exit 1
fi

CRITICAL_COUNT=$(... число находок severity == CRITICAL ...)
if [ "$CRITICAL_COUNT" -gt "0" ]; then
  echo "::error::Found $CRITICAL_COUNT CRITICAL security findings. Blocking merge."
  exit 1
fi
```

Незавершённый сканер приводит к падению сборки раньше, чем проверяется число
находок: «мы не смогли проверить» не должно выглядеть как «проверять нечего».

---

## Коды завершения

### Реализованное состояние

**В коде реализованы только коды `0` и `1`.** Отдельного кода `2` нет ни в
[kmg-guard.mjs](../tools/git-hooks/kmg-guard.mjs), ни в
[examples/ai-security.yml](../examples/ai-security.yml), ни в
[.github/workflows/security-scan.yml](../.github/workflows/security-scan.yml).

Соответствие фактической логики требованиям п. 4.3.3 ТЗ:

| Ситуация | ТЗ требует | Реализовано | Соответствие |
|---|---|---|---|
| Нарушений нет | `0` | `0` | да |
| Есть нарушения | `1` | `1` | да |
| Внутренняя ошибка агента | `2` | `1` | **нет** |
| Модель недоступна | `2` | `0` (AI-анализ пропускается, скан продолжается) | **нет** |
| Превышение лимитов | `2` | `1` (если проверка не выполнена) либо `0` (если AI-этап пропущен) | **нет** |
| Ошибка разбора проекта | `2` | `1` | **нет** |

### Код завершения 0

Возвращается, когда обязательных оснований для блокировки нет.

Конкретно ([kmg-guard.mjs](../tools/git-hooks/kmg-guard.mjs), `shouldFailProcess`):
`result.incomplete === false`, ни один сканер не в состоянии, отличном от
`COMPLETED`/`SKIPPED`, и `shouldBlock()` вернула `false`.

Пайплайн продолжает выполнение. Замечания информационного характера (`REVIEW`,
находки уровня `MEDIUM`/`LOW`) сборку не прерывают — это соответствует п. 4.3.6
ТЗ. В журнал при этом печатается предупреждение:
`⚠ Проверка пройдена с замечаниями — рекомендуется исправить.`

В workflow «под ключ» коду `0` соответствуют вердикты `PASS` и `REVIEW`.

### Код завершения 1

Возвращается в четырёх случаях:

1. **Вердикт `BLOCK`** — `result.blocked === true` либо `result.verdict === 'BLOCK'`.
2. **Порог `KMG_BLOCK_ON` превышен** — явная настройка, делающая CI строже
   серверной политики (например, `block-on: HIGH`).
3. **Проверка не завершена** — `result.incomplete === true` либо любой сканер в
   состоянии, отличном от `COMPLETED`/`SKIPPED`.
4. **Проверку не удалось выполнить** — недоступный API, отсутствующий токен,
   таймаут, внутренняя ошибка guard-а — при условии `KMG_FAIL_OPEN != 1`.

Слияние и развёртывание блокируются. В журнал выводится:

```
✖ Build blocked.
Security policy: BLOCK | INCOMPLETE.
Merge cannot proceed until security checks pass.
```

Пункты 3 и 4 объединяют в одном коде две разные по смыслу ситуации — это и есть
причина отсутствия кода `2`.

### Код завершения 2

**NOT IMPLEMENTED.**

Согласно п. 4.3.3 ТЗ код `2` должен возвращаться, когда проверка не выполнена по
причине внутренней ошибки агента: недоступность модели, превышение лимитов,
ошибка разбора проекта.

Текущее поведение:

* недоступный backend, отсутствующий токен, таймаут → `1`;
* незавершившийся сканер → `1`;
* недоступная модель → AI-этап пропускается, скан завершается штатно, код `0`
  или `1` по результатам сканеров;
* внутренняя ошибка guard-а (перехват в `catch` на верхнем уровне) → `1` при
  `KMG_FAIL_OPEN != 1`, иначе `0`.

**Что требуется реализовать.** Разделить в `shouldFailProcess` два исхода:
«проверка выполнена и выявила нарушения» (код `1`) и «проверка не выполнена»
(код `2`). Соответственно доработать шаг `Проверить вердикт` в workflow, чтобы
он различал три кода. Текущее объединение не является fail-open: сборка в обоих
случаях падает, но оператор CI не может отличить нарушение безопасности от сбоя
инфраструктуры.

### Fail-open

`KMG_FAIL_OPEN=1` (`fail-open: true`) разрешает сборку **только** когда проверку
не удалось выполнить. Вердикт `BLOCK` и незавершённое сканирование этим флагом
не отменяются — гарантируется функцией `shouldFailOnScanError`, применяемой
исключительно в ветках обработки ошибок запроса.

Поведение закреплено тестом
`KMG_FAIL_OPEN only allows an unavailable CI scan, not a BLOCK verdict`
([kmg-guard.test.mjs](../tools/git-hooks/kmg-guard.test.mjs)).

По умолчанию `fail-open` выключен: CI работает по принципу fail-closed.

---

## Содержание журнала выполнения

П. 4.3.5 ТЗ требует, чтобы причина прерывания была понятна из журнала шага без
открытия артефакта — с указанием количества нарушений и перечня нарушенных
требований ИБ.

Что печатается фактически ([kmg-guard.mjs](../tools/git-hooks/kmg-guard.mjs)):

```
  KMG AI Security Agent — проверка в CI (enforcing)
  ────────────────────────────────────────────────────────────
  Проверяется 128 файл(ов) из ветки main...

  [CRITICAL] SQL Injection via string interpolation in raw query
    src/user.service.ts:42  (semgrep · kmg-sql-injection-string-interpolation)
    Untrusted user input concatenated to db.query
    │ await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);

  Сканеры: semgrep=COMPLETED gitleaks=COMPLETED trivy=COMPLETED
  Итог: CRITICAL 1  HIGH 0  MEDIUM 3  LOW 5  INFO 0
  Вердикт политики: BLOCK   Риск: 10/10
  · Critical vulnerabilities detected (1) or risk score threshold exceeded (10.0/7.0).

  ✖ Build blocked.
  Security policy: BLOCK.
  Merge cannot proceed until security checks pass.
```

| Требование п. 4.3.5 | Состояние |
|---|---|
| Количество выявленных нарушений | PASS — счётчики по severity и общий итог |
| Перечень нарушенных требований ИБ | **NOT IMPLEMENTED** — печатаются правила сканеров, а не идентификаторы ИБ-01…ИБ-08 |
| Причина прерывания | PASS — вердикт и обоснования политики |

Дополнительно формируется job summary в Markdown — см.
[REPORT_FORMAT.md](REPORT_FORMAT.md#4-markdown-job-summary).

---

## Локальный режим разработчика

Реализован и **намеренно отделён** от авторитетного гейта CI.

| Свойство | Локальные хуки | CI |
|---|---|---|
| Проверка выполняется | да | да |
| Вердикт вычисляется | да | да |
| Находки показываются | да | да |
| Код завершения при `BLOCK` | **0** | **1** |
| Код завершения при недоступном backend | **0** | **1** |
| Код завершения при незавершённом сканировании | **0** | **1** |

Реализация — функция `enforcementMode`:

```js
export function enforcementMode(mode) {
  return mode === 'ci' ? 'enforce' : 'advisory';
}
```

Защита продублирована на уровне shell-хуков:
[pre-push](../tools/git-hooks/pre-push) и [pre-commit](../tools/git-hooks/pre-commit)
завершаются `exit 0` даже при неожиданном падении Node или самого guard-а.

Установка: `./tools/git-hooks/install.sh /path/to/repo`, затем
`git -C /path/to/repo config --local kmg.token <TOKEN>`. Токен хранится в
локальной конфигурации git, а не в переменных окружения и не в репозитории.

**Важно для экспертной комиссии.** Локальные хуки не являются средством
контроля соответствия. Они дают разработчику обратную связь до отправки кода;
обязательным контрольным шагом является CI. Разграничение сознательное, оно
задокументировано в [tools/git-hooks/README.md](../tools/git-hooks/README.md) и
покрыто тестами 1–6 в
[kmg-guard.test.mjs](../tools/git-hooks/kmg-guard.test.mjs), включая
интеграционный тест на настоящих git-хуках.

---

## Сводка соответствия п. 4.3 ТЗ

| Пункт | Требование | Состояние | Подтверждение |
|---|---|---|---|
| 4.3.1 | Автоматический запуск по push отдельным шагом | PASS | `on: [push, pull_request]`, отдельный job/step |
| 4.3.2 | Шаг размещён до слияния и развёртывания | PASS | шаг падает до любых шагов развёртывания; блокировка слияния — через branch protection |
| 4.3.3 | Коды завершения 0 / 1 / 2 | PARTIAL | реализованы 0 и 1; код 2 отсутствует |
| 4.3.4 | Отчёт сохраняется как артефакт и доступен при любом результате | PASS | `upload-artifact` и `upload-sarif` с `if: always()` |
| 4.3.5 | Причина прерывания понятна из журнала | PARTIAL | количество нарушений печатается; перечень требований ИБ — нет |
| 4.3.6 | Информационные замечания не прерывают пайплайн | PASS | `REVIEW` → `exit 0` |
