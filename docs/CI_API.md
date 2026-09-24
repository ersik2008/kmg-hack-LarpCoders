# API для CI/CD: анализ архива → SARIF

Один POST-запрос из CI, один SARIF в ответ. Ни webhook, ни публичного
callback-URL, ни захода в интерфейс KMG не требуется — инициатива всегда на
стороне CI.

```
GitHub Actions                     KMG backend
──────────────                     ───────────
tar -czf code.tar.gz .
        │
        ├─ POST /api/ci/scan ─────► распаковка (с проверкой архива)
        │  Bearer <KMG_TOKEN>        Semgrep + Gitleaks + Trivy
        │  application/gzip          AI: разбор, цепочки атак, функции ИБ
        │                            политика → вердикт
        │◄──── SARIF 2.1.0 ─────────┘ + заголовки X-KMG-*
        │
        ├─ upload-sarif ──────────► вкладка Security репозитория
        └─ exit 1 при BLOCK ──────► сборка остановлена
```

---

## Эндпоинты

### `POST /api/ci/scan`

Принимает архив репозитория, возвращает **SARIF 2.1.0**.

| | |
|---|---|
| Авторизация | `Authorization: Bearer <KMG_TOKEN>` |
| Content-Type | `application/gzip` |
| Тело | сырой `.tar.gz` (`--data-binary @code.tar.gz`) |
| Ответ | `200` + SARIF JSON |

**Параметры запроса**

| Параметр | Обяз. | Назначение |
|---|---|---|
| `repository` | да | `owner/name` |
| `repositoryId` | нет | числовой id репозитория из github-контекста |
| `sha` | нет | commit SHA проверяемого кода |
| `ref` | нет | `refs/heads/main` |
| `pr` | нет | номер pull request |
| `ai` | нет | `off` — пропустить AI-анализ и отвечать быстрее |

**Заголовки ответа** — чтобы принять решение, не разбирая SARIF:

| Заголовок | Значение |
|---|---|
| `X-KMG-Verdict` | `PASS` / `REVIEW` / `BLOCK` / `INCOMPLETE` |
| `X-KMG-Critical`, `X-KMG-High`, `X-KMG-Medium`, `X-KMG-Low` | количество находок |
| `X-KMG-Total` | всего находок |
| `X-KMG-Risk-Score` | оценка риска 0–10 |
| `X-KMG-Files-Scanned` | сколько файлов проанализировано |
| `X-KMG-Ai-Analysis` | выполнился ли AI-разбор |
| `X-KMG-Scan-Id` | id скана в KMG |

`INCOMPLETE` — принципиальный случай: сканирование не завершилось, вердикт не
вынесен. Пустой список находок при этом **не означает**, что код безопасен,
поэтому workflow обязан считать это провалом.

### `POST /api/ci/scan/summary`

То же самое, но ответ — компактный JSON со сводкой и списком находок вместо
SARIF. Для систем, куда SARIF выгружать некуда (GitLab, Jenkins).

### `GET /api/ci/ping`

Проверка адреса и токена. Возвращает `{ ok: true, user: "...", service: "kmg-ci" }`.

---

## Пример вызова

```bash
tar -czf /tmp/code.tar.gz --exclude='./.git' --exclude='./node_modules' .

curl -sS -X POST "$KMG_API_URL/ci/scan?repository=owner/name&sha=$GITHUB_SHA&ref=$GITHUB_REF" \
  -H "Authorization: Bearer $KMG_TOKEN" \
  -H "Content-Type: application/gzip" \
  --data-binary @/tmp/code.tar.gz \
  -D headers.txt -o results.sarif

grep -i '^x-kmg-verdict' headers.txt
```

---

## Готовый workflow

Файл [`examples/ai-security.yml`](../examples/ai-security.yml) кладётся в чужой
репозиторий как `.github/workflows/ai-security.yml`. Он самодостаточен: нужен
только `curl` и `tar`, которые есть в `ubuntu-latest`.

Перед первым запуском в репозитории добавляются два секрета
(*Settings → Secrets and variables → Actions*):

| Секрет | Значение |
|---|---|
| `KMG_API_URL` | `https://<ваш-kmg>/api` |
| `KMG_TOKEN` | токен сессии KMG (Настройки → Security) |

Workflow срабатывает на `on: [push, pull_request]` и:

1. упаковывает репозиторий, исключая `node_modules`, `dist`, бинарные файлы;
2. отправляет архив на `/api/ci/scan`;
3. загружает SARIF в Code Scanning (`github/codeql-action/upload-sarif`);
4. пишет сводку в Job Summary и комментарий в PR;
5. роняет сборку при `BLOCK` или `INCOMPLETE` — **последним шагом**, уже после
   публикации отчёта, чтобы разработчик видел, что именно не так.

Обязательные права в workflow:

```yaml
permissions:
  contents: read
  security-events: write   # без этого SARIF не загрузится
  pull-requests: write     # для комментария в PR
```

---

## Безопасность эндпоинта

Архив приходит из чужого CI, то есть это недоверенные данные.

**Проверка до распаковки.** Заголовки tar разбираются
([`tar-inspector.ts`](../backend/src/ci/tar-inspector.ts)) и архив отклоняется,
если содержит запись с `..`, абсолютным путём или ссылку наружу.

Полагаться на сам `tar` здесь нельзя: busybox tar молча срезает ведущие `../`,
и вывод `tar -tzf` traversal уже не показывает — проверка листинга такой архив
пропустит. Поведение конкретной реализации tar — деталь базового образа, и
обновление образа может её изменить.

Дополнительно ограничены: размер архива (`CI_MAX_ARCHIVE_BYTES`, по умолчанию
80 МБ), суммарный размер после распаковки (2 ГБ) и число записей (200 000) —
защита от zip-бомбы.

Рабочий каталог удаляется после анализа в любом случае, включая ошибки.

---

## Переменные окружения

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `CI_ARCHIVE_LIMIT` | `80mb` | лимит тела запроса на уровне express |
| `CI_MAX_ARCHIVE_BYTES` | `83886080` | лимит размера архива в сервисе |
| `SECURITY_ENGINE_TIMEOUT_MS` | `600000` | таймаут на прогон сканеров |

---

## Что видно после прогона

| Где | Что |
|---|---|
| Вкладка **Security → Code scanning** | находки с аннотациями на строках, история между прогонами |
| **Job Summary** в Actions | таблица по severity, вердикт, оценка риска |
| Комментарий в PR | сводка и ссылка на разбор |
| Артефакт `kmg-security-report` | `results.sarif` целиком |
| Дашборд KMG | полный разбор AI, цепочки атак, матрица функций ИБ |
