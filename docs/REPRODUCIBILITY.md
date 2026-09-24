# Воспроизведение запуска

Инструкция для экспертной комиссии. Все команды и версии взяты из
конфигурационных файлов репозитория.

Навигация: [README](README.md) · [TESTING](TESTING.md) ·
[CI_CD](CI_CD.md) · [PERFORMANCE](PERFORMANCE.md)

---

## Требования к среде

### Вариант 1 — Docker (рекомендуемый)

| Компонент | Версия | Откуда |
|---|---|---|
| Docker Engine | 20.10+ | требуется поддержка Compose V2 |
| Docker Compose | V2 (`docker compose`) | [docker-compose.yml](../docker-compose.yml) без ключа `version` |
| Свободная память | 4 ГБ и более | образ security-engine содержит Semgrep, Trivy и базу уязвимостей |
| Свободное место | 6 ГБ и более | образ security-engine ≈ 2–3 ГБ |

Внутри контейнеров: Node.js 22-alpine (backend), Node.js 20-alpine + nginx:alpine
(frontend), Python 3.11-slim (security-engine), PostgreSQL 16-alpine.

### Вариант 2 — локальный запуск без Docker

| Компонент | Версия | Обоснование |
|---|---|---|
| Node.js | 20 или 22 | CI использует 20 ([security-scan.yml](../.github/workflows/security-scan.yml)), образ backend — 22 |
| npm | 10+ | поставляется с Node.js |
| Python | 3.11 | зафиксировано в workflow и в Dockerfile движка |
| PostgreSQL | 16 | зафиксировано в docker-compose и в сервисе CI |
| Git | 2.30+ | требуется для клонирования и для работы guard-а |
| Semgrep | последняя, через `pipx` | **обязательно pipx**, см. предупреждение ниже |
| Gitleaks | 8.18.1 | версия зафиксирована в workflow и в Dockerfile |
| Trivy | последняя | ставится скриптом установки |

> **Предупреждение по Semgrep.** Устанавливать `pip install semgrep` в тот же
> интерпретатор, где лежат зависимости `security-engine`, нельзя. В
> `requirements.txt` закреплён `pydantic==2.5.2`, который ломает импорты
> Semgrep: инструмент падает с `No module named
> 'pydantic._internal._signature'`, то есть статический анализ молча не
> выполняется вообще, а сканер отчитывается как `FAILED`. Используйте `pipx` —
> так сделано и в [Dockerfile](../security-engine/Dockerfile), и в workflow.

---

## Клонирование

```sh
git clone https://github.com/<owner>/<repository>.git kmg
cd kmg
```

---

## Переменные окружения

```sh
cp .env.example .env
```

Далее отредактируйте `.env`. Ниже — только те переменные, без которых система не
работает. Полный перечень с комментариями — в
[.env.example](../.env.example).

### Обязательные

```sh
# База данных
DATABASE_URL=postgresql://postgres:<PASSWORD>@localhost:5432/kmg

# Подпись сессионных токенов
JWT_SECRET=<JWT_SECRET>

# Ровно 32 символа — иначе backend падает при старте с
# "ENCRYPTION_KEY must be exactly 32 characters long"
ENCRYPTION_KEY=<32_CHAR_ENCRYPTION_KEY>

# Языковая модель (провайдер — Groq)
GROQ_API_KEYS=<GROQ_API_KEY_1>,<GROQ_API_KEY_2>
GROQ_MODEL=openai/gpt-oss-120b
```

`GROQ_API_KEYS` принимает список через запятую, точку с запятой или перенос
строки, либо JSON-массив. Для одного ключа можно использовать `GROQ_API_KEY`.
Модель должна быть доступна учётной записи и поддерживать вызов инструментов —
перечень можно получить запросом `GET https://api.groq.com/openai/v1/models`.

### Требуются для сценариев с GitHub

```sh
GITHUB_CLIENT_ID=<GITHUB_CLIENT_ID>
GITHUB_CLIENT_SECRET=<GITHUB_CLIENT_SECRET>
GITHUB_CALLBACK_URL=http://localhost:3000/api/auth/github/callback
GITHUB_WEBHOOK_SECRET=<WEBHOOK_SECRET>
CICD_BRANCHES=main,master,develop
```

Без них не работают: вход в интерфейс, клонирование приватных репозиториев,
публикация commit status, выгрузка в Code Scanning. Путь
`POST /api/ci/scan` работает без OAuth — достаточно JWT.

### Настраиваемые (значения по умолчанию рабочие)

```sh
SECURITY_ENGINE_URL=http://localhost:8000
SECURITY_ENGINE_TIMEOUT_MS=600000
PREPUSH_ENGINE_TIMEOUT_MS=300000
SEMGREP_TIMEOUT_SECONDS=300
GITLEAKS_TIMEOUT_SECONDS=180
TRIVY_TIMEOUT_SECONDS=300
AI_TRIAGE_BATCH_SIZE=3
AI_TRIAGE_MAX_FINDINGS=0      # 0 — разбирать все находки
AI_RECON_ENABLED=false
API_BODY_LIMIT=25mb
CI_ARCHIVE_LIMIT=80mb
CI_MAX_ARCHIVE_BYTES=83886080
```

> Реальные значения ключей в `.env` не коммитить. Файл `.env` находится в
> [.gitignore](../.gitignore); в репозитории присутствует только `.env.example`.

> **Расхождение в значениях по умолчанию.** [.env.example](../.env.example)
> задаёт `AI_TRIAGE_MAX_FINDINGS=24` и `AI_TRIAGE_BATCH_SIZE=4`, тогда как
> [docker-compose.yml](../docker-compose.yml) и сам код
> ([investigation.service.ts](../backend/src/agent/investigation.service.ts))
> используют `0` и `3`. Значение `24` ограничивает число находок, получающих
> индивидуальный вердикт модели, — при копировании `.env.example` как есть часть
> находок останется без AI-разбора. Для полного разбора задайте
> `AI_TRIAGE_MAX_FINDINGS=0`. На вердикт политики это не влияет: находки
> сканеров учитываются все.

---

## Запуск в Docker

```sh
docker compose up --build
```

Поднимаются четыре сервиса:

| Сервис | Адрес | Проверка готовности |
|---|---|---|
| `kmg-postgres` | `localhost:5432` | `pg_isready`, интервал 5 с |
| `kmg-backend` | `http://localhost:3000` | миграции применяются при старте |
| `kmg-security-engine` | `http://localhost:8000` | `GET /health`, интервал 15 с |
| `kmg-frontend` | `http://localhost:5173` | — |

Первая сборка занимает заметное время: образ движка клонирует официальные
правила Semgrep и предзагружает базу уязвимостей Trivy.

Проверка готовности движка:

```sh
curl http://localhost:8000/health
```

Ожидаемый ответ:

```json
{
  "status": "ok",
  "service": "security-engine",
  "tools": { "semgrep": true, "gitleaks": true, "trivy": true }
}
```

Если любой из трёх инструментов показывает `false`, запуск некорректен: такой
сканер будет отчитываться как `FAILED`, и вердикт `PASS` станет недостижим.

> **Замечание по безопасности.** В [docker-compose.yml](../docker-compose.yml)
> заданы значения по умолчанию для пароля базы данных, `JWT_SECRET` и
> `ENCRYPTION_KEY`. Они предназначены исключительно для локального запуска.
> Перед любым развёртыванием вне рабочей станции все три значения должны быть
> переопределены через `.env`. См. [SECURITY.md](SECURITY.md).

---

## Локальный запуск без Docker

```sh
# 1. База данных
docker run -d --name kmg-pg -p 5432:5432 \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=<PASSWORD> -e POSTGRES_DB=kmg \
  postgres:16-alpine

# 2. Backend
cd backend
npm ci
npx prisma generate
npx prisma migrate deploy
npm run build
npm run start:prod          # либо npm run start:dev для режима разработки

# 3. Security engine (отдельный терминал)
cd security-engine
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 4. Сканеры (один раз)
pip install pipx && pipx install semgrep && semgrep --version
# Gitleaks 8.18.1 и Trivy — см. команды в .github/workflows/security-scan.yml

# 5. Frontend (отдельный терминал)
cd frontend
npm ci
npm run dev
```

Миграции: четыре штуки в [backend/prisma/migrations](../backend/prisma/migrations)
(`init`, `security_controls`, `repository_activity`, `user_repositories`).

---

## Запуск проверки безопасности

### Способ 1 — анализ архива репозитория (соответствует п. 4.4 ТЗ)

Полный анализ проекта, тот же путь, что используется в CI.

```sh
# Токен: интерфейс KMG → Настройки → Security → «Показать токен»
export KMG_TOKEN=<KMG_SESSION_TOKEN>

# Упаковка проверяемого проекта
cd /path/to/project-under-test
tar -czf /tmp/code.tar.gz \
  --exclude='./.git' --exclude='./node_modules' --exclude='./**/node_modules' \
  --exclude='./dist' --exclude='./build' --exclude='./.venv' \
  .

# Отправка на анализ
curl -sS -X POST "http://localhost:3000/api/ci/scan?repository=owner/name&sha=$(git rev-parse HEAD)&ref=$(git symbolic-ref HEAD)" \
  -H "Authorization: Bearer $KMG_TOKEN" \
  -H "Content-Type: application/gzip" \
  --data-binary @/tmp/code.tar.gz \
  --max-time 900 \
  -D /tmp/headers.txt \
  -o /tmp/results.sarif

# Вердикт — из заголовков ответа
grep -i '^X-KMG-' /tmp/headers.txt
```

Компактная сводка вместо SARIF:

```sh
curl -sS -X POST "http://localhost:3000/api/ci/scan/summary?repository=owner/name" \
  -H "Authorization: Bearer $KMG_TOKEN" \
  -H "Content-Type: application/gzip" \
  --data-binary @/tmp/code.tar.gz | python -m json.tool
```

### Способ 2 — прямое обращение к движку (без backend и без БД)

Самый короткий путь проверить работу сканеров:

```sh
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"repository_path": "/absolute/path/to/project", "scan_id": "manual-001"}' \
  | python -m json.tool
```

Авторизация не требуется. AI-анализ не выполняется. Полезно для проверки того,
что Semgrep, Gitleaks и Trivy действительно работают.

### Способ 3 — guard в режиме CI

```sh
cd /path/to/project-under-test

export KMG_API_URL=http://localhost:3000/api
export KMG_TOKEN=<KMG_SESSION_TOKEN>
export KMG_SCAN_SCOPE=all          # весь проект, как требует п. 4.4.1 ТЗ
export KMG_HEAD_REF=$(git rev-parse HEAD)

node /path/to/kmg/tools/git-hooks/kmg-guard.mjs ci
echo "exit code: $?"
```

Создаются файлы `kmg-scan-report.json` и `kmg-results.sarif` в текущем каталоге.

### Способ 4 — локальные git-хуки (только информирование)

```sh
./tools/git-hooks/install.sh /path/to/project-under-test
git -C /path/to/project-under-test config --local kmg.token  <KMG_SESSION_TOKEN>
git -C /path/to/project-under-test config --local kmg.apiurl http://localhost:3000/api
```

Хуки всегда завершаются кодом 0 — они показывают находки, но не блокируют. См.
[CI_CD.md](CI_CD.md#локальный-режим-разработчика).

---

## Запуск тестов

```sh
# Backend: 16 тестов, БД и движок не требуются
cd backend && npm ci && npm run test

# Guard: 12 тестов, внешних зависимостей нет
node --test tools/git-hooks/kmg-guard.test.mjs

# Покрытие
cd backend && npm run test:cov
```

Фактические результаты прогона — [TESTING.md](TESTING.md#результаты-прогона).

---

## Запуск в CI

### Проверка чужого репозитория

1. Скопировать [examples/ai-security.yml](../examples/ai-security.yml) в
   проверяемый репозиторий как `.github/workflows/ai-security.yml`.
2. Добавить два секрета: `Settings → Secrets and variables → Actions`:
   * `KMG_API_URL` — адрес KMG, доступный из среды выполнения GitHub Actions;
   * `KMG_TOKEN` — сессионный токен KMG.
3. Выполнить push. Workflow запустится автоматически.

Адрес KMG должен быть доступен снаружи. Для `localhost` этот путь неприменим.

### Вариант через composite action

```yaml
- uses: <owner>/<repository>@main
  with:
    api-url: ${{ secrets.KMG_API_URL }}
    token: ${{ secrets.KMG_TOKEN }}
    paths: all          # обязательно для соответствия п. 4.4.1 ТЗ
    fail-open: 'false'
```

### Самопроверка репозитория агента

[.github/workflows/security-scan.yml](../.github/workflows/security-scan.yml)
запускается сам при push в `main`/`develop`. Требуются секреты `GROQ_API_KEY`,
`ENCRYPTION_KEY`, а для шага применения политики — `KMG_API_URL` и `KMG_TOKEN`.

---

## Ожидаемые результаты

### Движок

| Проверка | Ожидание |
|---|---|
| `GET /health` | `status: ok`, все три инструмента `true` |
| `POST /scan` по проекту с уязвимостями | `status: "success"`, непустой `findings`, все сканеры `COMPLETED` |
| `POST /scan` по пустому каталогу | HTTP 422, `Workspace … contains no files to scan` |
| `POST /scan` по несуществующему пути | HTTP 404 |

Проверка на заведомо уязвимом коде:

```sh
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"repository_path": "/abs/path/to/kmg/security-test-repository", "scan_id": "fixtures"}' \
  | python -c "import json,sys; d=json.load(sys.stdin); print(d['status'], len(d['findings']))"
```

Ожидается `success` и ненулевое число находок. Точное число не фиксировано: оно
зависит от версии официальных правил Semgrep и от базы уязвимостей Trivy на
момент сборки образа, поэтому приводить его как эталон было бы некорректно.

### Guard в режиме CI

| Ситуация | Код завершения | Что печатается |
|---|---|---|
| Находок нет | 0 | `✔ Проблем не найдено.` |
| Находки есть, вердикт `REVIEW` | 0 | `⚠ Проверка пройдена с замечаниями` |
| Вердикт `BLOCK` | 1 | `✖ Build blocked. Security policy: BLOCK.` |
| Сканер не завершился | 1 | `Security policy: INCOMPLETE.` |
| Backend недоступен | 1 | `✖ Build blocked: security validation could not complete.` |
| Backend недоступен при `KMG_FAIL_OPEN=1` | 0 | `KMG_FAIL_OPEN=1 — CI scan could not run; build allowed` |

### Воспроизводимость результатов

| Часть результата | Воспроизводима | Пояснение |
|---|---|---|
| Набор находок сканеров | да, при неизменных версиях инструментов и правил | правила вшиты в образ; реестр Semgrep по умолчанию не используется |
| Статусы сканеров | да | — |
| Оценка риска | да | детерминированная формула |
| Вердикт политики | да | детерминированный алгоритм |
| Код завершения | да | выводится из вердикта |
| Вердикты триажа | **нет** | `temperature: 0.1` снижает разброс, но не устраняет его |
| Тексты обоснований и сводки | **нет** | генерируются моделью |
| Статусы контролей ИБ | частично | детерминированные ветки (`MISSING` без признаков, `NOT_APPLICABLE`) воспроизводимы; оценка моделью — нет |

Иначе говоря: **всё, что влияет на решение пайплайна, воспроизводимо**.
Невоспроизводима только пояснительная часть отчёта.

---

## Типичные проблемы

| Симптом | Причина | Решение |
|---|---|---|
| `ENCRYPTION_KEY must be exactly 32 characters long` | ключ не той длины | задать ровно 32 символа |
| `semgrep: No module named 'pydantic._internal._signature'` | Semgrep установлен в общий интерпретатор | переустановить через `pipx` |
| Все сканеры `FAILED`, `engineUsed: builtin-fallback` | движок недоступен | проверить `SECURITY_ENGINE_URL` и `GET /health` |
| `Trivy wrote an empty report` | база уязвимостей не загружена | проверить доступ в сеть при сборке образа |
| `Semgrep ran but analysed 0 of the repository's source files` | рабочая область пуста либо содержит только неподдерживаемые типы файлов | проверить состав архива |
| `verdict: null`, `statusText: SCAN_PARTIAL` | сканер не завершился | причина в `scanners[<имя>].error` |
| `GROQ_API_KEY не настроен` | ключи отсутствуют | задать `GROQ_API_KEYS`; проверка сканерами при этом продолжится |
| `все настроенные Groq API-ключи отклонены провайдером` | ключи недействительны | обновить ключи; на вердикт это не влияет |
| HTTP 413 при `POST /api/ci/scan` | архив больше 80 МБ | расширить список исключений при упаковке |
| `Не git-репозиторий, проверка пропущена` | guard запущен вне git | запускать из корня репозитория |
