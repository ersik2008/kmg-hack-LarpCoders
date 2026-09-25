# 🛡️ KMG AI Security Agent

> **ИИ-агент для автоматизированной проверки информационной безопасности в CI/CD**
> Разработан для хакатона ТОО «KMG Digital» · г. Павлодар, 2026

---

## Что это

KMG AI Security Agent — система, которая автоматически проверяет репозиторий на соответствие 8 обязательным требованиям ИБ (ТЗ п. 4.5) при каждом push-событии и либо пропускает, либо блокирует деплой.

```
git push
  └─► GitHub Actions
        └─► KMG Security Agent
              ├─► Semgrep (SAST)
              ├─► Gitleaks (секреты)
              ├─► Trivy (зависимости)
              └─► AI-анализ (Qwen 3.5 via Ollama по ИБ 01-08)
                    └─► Отчёт + вердикт → exit code
```

**Коды завершения:**

| Код | Смысл | Пайплайн |
|-----|-------|----------|
| `0` | Нарушений не найдено | ✅ Продолжается |
| `1` | Найдено ≥ 1 нарушения ИБ | ❌ Блокируется |
| `2` | Ошибка агента (модель недоступна, таймаут) | ⚠️ Блокируется |

---

## Быстрый старт

### Требования

- Docker + Docker Compose
- Git
- GitHub OAuth App (для авторизации)
- Ollama с моделью `qwen3.5:latest` (или Groq API ключ)

### 1. Клонировать и настроить

```bash
git clone <repository-url> kmg
cd kmg
cp .env.example .env
```

### 2. Заполнить `.env`

Откройте `.env` и заполните обязательные поля:

```env
# Пароль базы данных
POSTGRES_PASSWORD=your_secure_password
DATABASE_URL=postgresql://postgres:your_secure_password@localhost:5432/kmg

# JWT (сгенерируйте: openssl rand -hex 32)
JWT_SECRET=<32+ случайных символов>

# Ключ шифрования (ровно 32 символа)
ENCRYPTION_KEY=<32 символа>

# GitHub OAuth App (создать на github.com/settings/developers)
GITHUB_CLIENT_ID=<ваш client id>
GITHUB_CLIENT_SECRET=<ваш client secret>

# Вариант A: Ollama (локально)
OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_MODEL=qwen3.5:latest

# Вариант B: Groq (облако)
GROQ_API_KEY=<ваш groq api key>
```

### 3. Запустить

```bash
docker compose up --build
```

> Первый запуск займёт 3–5 минут (скачивание образов, Prisma миграции).

### 4. Проверить работоспособность

```bash
curl http://localhost:8000/health   # Security Engine
curl http://localhost:3000/api/health  # Backend API
```

### 5. Открыть интерфейс

Перейдите на `http://localhost:5173`, войдите через GitHub → добавьте репозиторий → запустите сканирование.

---

## Архитектура

```
┌──────────────────────────────────────────────────────────┐
│                    Docker Compose                        │
│                                                          │
│  ┌─────────────┐   ┌─────────────┐   ┌───────────────┐  │
│  │  Frontend   │   │   Backend   │   │Security Engine│  │
│  │  React/Vite │◄──│  NestJS 12  │──►│  FastAPI/Py   │  │
│  │  :5173      │   │  :3000      │   │  :8000        │  │
│  └─────────────┘   └──────┬──────┘   └───────────────┘  │
│                           │                              │
│                    ┌──────▼──────┐                       │
│                    │ PostgreSQL  │                       │
│                    │  :5432      │                       │
│                    └─────────────┘                       │
└──────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
    GitHub API                    Ollama / Groq
    (репозитории)                 (AI анализ)
```

| Компонент | Технологии | Назначение |
|-----------|-----------|------------|
| `frontend/` | React 19, Vite, TypeScript | Дашборд результатов |
| `backend/` | NestJS 12, TypeScript, Prisma | API, оркестрация, политика |
| `security-engine/` | FastAPI, Python 3.11 | Semgrep, Gitleaks, Trivy |
| `action.yml` | GitHub composite action | CI/CD интеграция |

---

## Интеграция в CI/CD

### Быстрое подключение

```bash
mkdir -p .github/workflows
cp examples/ai-security.yml .github/workflows/ai-security.yml
```

Добавьте секреты в **Settings → Secrets and variables → Actions**:

| Секрет | Значение |
|--------|----------|
| `KMG_API_URL` | URL бэкенда, например `https://your-kmg.example.com` |
| `KMG_TOKEN` | API-токен пользователя из настроек профиля |

Артефакты после каждого прогона:
- `kmg-report.md` — читаемый Markdown-отчёт для специалиста ИБ
- `kmg-scan-report.json` — машиночитаемый JSON
- `kmg-results.sarif` — SARIF 2.1.0 для GitHub Code Scanning

---

## Проверяемые требования ИБ (ТЗ п. 4.5)

| ID | Требование | Метод проверки |
|----|-----------|----------------|
| **ИБ-01** | Разграничение доступа к административному функционалу | AI + статический анализ |
| **ИБ-02** | Проверка сессии и токена на стороне сервера | Semgrep + AI |
| **ИБ-03** | Защита канала передачи данных (TLS ≥ 1.2) | Анализ конфигурации |
| **ИБ-04** | Криптозащита персональных данных (bcrypt/argon2/scrypt) | Gitleaks + AI |
| **ИБ-05** | Защита локальных журналов приложения | AI-анализ кода |
| **ИБ-06** | Ссылки на нормативную базу в документации | Поиск по документам |
| **ИБ-07** | Журналирование действий пользователей и событий СУБД | AI (сквозное) |
| **ИБ-08** | Контроль выгрузки персональных данных | AI + RBAC-анализ |

---

## Конфигурация AI

### Ollama (рекомендуется)

```env
OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_MODEL=qwen3.5:latest
```

```bash
ollama pull qwen3.5:latest
```

### Groq (облачная альтернатива)

```env
GROQ_API_KEY=gsk_...
GROQ_MODEL=openai/gpt-oss-120b
```

Получить ключ: [console.groq.com](https://console.groq.com)

---

## Локальная разработка

```bash
# Security Engine
cd security-engine && pip install -r requirements.txt
uvicorn app.main:app --port 8000

# Backend
cd backend && npm install && npx prisma migrate dev && npm run start:dev

# Frontend
cd frontend && npm install && npm run dev
```

### Тесты

```bash
cd backend && npm ci && npx vitest run     # Unit + integration тесты
cd backend && npx oxlint src/ test/       # Линтер
cd frontend && npm ci && npx vite build   # Сборка фронтенда
```

---

## Структура проекта

```
kmg/
├── backend/                 # NestJS API сервер
│   ├── src/
│   │   ├── ai/             # Интеграция с Ollama / Groq
│   │   ├── scan/           # Логика сканирования
│   │   ├── agent/          # AI агент (расследование)
│   │   ├── requirements/   # Проверка ИБ-01…ИБ-08
│   │   ├── ci/             # CI/CD интеграция
│   │   └── auth/           # GitHub OAuth
│   └── Dockerfile
├── frontend/                # React дашборд
│   └── src/
│       ├── pages/          # ScanDetails, Dashboard
│       └── components/     # IBRequirementsPanel и др.
├── security-engine/         # Python FastAPI + сканеры
│   └── app/
│       ├── scanners/       # Semgrep, Gitleaks, Trivy
│       └── normalizers/    # Нормализация находок
├── tools/                   # Вспомогательные утилиты
├── examples/               # Готовые workflow для GitHub Actions
├── docs/                   # Полная документация
├── action.yml              # GitHub composite action
├── docker-compose.yml
└── .env.example
```

---

## Документация

| Документ | Что внутри |
|----------|-----------| 
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Компоненты, диаграммы, потоки данных |
| [docs/ANALYSIS_PIPELINE.md](docs/ANALYSIS_PIPELINE.md) | Жизненный цикл проверки |
| [docs/SECURITY_REQUIREMENTS.md](docs/SECURITY_REQUIREMENTS.md) | Матрица ИБ-01…ИБ-08 |
| [docs/CI_CD.md](docs/CI_CD.md) | Интеграция, коды завершения, артефакты |
| [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) | Полная инструкция воспроизведения |
| [docs/DECISION_ENGINE.md](docs/DECISION_ENGINE.md) | Детерминированная политика вердикта |
| [docs/LLM.md](docs/LLM.md) | AI слой, защита от галлюцинаций |
| [docs/REPORT_FORMAT.md](docs/REPORT_FORMAT.md) | Схемы JSON, SARIF, Markdown |
| [docs/HACKATHON_COMPLIANCE.md](docs/HACKATHON_COMPLIANCE.md) | Чек-лист соответствия ТЗ |
| [docs/PITCH_CHEATSHEET.md](docs/PITCH_CHEATSHEET.md) | Шпаргалка для презентации жюри |

---

## Нормативная база

Агент проверяет соответствие следующим нормативным актам РК:

1. **Закон РК № 418-V от 24.11.2015** «О кибербезопасности»
2. **Закон РК № 94-V от 21.05.2013** «О персональных данных и их защите»
3. **Постановление Правительства РК № 832 от 20.12.2016** — единые требования в области ИКТ и ИБ
4. **СТ РК ISO/IEC 27001-2023** — системы менеджмента информационной безопасности
5. **СТ РК ISO/IEC 27002-2023** — средства управления ИБ
6. **СТ РК 1073-2007** — криптографическая защита информации

---

## 🔗 Подключение к демо-стенду (Tailscale)

Для доступа к живому демо-стенду используется защищённый туннель через **Tailscale**.

### Как подключиться

1. Установите Tailscale: [tailscale.com/download](https://tailscale.com/download)
2. Войдите или создайте аккаунт на [login.tailscale.com](https://login.tailscale.com)
3. **Свяжитесь с командой для получения данных доступа (invite-ссылки в сеть):**

   📞 **+7 705 205 8755** (WhatsApp / Telegram)

4. После добавления в Tailscale-сеть система будет доступна по внутреннему IP (адрес сообщат при подключении)

> ⚠️ Доступ предоставляется только участникам жюри и организаторам хакатона. Данные туннеля передаются лично по запросу.

---

## FAQ

**Q: Ollama недоступна из контейнера?**
Используйте `host.docker.internal` вместо `localhost` в `OLLAMA_BASE_URL`.

**Q: Ошибки 429 Too Many Requests?**
Лимит по умолчанию 600 запросов/мин. Изменить: `backend/src/app.module.ts` → `limit`.

**Q: Как обновить бэкенд после правок?**
```bash
docker compose up -d --build backend
```

**Q: Где смотреть логи?**
```bash
docker logs kmg-backend --tail 50 -f
docker logs kmg-security-engine --tail 50 -f
```

**Q: Как добавить своё правило Semgrep?**
Добавьте `.yaml` в `security-engine/rules/` и перезапустите engine.

---

<div align="center">
  <sub>Сделано с ❤️ и 🛡️ командой <b>LarpCoders</b> · KMG Digital Hackathon 2026</sub>
</div>
