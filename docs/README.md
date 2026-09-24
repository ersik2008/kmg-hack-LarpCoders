# KMG Security AI Agent

Индекс документации проекта для хакатона KMG Digital «Разработка ИИ-агента для
автоматизированной проверки функций информационной безопасности в процессе
разработки программного обеспечения с интеграцией в CI/CD».

> **Статус документации.** Все утверждения ниже подтверждены конкретными файлами
> репозитория. Там, где функциональность отсутствует или реализована частично,
> стоит явная пометка `NOT IMPLEMENTED`, `PARTIAL` или `TODO`. Документация
> описывает текущее состояние кода, а не план.

---

## Назначение

Система выполняет автоматизированный анализ безопасности репозитория и
возвращает детерминированный вердикт (`PASS` / `REVIEW` / `BLOCK` /
`INCOMPLETE`), по которому CI/CD принимает решение о продолжении сборки.

Анализ состоит из двух независимых частей:

1. **Поиск дефектов** — три внешних сканера (Semgrep, Gitleaks, Trivy) плюс
   встроенный regex-сканер как аварийный резерв. Отвечает на вопрос «где в коде
   есть уязвимость».
2. **Оценка функций ИБ** — 10 контролей безопасности
   ([control-evidence.ts](../backend/src/agent/control-evidence.ts)):
   детерминированный сбор признаков по коду, затем оценка найденных признаков
   языковой моделью. Отвечает на вопрос «реализован ли механизм защиты вообще».

Вердикт вычисляется детерминированно в
[policy.service.ts](../backend/src/policy/policy.service.ts). Модель не участвует
в принятии решения о блокировке пайплайна.

---

## Фактический поток выполнения

Схема ниже соответствует коду. Отличия от схемы из задания отмечены явно.

```
Git Push
   │
   ├─► GitHub Actions
   │      │
   │      ├─► examples/ai-security.yml  — упаковка репозитория целиком в tar.gz
   │      │        └─► POST /api/ci/scan  (CiService)
   │      │
   │      └─► action.yml (composite)     — отбор файлов через git
   │               └─► kmg-guard.mjs ci
   │                    └─► POST /api/prepush/check  (PrepushService)
   │
   └─► GitHub webhook  ──► POST /api/cicd/webhook  (CicdService)
                             └─► ScanService.startScan → git clone --depth 1

                    ┌──────────────────────────────────┐
                    │  Рабочая область (workspace)     │
                    └──────────────────────────────────┘
                                   │
          ┌────────────────────────┼────────────────────────┐
          ▼                        ▼                        ▼
   security-engine           ArchitectureService     BuiltinScannerService
   POST /scan                (дерево файлов,         (regex-резерв, только
   Semgrep│Gitleaks│Trivy     граф, языки)            если движок недоступен)
          │
          ▼
   Нормализация находок (normalizer.py → finding-row.util.ts) → БД
          │
          ▼
   AI-слой (Groq):  SecurityControlsService  → 10 контролей ИБ
                    InvestigationService     → триаж находок, цепочки атак, сводка
          │
          ▼
   PolicyService.evaluate()  — детерминированный вердикт
          │
          ▼
   Отчёты: SARIF 2.1.0 · kmg-scan-report.json · GitHub Step Summary (Markdown)
          │
          ▼
   Exit code:  0 = PASS/REVIEW      1 = BLOCK / INCOMPLETE / ошибка проверки
               (отдельного кода 2 в реализации НЕТ — см. CI_CD.md)
```

**Отличия от схемы задания:**

| Этап из задания | Состояние |
|---|---|
| Full Project Analysis | PARTIAL — поддерживается, но композитный action по умолчанию берёт `paths: changed` |
| Security Scanners | PASS — Semgrep, Gitleaks, Trivy |
| Requirement Analysis (ИБ-01…ИБ-08) | NOT IMPLEMENTED — есть 10 контролей ИБ, не привязанных к идентификаторам ИБ-01…ИБ-08 |
| LLM Analysis | PASS — Groq |
| Evidence Validation | PARTIAL — для контролей и цепочек атак валидация есть, для триажа находок нет |
| Report | PARTIAL — JSON и SARIF есть, Markdown только как job summary / комментарий PR |
| Policy Decision | PASS — детерминированный |
| Exit Code | PARTIAL — реализованы только 0 и 1 |

---

## Документы

| Документ | Содержание |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Компоненты, входы, выходы, взаимодействие, диаграммы |
| [ANALYSIS_PIPELINE.md](ANALYSIS_PIPELINE.md) | Жизненный цикл проверки от триггера до отчёта |
| [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) | Матрица ИБ-01…ИБ-08 и состояние проверки каждого |
| [CONTEXT_ANALYSIS.md](CONTEXT_ANALYSIS.md) | Как решается ограничение контекстного окна модели |
| [LLM.md](LLM.md) | Слой языковой модели, промпты, защита от галлюцинаций и инъекций |
| [CI_CD.md](CI_CD.md) | GitHub Actions, коды завершения, артефакты, локальный режим |
| [REPORT_FORMAT.md](REPORT_FORMAT.md) | Схемы JSON, SARIF и Markdown-представлений |
| [DECISION_ENGINE.md](DECISION_ENGINE.md) | Детерминированная политика и приоритеты вердиктов |
| [TESTING.md](TESTING.md) | Существующие тесты, результаты прогона, пробелы |
| [REPRODUCIBILITY.md](REPRODUCIBILITY.md) | Инструкция воспроизведения для экспертной комиссии |
| [PERFORMANCE.md](PERFORMANCE.md) | Лимиты времени, таймауты, потребление токенов |
| [SECURITY.md](SECURITY.md) | Безопасность самого агента, недоверенный вход, найденные пробелы |
| [LIMITATIONS.md](LIMITATIONS.md) | Что агент может и чего не может доказать |
| [TRACEABILITY.md](TRACEABILITY.md) | Матрица прослеживаемости ТЗ → код → тест → отчёт |
| [HACKATHON_COMPLIANCE.md](HACKATHON_COMPLIANCE.md) | Чек-лист соответствия ТЗ с указанием доказательств |

Ранее написанные документы по интеграции сохранены и остаются актуальными:

* [CICD_INTEGRATION.md](CICD_INTEGRATION.md) — три уровня встраивания проверки;
* [CI_API.md](CI_API.md) — контракт `POST /api/ci/scan`.

---

## Реально реализованные возможности

Каждый пункт подтверждён файлом.

| Возможность | Подтверждение |
|---|---|
| Неинтерактивный запуск в CI | [action.yml](../action.yml), [kmg-guard.mjs](../tools/git-hooks/kmg-guard.mjs) |
| Анализ всего репозитория (архив tar.gz) | [ci.service.ts](../backend/src/ci/ci.service.ts) |
| Анализ всего репозитория (git clone) | [repository.service.ts](../backend/src/repository/repository.service.ts) |
| Semgrep SAST с офлайн-правилами | [semgrep_scanner.py](../security-engine/app/scanners/semgrep_scanner.py), [Dockerfile](../security-engine/Dockerfile) |
| Собственный набор правил (19 правил) | [kmg-baseline.yaml](../security-engine/rules/kmg-baseline.yaml) |
| Поиск секретов | [gitleaks_scanner.py](../security-engine/app/scanners/gitleaks_scanner.py) |
| Анализ зависимостей и конфигураций | [trivy_scanner.py](../security-engine/app/scanners/trivy_scanner.py) |
| Явный статус каждого сканера (COMPLETED/FAILED/SKIPPED) | [main.py](../security-engine/app/main.py) |
| Запрет вердикта PASS при незавершённой проверке | [policy.service.ts:139-205](../backend/src/policy/policy.service.ts#L139-L205) |
| Детерминированная политика | [policy.service.ts:207-262](../backend/src/policy/policy.service.ts#L207-L262) |
| Оценка 10 функций ИБ | [security-controls.service.ts](../backend/src/agent/security-controls.service.ts) |
| Триаж находок моделью (TP/FP/UNCERTAIN) | [investigation.service.ts](../backend/src/agent/investigation.service.ts) |
| Отчёт SARIF 2.1.0 | [sarif.service.ts](../backend/src/scan/sarif.service.ts) |
| Выгрузка в GitHub Code Scanning | [github-status.service.ts](../backend/src/github/github-status.service.ts) |
| Пул ключей Groq с отказоустойчивостью | [groq.service.ts](../backend/src/ai/groq.service.ts) |
| Веб-интерфейс с результатами | [frontend/src/pages](../frontend/src/pages) |

## Что не реализовано

Короткий список; подробности — в [HACKATHON_COMPLIANCE.md](HACKATHON_COMPLIANCE.md).

* Требования ИБ-01…ИБ-08 как отдельные проверяемые сущности с собственным
  статусом `PASS` / `VIOLATION` / `INSUFFICIENT_EVIDENCE`.
* Код завершения `2` (внутренняя ошибка агента).
* Отчёт со сводной частью по п. 4.6.3 ТЗ (commit id, время начала и завершения,
  длительность, статус по каждому требованию).
* Markdown-отчёт как самостоятельный артефакт сборки.
* Проверка ИБ-05, ИБ-06, ИБ-08 в каком-либо виде.

---

## Нормативная база

Документация опирается на перечень п. 3.1 ТЗ:

1. Закон Республики Казахстан от 24.11.2015 № 418-V «О кибербезопасности».
2. Закон Республики Казахстан от 21.05.2013 № 94-V «О персональных данных и их защите».
3. Единые требования в области информационно-коммуникационных технологий и
   обеспечения информационной безопасности, утверждённые постановлением
   Правительства Республики Казахстан от 20.12.2016 № 832.
4. СТ РК ISO/IEC 27001-2023.
5. СТ РК ISO/IEC 27002-2023.
6. СТ РК 1073-2007.

Акты из п. 3.2 ТЗ (Цифровой кодекс РК, Закон «Об искусственном интеллекте»)
подлежат подтверждению подразделением ИБ Организатора и в настоящей
документации как обязательные не используются.
