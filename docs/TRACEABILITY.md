# Матрица прослеживаемости

Сопоставление пунктов Технического задания хакатона с реализацией, тестами,
отчётом и поведением CI.

Правило заполнения: в колонках «Реализация» и «Тест» указывается конкретный файл
либо `NOT IMPLEMENTED`. Предположений и планов в таблицах нет.

Навигация: [README](README.md) · [SECURITY_REQUIREMENTS](SECURITY_REQUIREMENTS.md) ·
[HACKATHON_COMPLIANCE](HACKATHON_COMPLIANCE.md)

---

## 1. Требования ИБ (п. 4.5)

| ТЗ | ID | Реализация | Тест | Отчёт | Поведение CI |
|---|---|---|---|---|---|
| 4.5.1 | ИБ-01 | PARTIAL — контроль `AUTHORIZATION` в [control-evidence.ts](../backend/src/agent/control-evidence.ts) | NOT IMPLEMENTED | статус контроля в `security_controls`; в SARIF при `MISSING`/`PARTIAL` с доказательством | статус требования на вердикт не влияет |
| 4.5.2 | ИБ-02 | PARTIAL — контроли `AUTHENTICATION`, `SESSION_MANAGEMENT`; правила `kmg-jwt-decode-without-verification`, `kmg-jwt-algorithm-none`, `kmg-jwt-hardcoded-secret` в [kmg-baseline.yaml](../security-engine/rules/kmg-baseline.yaml) | NOT IMPLEMENTED | находки правил — как обычные находки | находка `CRITICAL` → `BLOCK`, но не как нарушение ИБ-02 |
| 4.5.3 | ИБ-03 | PARTIAL — контроль `TRANSPORT_SECURITY`; правило `kmg-tls-verification-disabled` | NOT IMPLEMENTED | то же | находка `HIGH` влияет через оценку риска |
| 4.5.4 | ИБ-04 | PARTIAL — контроли `AUTHENTICATION`, `CRYPTOGRAPHY`; правила `kmg-weak-hash-algorithm`, `kmg-python-weak-hash-algorithm`, `kmg-insecure-randomness-for-secrets` | NOT IMPLEMENTED | то же | SHA-256 для пароля не детектируется |
| 4.5.5 | ИБ-05 | **NOT IMPLEMENTED** | NOT IMPLEMENTED | отсутствует | отсутствует |
| 4.5.6 | ИБ-06 | **NOT IMPLEMENTED** — `.md` не читается ни одним компонентом | NOT IMPLEMENTED | отсутствует | отсутствует |
| 4.5.7 | ИБ-07 | PARTIAL — контроль `AUDIT_LOGGING` без оценки покрытия | NOT IMPLEMENTED | статус контроля | статус на вердикт не влияет |
| 4.5.8 | ИБ-08 | **NOT IMPLEMENTED** | NOT IMPLEMENTED | отсутствует | отсутствует |

---

## 2. Общие требования (п. 4.1)

| ТЗ | Требование | Реализация | Тест | Состояние |
|---|---|---|---|---|
| 4.1.1 | Проверка кода, конфигурации и документации | [main.py](../security-engine/app/main.py), [ci.service.ts](../backend/src/ci/ci.service.ts) | NOT IMPLEMENTED | PARTIAL — документация не анализируется |
| 4.1.2 | Неинтерактивный режим | [kmg-guard.mjs](../tools/git-hooks/kmg-guard.mjs), [action.yml](../action.yml) | тесты 7–10 в [kmg-guard.test.mjs](../tools/git-hooks/kmg-guard.test.mjs) | PASS |
| 4.1.3 | Детерминированность формата вывода и кодов завершения | [sarif.service.ts](../backend/src/scan/sarif.service.ts), `shouldFailProcess` | тесты 1–12 в `kmg-guard.test.mjs` | PASS |
| 4.1.4 | Свободный выбор языка, библиотек и модели | TypeScript + Python, Groq | — | PASS |
| 4.1.5 | Агент не изменяет проверяемый репозиторий | клонирование и распаковка в отдельную рабочую область; запись только в `${WORKSPACES_ROOT}` | NOT IMPLEMENTED | PASS по коду |

---

## 3. Компоненты решения (п. 4.2)

| ТЗ | Компонент | Реализация | Состояние |
|---|---|---|---|
| 4.2.1 | Модуль интеграции с CI/CD | [action.yml](../action.yml), [examples/ai-security.yml](../examples/ai-security.yml), [cicd.service.ts](../backend/src/cicd/cicd.service.ts) | PASS |
| 4.2.2 | Модуль сбора контекста | [ci.service.ts](../backend/src/ci/ci.service.ts), [repository.service.ts](../backend/src/repository/repository.service.ts), [architecture.service.ts](../backend/src/scan/architecture.service.ts), [control-evidence.ts](../backend/src/agent/control-evidence.ts) | PASS |
| 4.2.3 | Модуль анализа | [security-engine/app/scanners](../security-engine/app/scanners), [security-controls.service.ts](../backend/src/agent/security-controls.service.ts), [investigation.service.ts](../backend/src/agent/investigation.service.ts) | PASS |
| 4.2.4 | Модуль формирования отчёта | [sarif.service.ts](../backend/src/scan/sarif.service.ts), `emitCiArtifacts` в [kmg-guard.mjs](../tools/git-hooks/kmg-guard.mjs) | PARTIAL — нет привязки к требованиям ИБ, нет Markdown-артефакта |
| 4.2.5 | Модуль принятия решения | [policy.service.ts](../backend/src/policy/policy.service.ts) | PARTIAL — решение по severity, а не по требованиям ИБ |

---

## 4. Интеграция с CI/CD (п. 4.3)

| ТЗ | Требование | Реализация | Тест | Состояние |
|---|---|---|---|---|
| 4.3.1 | Автоматический запуск по push отдельным шагом | `on: [push, pull_request]` в [examples/ai-security.yml](../examples/ai-security.yml) | NOT IMPLEMENTED | PASS |
| 4.3.2 | Шаг размещён до слияния и развёртывания | шаг `Проверить вердикт` завершает job ошибкой | NOT IMPLEMENTED | PASS |
| 4.3.3 | Код завершения 0 | `shouldFailProcess` → `false` | тесты 1, 2, 7 в `kmg-guard.test.mjs` | PASS |
| 4.3.3 | Код завершения 1 | `shouldFailProcess` → `true` | тесты 8–11 | PASS |
| 4.3.3 | Код завершения 2 | **NOT IMPLEMENTED** | NOT IMPLEMENTED | **NOT IMPLEMENTED** |
| 4.3.4 | Отчёт как артефакт, доступный при любом результате | `upload-artifact` и `upload-sarif` с `if: always()` | NOT IMPLEMENTED | PASS |
| 4.3.5 | Причина прерывания в журнале | `printFindings`, `printCiFailure`, `emitCiArtifacts` | NOT IMPLEMENTED | PARTIAL — перечня требований ИБ нет |
| 4.3.6 | Информационные замечания не прерывают пайплайн | `REVIEW` → код 0 | тест 7 | PASS |

---

## 5. Глубина и полнота анализа (п. 4.4)

| ТЗ | Требование | Реализация | Тест | Состояние |
|---|---|---|---|---|
| 4.4.1 | Анализ проекта целиком, а не только изменённых файлов | `tar -czf … .` в [examples/ai-security.yml](../examples/ai-security.yml); `git clone` в [repository.service.ts](../backend/src/repository/repository.service.ts); `KMG_SCAN_SCOPE=all` в `collectCiTargets` | NOT IMPLEMENTED | PARTIAL — `paths` по умолчанию `changed` в [action.yml](../action.yml) |
| 4.4.2 | Учёт сквозных требований | сбор признаков контролей всегда по всей рабочей области | NOT IMPLEMENTED | PARTIAL — покрытие проекта не оценивается |
| 4.4.3 | Анализ кода, конфигурации, зависимостей, CI/CD, документации | Semgrep, Trivy `misconfig`, Trivy `vuln`, Semgrep по `.github/workflows` | NOT IMPLEMENTED | PARTIAL — документация не анализируется |
| 4.4.4 | Механизм полноты при ограничении контекста | [CONTEXT_ANALYSIS.md](CONTEXT_ANALYSIS.md); группировка, дедупликация, адаптивное окно, независимые запросы | NOT IMPLEMENTED | PASS — механизм реализован и описан |
| 4.4.5 | Отсутствие реализации = нарушение | `missingWithoutEvidence` → статус `MISSING` без обращения к модели | NOT IMPLEMENTED | PARTIAL — на вердикт не влияет |

---

## 6. Отчёт (п. 4.6)

| ТЗ | Требование | Реализация | Состояние |
|---|---|---|---|
| 4.6.1 | JSON | `kmg-scan-report.json`, SARIF 2.1.0 | PASS |
| 4.6.1 | Markdown | `GITHUB_STEP_SUMMARY`, комментарий PR | PARTIAL — отдельного файла нет |
| 4.6.2 | Идентификатор и формулировка нарушенного требования | — | **NOT IMPLEMENTED** |
| 4.6.2 | Путь к файлу | `filePath` в `findings` | PASS |
| 4.6.2 | Номер строки | `startLine`, `endLine` | PASS |
| 4.6.2 | Наименование функции / класса / параметра | — | **NOT IMPLEMENTED** |
| 4.6.2 | Фрагмент кода | `codeSnippet` | PASS |
| 4.6.2 | Обоснование | `description` (текст правила, CWE, OWASP) | PARTIAL |
| 4.6.2 | Уровень критичности | `severity` | PASS |
| 4.6.2 | Рекомендация | `ai_analyses.metadata.recommendation` | PARTIAL — в отчёт CI не попадает |
| 4.6.3 | Идентификатор коммита | `versionControlProvenance.revisionId` в SARIF | PARTIAL — в JSON-отчёте отсутствует |
| 4.6.3 | Время начала и завершения | `scans.startedAt`, `scans.completedAt` в БД | **NOT IMPLEMENTED** в отчёте |
| 4.6.3 | Длительность | `duration_ms` в ответе движка | PARTIAL — в итоговый отчёт не переносится |
| 4.6.3 | Общий результат | `verdict`, `policyResult` | PASS |
| 4.6.3 | Количество нарушений | `counts` | PASS |
| 4.6.3 | Статус по каждому требованию | — | **NOT IMPLEMENTED** |
| 4.6.4 | Конкретность описания | все находки несут `filePath` и `startLine` | PASS |
| 4.6.5 | Результат соответствует коду завершения | `shouldFailProcess` выводит код из `verdict` | PASS |

---

## 7. Производительность (п. 4.7)

| ТЗ | Требование | Реализация | Состояние |
|---|---|---|---|
| 4.7.1 | Время шага ≤ 30 минут | `timeout-minutes: 30` в [security-scan.yml](../.github/workflows/security-scan.yml) | PARTIAL — не измерено |
| 4.7.2 | Корректное завершение по лимиту с частичным отчётом | — | **NOT IMPLEMENTED** |
| 4.7.3 | Обработка ошибок внешних сервисов | пул ключей Groq, обработка таймаутов сканеров, резервный сканер | PARTIAL — вместо аварийного завершения работа продолжается |

---

## 8. Предмет проверки (п. 4.8)

| ТЗ | Требование | Реализация | Состояние |
|---|---|---|---|
| 4.8.1 | Нарушения ИБ — основание для прерывания | — | **NOT IMPLEMENTED** — прерывание по severity |
| 4.8.1 | Прочие дефекты приводятся отдельным разделом и не прерывают пайплайн | — | **NOT IMPLEMENTED** — разделения нет |

---

## 9. Нормативная база (п. 3.1)

| ТЗ | Акт | Упоминание в документации проекта |
|---|---|---|
| 3.1.1 | Закон РК от 24.11.2015 № 418-V «О кибербезопасности» | [docs/README.md](README.md), [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) |
| 3.1.2 | Закон РК от 21.05.2013 № 94-V «О персональных данных и их защите» | там же |
| 3.1.3 | Единые требования, ПП РК от 20.12.2016 № 832 | там же |
| 3.1.4 | СТ РК ISO/IEC 27001-2023 | там же |
| 3.1.5 | СТ РК ISO/IEC 27002-2023 | там же |
| 3.1.6 | СТ РК 1073-2007 | там же, раздел ИБ-04 |
| 3.3 | Проверка наличия ссылок как предмет ИБ-06 | **NOT IMPLEMENTED** |

До подготовки настоящего комплекта документации перечень п. 3.1 в репозитории
не упоминался ни в одном файле.

---

## 10. Критерии оценки (раздел 6 ТЗ)

| Критерий | Вес | Что реализовано | Чего не хватает |
|---|---|---|---|
| Выявление уязвимостей | 50% | Semgrep с 19 собственными правилами и официальными наборами, Gitleaks, Trivy; 10 контролей ИБ; триаж моделью с доказательствами | проверки ИБ-05, ИБ-06, ИБ-08; детекция SHA-256 для паролей; оценка покрытия для ИБ-07 |
| Точность выводов | 10% | триаж TP/FP/UNCERTAIN, дедупликация по `filePath::ruleId` внутри триажа, `CONFIRMED`/`POTENTIAL` для графа, исключение localhost для `http://`, удаление рёбер по ложным срабатываниям | дедупликация между сканерами; проверка ссылок в тексте вердикта; разделение обязательных и дополнительных находок |
| Полнота анализа | 5% | анализ всего репозитория по трём путям; явный статус каждого сканера; запрет `PASS` при незавершённой проверке | `paths: all` по умолчанию; анализ документации; оценка покрытия проекта |
| Интеграция с CI/CD | 15% | три пути интеграции; артефакты при любом результате; SARIF в Code Scanning; комментарий в PR; fail-closed по умолчанию; разделение локального и CI enforcement | код завершения 2; перечень нарушенных требований в журнале |
| Качество отчётности | 15% | SARIF 2.1.0 с устойчивыми отпечатками; job summary; комментарий PR; редактирование секретов на четырёх уровнях | привязка к требованиям ИБ; Markdown-артефакт; сводная часть по п. 4.6.3 |
| Воспроизводимость и эффективность | 5% | офлайн-правила в образе; предзагруженная база Trivy; детерминированный вердикт; [REPRODUCIBILITY.md](REPRODUCIBILITY.md) | замеры производительности; корректное завершение по лимиту времени |

---

## Сводка

| Категория | PASS | PARTIAL | NOT IMPLEMENTED | Всего |
|---|---|---|---|---|
| Общие требования (4.1) | 4 | 1 | 0 | 5 |
| Компоненты (4.2) | 3 | 2 | 0 | 5 |
| Интеграция с CI/CD (4.3) | 6 | 1 | 1 | 8 |
| Полнота анализа (4.4) | 1 | 4 | 0 | 5 |
| Требования ИБ (4.5) | 0 | 5 | 3 | 8 |
| Отчёт (4.6) | 9 | 5 | 4 | 18 |
| Производительность (4.7) | 0 | 2 | 1 | 3 |
| Предмет проверки (4.8) | 0 | 0 | 2 | 2 |
| **Итого** | **23** | **20** | **11** | **54** |
