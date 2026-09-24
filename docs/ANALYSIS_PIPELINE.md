# Конвейер анализа

Полный жизненный цикл проверки — от триггера до отчёта и кода завершения.
Разделы отражают реализацию; отсутствующие этапы помечены явно.

Навигация: [README](README.md) · [ARCHITECTURE](ARCHITECTURE.md) ·
[CONTEXT_ANALYSIS](CONTEXT_ANALYSIS.md) · [DECISION_ENGINE](DECISION_ENGINE.md)

---

## Trigger

В коде существует четыре точки запуска.

| Триггер | Реализация | Режим |
|---|---|---|
| `push`, `pull_request` в GitHub Actions | [examples/ai-security.yml](../examples/ai-security.yml) | блокирующий |
| Шаг пайплайна через composite action | [action.yml](../action.yml) → `kmg-guard.mjs ci` | блокирующий |
| GitHub webhook `push` / `pull_request` | [cicd.service.ts](../backend/src/cicd/cicd.service.ts) | публикует commit status |
| Локальные git-хуки | [tools/git-hooks/pre-push](../tools/git-hooks/pre-push), [pre-commit](../tools/git-hooks/pre-commit) | **только информирование**, всегда `exit 0` |
| Ручной запуск из интерфейса | `POST /api/scans` | без влияния на CI |

Самопроверка репозитория агента запускается
[.github/workflows/security-scan.yml](../.github/workflows/security-scan.yml) на
`push` в `main`/`develop` и на `pull_request` в `main`.

Все режимы неинтерактивны: ни один код не запрашивает ввод пользователя в
процессе проверки.

---

## Input

Что фактически получает агент.

### Путь через `POST /api/ci/scan`

| Параметр | Источник | Обязателен |
|---|---|---|
| тело запроса | сырой `tar.gz` репозитория | да |
| `repository` | `${{ github.repository }}` → `owner/name` | да |
| `repositoryId` | `${{ github.event.repository.id }}` | нет |
| `sha` | commit SHA (`pull_request.head.sha` или `github.sha`) | нет |
| `ref` | `${{ github.ref }}` | нет |
| `pr` | номер pull request | нет |
| `ai` | `off` — пропустить AI-анализ | нет |
| авторизация | `Authorization: Bearer <KMG_TOKEN>` (JWT) | да |

### Путь через `kmg-guard.mjs ci`

Конфигурация читается по приоритету: переменная окружения → `git config kmg.*` →
`.kmg.json` → значение по умолчанию
([kmg-guard.mjs](../tools/git-hooks/kmg-guard.mjs), `loadConfig`).

| Ключ | По умолчанию | Назначение |
|---|---|---|
| `KMG_API_URL` | `http://localhost:3000/api` | адрес backend |
| `KMG_TOKEN` | — | сессионный токен, обязателен |
| `KMG_BLOCK_ON` | пусто (вердикт сервера) | `CRITICAL` / `HIGH` / `ANY` |
| `KMG_FAIL_OPEN` | `0` | `1` разрешает сборку только при недоступной проверке |
| `KMG_MAX_FILES` | `400` | предел числа файлов в одной проверке |
| `KMG_MAX_FILE_KB` | `512` | предел размера одного файла |
| `KMG_TIMEOUT_MS` | `300000` | таймаут HTTP-запроса к backend |
| `KMG_SCAN_SCOPE` | `changed` | `changed` или `all` |
| `KMG_BASE_REF` / `KMG_HEAD_REF` | из github-контекста | границы диффа |

Тело запроса к `/api/prepush/check`:
`{ repository, branch, commitSha, remote, stage, files: [{ path, contentBase64 }] }`.

---

## Repository discovery

Корень проекта определяется по-разному в зависимости от пути.

* **Архив из CI:** корнем становится каталог распаковки `tar -xzf` — то есть то,
  что упаковал workflow. Проверка записей архива выполняется **до** записи на
  диск ([tar-inspector.ts](../backend/src/ci/tar-inspector.ts)); абсолютные пути и
  выходы через `..` отклоняются.
* **Клонирование:** `git clone --depth 1` в
  `${WORKSPACES_ROOT}/scan-<scanId>/repository`
  ([repository.service.ts](../backend/src/repository/repository.service.ts)). При
  неудаче с явной веткой выполняется повтор с remote HEAD.
* **Guard:** корень — `git rev-parse --show-toplevel`. Файлы читаются не из
  рабочей копии, а из объектов git (`git show <sha>:<path>`), то есть ровно то
  содержимое, которое уйдёт в репозиторий.

Во всех случаях пустая рабочая область — ошибка, а не «уязвимостей нет»:
`main.py` отвечает HTTP 422, `ci.service.ts` — `BadRequestException`,
`scan.service.ts` ставит скану статус `FAILED`.

---

## Full project analysis

Требование ТЗ (п. 4.4.1): агент обязан анализировать проект целиком, а не только
файлы, изменённые в коммите.

**Состояние: PARTIAL.**

| Путь | Объём анализа | Соответствие п. 4.4.1 |
|---|---|---|
| `POST /api/ci/scan` ([examples/ai-security.yml](../examples/ai-security.yml)) | весь репозиторий (`tar -czf … .`) | соответствует |
| `POST /api/scans` (webhook, UI) | весь репозиторий (`git clone`) | соответствует |
| `action.yml` с `paths: all` | весь репозиторий (`git ls-tree -r HEAD`) | соответствует |
| `action.yml` со значением по умолчанию `paths: changed` | `git diff --name-only <base> <head>` | **не соответствует** |

Дефолт `changed` задан в [action.yml](../action.yml) и используется в шаге
`Enforce KMG AI security policy` собственного workflow этого репозитория. Для
соответствия ТЗ значение по умолчанию должно быть `all` — это зафиксировано как
критический пробел в [HACKATHON_COMPLIANCE.md](HACKATHON_COMPLIANCE.md).

Смягчающие обстоятельства, реально присутствующие в коде
([kmg-guard.mjs](../tools/git-hooks/kmg-guard.mjs), `collectCiTargets`): при
отсутствии базового коммита, при нулевом SHA и при пустом диффе (типично для
shallow clone) выполняется откат на полное дерево — «ничего не проверили»
исключено.

Состав анализируемых артефактов при полном проходе:

| Категория | Кто анализирует |
|---|---|
| Исходный код | Semgrep (собственные правила + официальные security-наборы), встроенный резерв |
| Конфигурация | Trivy `misconfig`, Semgrep (`.yaml`, `.json`, `.tf`) |
| Зависимости | Trivy `vuln` по манифестам и lock-файлам |
| Конфигурация CI/CD | Semgrep по `.github/workflows/*.yml`; `SECURITY_CONFIGURATION.fileSignals` проверяет наличие security-workflow |
| Документация | **не анализируется** — `.md` отсутствует и в `CODE_EXTENSIONS` Semgrep-сканера, и в `EVIDENCE_EXTENSIONS` сборщика признаков. Прямое следствие: ИБ-06 проверить нечем |
| Секреты | Gitleaks (правила встроены в бинарь, работает офлайн), Trivy `secret` |

Сквозные требования (ИБ-01, ИБ-02, ИБ-07, ИБ-08) требуют именно полного прохода:
по одному изменённому файлу нельзя установить, существует ли единый слой
журналирования или общий middleware аутентификации. Обоснование —
[CONTEXT_ANALYSIS.md](CONTEXT_ANALYSIS.md#почему-анализа-изменённых-файлов-недостаточно).

---

## Indexing

**Состояние: PARTIAL — индекс существует, но не используется для планирования анализа.**

Что реально собирается
([architecture.service.ts](../backend/src/scan/architecture.service.ts)):

| Данные | Как собираются |
|---|---|
| Дерево файлов | рекурсивный обход, игнор-лист из 14 каталогов |
| Количество файлов и строк | подсчёт при обходе; строки — только для файлов < 500 КБ |
| Языки | сопоставление расширения со словарём `EXT_TO_LANG` (20 расширений) |
| Граф архитектуры (Graph A) | классификация файла в `MODULE`/`CONTROLLER`/`SERVICE`/`MODEL`/`DATABASE`/`EXTERNAL_API`/`CONFIG`/`FILE` по пути и содержимому |
| Признаки контролей ИБ | [control-evidence.ts](../backend/src/agent/control-evidence.ts): 41 регулярное выражение + 8 сигналов по пути файла, с привязкой к `file:line` |

Ограничения, заложенные в код:

* обход дерева останавливается на **800 файлах**;
* сборщик признаков контролей: до **12 000** файлов в обходе, до **4 000**
  читаемых, глубина **8**, размер файла до **400 КБ**, до **3** совпадений на
  сигнал и до **8** на контроль;
* Semgrep-сканер считает файлы отдельно и не имеет такого потолка.

**TODO (NOT IMPLEMENTED):**

* карта зависимостей между модулями на основе `import`/`require`;
* карта символов (функции, классы, декораторы) с привязкой к требованию;
* скоринг релевантности файла конкретному требованию ИБ;
* инвертированный индекс по признакам для повторного использования между сканами.

---

## Static analysis

### Semgrep

| Параметр | Значение |
|---|---|
| Файл | [semgrep_scanner.py](../security-engine/app/scanners/semgrep_scanner.py) |
| Назначение | SAST: инъекции, небезопасная криптография, JWT, CORS, TLS, path traversal, SSRF |
| Вход | путь рабочей области |
| Выход | `{ status, data: { results, paths.scanned }, error, filesScanned }` |
| Наборы правил | `/app/rules` (19 собственных правил, [kmg-baseline.yaml](../security-engine/rules/kmg-baseline.yaml)) + `/opt/semgrep-rules` (официальные `security`-наборы, вшиты в образ) |
| Severity | `metadata.kmg_severity` из правила, иначе `ERROR→HIGH`, `WARNING→MEDIUM`, `INFO→LOW` |
| Таймаут | `SEMGREP_TIMEOUT_SECONDS`, по умолчанию 300 с; плюс `--timeout 30` на правило/файл |
| Обработка ошибок | нет вывода, невалидный JSON, код возврата ∉ {0,1}, отсутствие наборов правил → `FAILED` |

Отдельная защита от ложного «чисто»: если Semgrep отчитался успехом, но
`paths.scanned` пуст, а в рабочей области есть файлы поддерживаемых расширений —
статус принудительно становится `FAILED` с текстом «Semgrep ran but analysed 0 of
the repository's source files».

Реестровые наборы (`SEMGREP_REGISTRY_CONFIG`) по умолчанию отключены, чтобы
проверка не зависела от доступности сети. Каждый реестровый набор запускается
отдельным процессом, чтобы его падение не уронило локальные правила.

### Gitleaks

| Параметр | Значение |
|---|---|
| Файл | [gitleaks_scanner.py](../security-engine/app/scanners/gitleaks_scanner.py) |
| Назначение | поиск секретов в файлах рабочей области |
| Аргументы | `detect --source . --report-format json --no-git --redact --exit-code 1` |
| Severity | всегда `CRITICAL` ([normalizer.py](../security-engine/app/scanners/normalizer.py)) |
| Таймаут | `GITLEAKS_TIMEOUT_SECONDS`, по умолчанию 180 с |
| Обработка ошибок | код возврата ≥ 2, отсутствие файла отчёта, невалидный JSON, неожиданная форма отчёта → `FAILED` |
| Секреты в отчёте | `codeSnippet` жёстко заменяется на `***REDACTED***` |

`--no-git` использован намеренно: рабочая область — shallow clone или
материализованный набор файлов, истории коммитов там нет.

### Trivy

| Параметр | Значение |
|---|---|
| Файл | [trivy_scanner.py](../security-engine/app/scanners/trivy_scanner.py) |
| Назначение | уязвимости зависимостей, ошибки конфигурации, секреты |
| Аргументы | `fs --format json --scanners vuln,misconfig,secret --cache-dir … --timeout Ns --no-progress -q .` |
| Severity | `CRITICAL/HIGH/MEDIUM/LOW` как есть, `UNKNOWN → INFO` |
| Таймаут | `TRIVY_TIMEOUT_SECONDS`, по умолчанию 300 с; ожидание процесса `+30 с` |
| Обработка ошибок | код возврата ≠ 0, отсутствие отчёта, **пустой отчёт**, невалидный JSON → `FAILED` |
| БД уязвимостей | предзагружается на этапе сборки образа (`trivy image --download-db-only`) |

Пустой отчёт трактуется как ошибка намеренно: «Trivy не смог» не должно
выглядеть как «уязвимостей нет».

### Встроенный резервный сканер

Запускается **только** когда ни один требуемый сканер не завершился успешно
(`allRequiredFailed`). 15 регулярных правил. Результаты попадают в отчёт с
`scanner: "builtin_fallback"`, но не удовлетворяют требованию политики о
завершённости сканеров — вердикт остаётся `SCAN_PARTIAL`.

---

## Requirement analysis

**Состояние: NOT IMPLEMENTED для ИБ-01…ИБ-08.**

Поиск по репозиторию не находит ни одного вхождения идентификаторов `ИБ-01`…`ИБ-08`
или `IB-01`…`IB-08` в исходном коде. Отдельной сущности требования нет ни в
[schema.prisma](../backend/prisma/schema.prisma), ни в логике политики.

Что вместо этого реализовано — оценка **10 контролей безопасности**
([control-evidence.ts](../backend/src/agent/control-evidence.ts)):

| Ключ контроля | Заголовок | Ближайшее требование ТЗ |
|---|---|---|
| `AUTHENTICATION` | Аутентификация | частично ИБ-02, частично ИБ-04 |
| `AUTHORIZATION` | Авторизация и контроль доступа | частично ИБ-01 |
| `SECRETS_MANAGEMENT` | Управление секретами | вне перечня ИБ |
| `INPUT_VALIDATION` | Валидация входных данных | вне перечня ИБ |
| `CRYPTOGRAPHY` | Криптография | частично ИБ-04 |
| `SESSION_MANAGEMENT` | Управление сессиями | частично ИБ-02 |
| `AUDIT_LOGGING` | Аудит и журналирование | частично ИБ-07 |
| `TRANSPORT_SECURITY` | Защита канала передачи | частично ИБ-03 |
| `SECURITY_CONFIGURATION` | Конфигурация безопасности | вне перечня ИБ |
| `DEPENDENCY_SECURITY` | Безопасность зависимостей | вне перечня ИБ |

Алгоритм оценки одного контроля
([security-controls.service.ts](../backend/src/agent/security-controls.service.ts)):

```
1. Обход рабочей области → список файлов (all + readable)
2. Чтение манифестов зависимостей → список пакетов
3. Определение наличия HTTP-поверхности (веб-фреймворк в манифесте или
   характерные маршруты в первых 400 файлах)
4. Для каждого контроля:
     a. сигналы по пути файла    → hits (label, filePath, line=0, positive)
     b. построчные регулярные выражения → hits (label, filePath, line, snippet, positive)
     c. совпадения пакетов манифеста → packagesFound
5. Детерминированные решения БЕЗ модели:
     requiresWebSurface && !hasWebSurface        → NOT_APPLICABLE
     hits.length == 0 && packagesFound.length == 0 → MISSING
6. Остальные контроли — пачками по 3 в один запрос к модели
7. Ответ модели нормализуется: статус и confidence приводятся к белому списку,
   ссылки на file:line, которых нет в собранных признаках, отбрасываются
8. Результат сохраняется в security_controls (unique scanId+control)
```

Сквозного покрытия проекта контроль `AUDIT_LOGGING` не устанавливает: он
фиксирует наличие признаков журналирования (до 8 совпадений), но не считает,
какая доля обработчиков данных покрыта. Для ИБ-07 этого недостаточно — см.
[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md#иб-07).

---

## LLM analysis

Контекст для модели формируется по-разному для двух задач.

### Триаж находок

[investigation.service.ts](../backend/src/agent/investigation.service.ts):

1. Находки сортируются по severity и дедуплицируются по ключу
   `filePath::ruleId|title` — одно правило, сработавшее в файле многократно,
   отправляется один раз.
2. Для каждой находки подбирается объём кода в зависимости от её типа
   (`contextBudget`):
   * «самодостаточные» (секрет, `ws://`, `http://`, слабый хеш, Gitleaks) — 12 строк / 1600 символов;
   * требующие потока данных (инъекции, traversal, SSRF, XSS, десериализация) — 40 строк / 7000 символов;
   * остальные — 22 строки / 3500 символов.
3. Находка в lock-файле получает **манифест** зависимостей вместо строки
   lock-файла: решение принимается по версии, а не по хешу.
4. Батч из `AI_TRIAGE_BATCH_SIZE` (по умолчанию 3) находок режется по общему
   бюджету `BATCH_CODE_BUDGET_CHARS = 12 000` символов кода.
5. Вердикт: `TRUE_POSITIVE` / `FALSE_POSITIVE` / `UNCERTAIN` + `confidence`.
6. Вердикт копируется на все дубликаты группы, чтобы ни одна находка в таблице
   не осталась без разбора.

### Оценка контролей

Модель получает **только** уже найденные в коде строки, сгруппированные на
«признаки реализации» и «признаки нарушения». Репозиторий целиком в промпт не
отправляется ни на одном этапе.

### Цепочки атак

Строятся **первыми**, до триажа: это один дешёвый запрос, и он не должен
зависеть от остатка дневного бюджета токенов. На вход — до 12 находок и белый
список допустимых файлов.

Подробности промптов, схем ответа и защиты — [LLM.md](LLM.md).

---

## Evidence validation

| Проверка | Реализована | Где |
|---|---|---|
| Ответ модели — валидный JSON | да | `GroqService.completeJson` (`response_format: json_object` + `JSON.parse` в try/catch) |
| Наличие требуемого поля в ответе | да | `triageBatch`, `buildAttackPaths`, `judgeBatch` бросают ошибку при отсутствии поля |
| Вердикт относится к находке из текущего батча | да | фильтр по `allowedIds` |
| Ссылка на `file:line` существует среди собранных признаков | да, для контролей | `SecurityControlsService.toAssessment` |
| Файл в цепочке атак встречается среди находок | да | `buildAttackPaths` |
| Тип ребра графа из белого списка | да | `VALID_EDGE_TYPES` |
| Рёбра, опирающиеся на ложные срабатывания, удаляются | да | `dropPathsForFalsePositives` |
| Файлы и строки, упомянутые **в тексте** вердикта триажа | **нет** | TODO |
| Статус требования ИБ подтверждён доказательством | **нет** — требований как сущности нет | TODO |

---

## Aggregation

1. Находки движка и резервного сканера объединяются в один массив.
2. Каждая приводится к строке БД через
   [finding-row.util.ts](../backend/src/scan/finding-row.util.ts): severity и
   confidence приводятся к перечислениям, строки обрезаются по длине колонок.
   Защита сознательная — одна некорректная запись раньше роняла весь
   `createMany` и превращала успешный скан в «0 находок».
3. Массовая вставка; при ошибке — построчная, с логированием отброшенных.
4. Счётчики по severity считаются из БД, а не из ответа движка.
5. Статусы сканеров, ошибки, настройки политики и метаданные записываются в
   `ScanResult.summary` как JSON-строка.

**Дедупликации между сканерами нет.** Одна и та же проблема, найденная Semgrep и
Trivy, даёт две записи `Finding`. Единого `finding_id` с полем `detected_by`
не существует — зафиксировано как пробел.

Дедупликация есть только внутри AI-триажа (по `filePath::ruleId`) и она влияет
на расход токенов, но не на состав отчёта и не на подсчёт находок.

---

## Decision

Вход политики:

```
findings[]            — все находки из БД
scanners{}            — статус каждого сканера
repositoryStatus      — READY | FAILED | INCOMPLETE
requiredScanners[]    — включённые в активной политике
thresholds            — пороги из таблицы policies
```

Порядок проверок ([policy.service.ts](../backend/src/policy/policy.service.ts)):

1. `repositoryStatus !== 'READY'` → `SCAN_INCOMPLETE`, `result = null`.
2. Ни одного включённого сканера → `SCAN_INCOMPLETE`, `result = null`.
3. Любой требуемый сканер не `COMPLETED` → `SCAN_PARTIAL`, `result = null`,
   риск считается частично.
4. Иначе — расчёт риска и вердикт `BLOCK` / `REVIEW` / `PASS`.

Подробно — [DECISION_ENGINE.md](DECISION_ENGINE.md).

---

## Report

| Формат | Кто формирует | Куда попадает |
|---|---|---|
| SARIF 2.1.0 (полный) | [sarif.service.ts](../backend/src/scan/sarif.service.ts) | ответ `/api/ci/scan`, `GET /api/scans/:id/sarif`, Code Scanning |
| SARIF 2.1.0 (минимальный) | `kmg-guard.mjs`, функция `toSarif` | `kmg-results.sarif` в рабочем каталоге job-а |
| JSON | `kmg-guard.mjs`, `emitCiArtifacts` | `kmg-scan-report.json` |
| JSON | самопроверка: ответ `POST /scan` движка | `scan_results.json`, артефакт сборки |
| Markdown | `kmg-guard.mjs`, `emitCiArtifacts` | `GITHUB_STEP_SUMMARY` |
| Markdown | [github-status.service.ts](../backend/src/github/github-status.service.ts), `renderComment` | комментарий в pull request |
| Markdown (сводка аудитора) | `InvestigationService.writeReport` через модель | запись `AIAnalysis`, отображается в интерфейсе |

**Markdown-отчёт как самостоятельный файл-артефакт не формируется** — это
отклонение от п. 4.6.1 ТЗ. Схемы и примеры — [REPORT_FORMAT.md](REPORT_FORMAT.md).
