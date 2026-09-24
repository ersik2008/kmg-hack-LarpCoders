# Формат отчёта

Документ описывает фактически формируемые отчёты. Все схемы построены по коду,
который их создаёт; поля, требуемые ТЗ, но отсутствующие в реализации, отмечены
отдельно.

Навигация: [README](README.md) · [CI_CD](CI_CD.md) ·
[DECISION_ENGINE](DECISION_ENGINE.md) · [SECURITY_REQUIREMENTS](SECURITY_REQUIREMENTS.md)

---

## Какие отчёты формируются

| Формат | Файл / место | Кто формирует | Соответствие ТЗ |
|---|---|---|---|
| SARIF 2.1.0 (полный) | ответ `POST /api/ci/scan`, `GET /api/scans/:id/sarif`, Code Scanning | [sarif.service.ts](../backend/src/scan/sarif.service.ts) | машиночитаемый JSON — п. 4.6.1 частично |
| SARIF 2.1.0 (минимальный) | `kmg-results.sarif` | [kmg-guard.mjs](../tools/git-hooks/kmg-guard.mjs), `toSarif` | то же |
| JSON вердикта | `kmg-scan-report.json` | `kmg-guard.mjs`, `emitCiArtifacts` | п. 4.6.1 частично |
| JSON движка | `scan_results.json` | [security-engine/app/main.py](../security-engine/app/main.py) | внутренний |
| Markdown job summary | `GITHUB_STEP_SUMMARY` | `kmg-guard.mjs`, `emitCiArtifacts` | п. 4.6.1 частично |
| Markdown комментарий PR | комментарий в pull request | [github-status.service.ts](../backend/src/github/github-status.service.ts), `renderComment` | п. 4.6.1 частично |
| Markdown сводка аудитора | запись `ai_analyses` | `InvestigationService.writeReport` через модель | справочный |

> **Отклонение от п. 4.6.1 ТЗ.** Markdown-представление отчёта существует, но
> только как job summary и комментарий в PR. Отдельный файл-артефакт
> `report.md` не формируется.

> **Отклонение от п. 4.6.3 ТЗ.** Ни один отчёт не содержит полной сводной части:
> отсутствуют время начала и завершения проверки, её длительность и статус по
> каждому требованию ИБ-01…ИБ-08.

---

## 1. `kmg-scan-report.json`

Файл записывается `emitCiArtifacts` и представляет собой дословный ответ
`POST /api/prepush/check`, то есть структуру `PrePushCheckResult`
([prepush.service.ts](../backend/src/prepush/prepush.service.ts)).

### Фактическая схема

```json
{
  "verdict": "BLOCK",
  "statusText": "BLOCK",
  "blocked": true,
  "incomplete": false,
  "riskScore": 10,
  "reasons": [
    "Critical vulnerabilities detected (2) or risk score threshold exceeded (10.0/7.0)."
  ],
  "counts": {
    "CRITICAL": 2,
    "HIGH": 1,
    "MEDIUM": 3,
    "LOW": 0,
    "INFO": 0
  },
  "findings": [
    {
      "scanner": "semgrep",
      "ruleId": "kmg-sql-injection-string-interpolation",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "title": "SQL-запрос собирается конкатенацией недоверенного ввода",
      "description": "CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command\nOWASP: A03:2021 - Injection",
      "filePath": "src/auth/auth.service.ts",
      "startLine": 42,
      "endLine": 42,
      "codeSnippet": "const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`);"
    },
    {
      "scanner": "gitleaks",
      "ruleId": "aws-access-token",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "title": "Exposed secret: aws-access-token",
      "description": "AWS Access Token. A live credential committed to the repository must be considered compromised: rotate it and remove it from the code and from git history.",
      "filePath": "src/config/credentials.ts",
      "startLine": 7,
      "endLine": 7,
      "codeSnippet": "***REDACTED***"
    }
  ],
  "scanners": {
    "semgrep":  { "status": "COMPLETED", "findingsCount": 4, "error": null,
                  "startedAt": "2026-09-24T09:14:02.118Z",
                  "finishedAt": "2026-09-24T09:16:37.902Z" },
    "gitleaks": { "status": "COMPLETED", "findingsCount": 1, "error": null,
                  "startedAt": "2026-09-24T09:14:02.118Z",
                  "finishedAt": "2026-09-24T09:16:37.902Z" },
    "trivy":    { "status": "COMPLETED", "findingsCount": 1, "error": null,
                  "startedAt": "2026-09-24T09:14:02.118Z",
                  "finishedAt": "2026-09-24T09:16:37.902Z" }
  },
  "filesChecked": 128,
  "scanId": "3f9a1c2e-0b7d-4a51-9e28-6c4f0d5b7a13",
  "sarifAvailable": true,
  "engineUsed": "security-engine"
}
```

### Поля

| Поле | Тип | Описание |
|---|---|---|
| `verdict` | `"BLOCK" \| "REVIEW" \| "PASS" \| null` | `null`, когда проверка не завершена |
| `statusText` | `string` | `BLOCK` / `REVIEW` / `PASS` / `SCAN_PARTIAL` / `SCAN_INCOMPLETE` |
| `blocked` | `boolean` | политика требует блокировки (включая незавершённость) |
| `incomplete` | `boolean` | проверка не завершена, вердикту доверять нельзя |
| `riskScore` | `number \| null` | 0–10, детерминированный расчёт |
| `reasons` | `string[]` | обоснования решения политики |
| `counts` | `object` | счётчики по severity |
| `findings` | `array` | см. ниже |
| `scanners` | `object` | статус каждого сканера |
| `filesChecked` | `number` | число файлов, записанных в рабочую область |
| `scanId` | `string \| null` | `null`, если репозиторий не найден в базе |
| `sarifAvailable` | `boolean` | доступна ли выгрузка SARIF по `scanId` |
| `engineUsed` | `"security-engine" \| "builtin-fallback" \| "none"` | какой движок дал результат |

### Объект находки

| Поле | Тип | Требование ТЗ п. 4.6.2 |
|---|---|---|
| `scanner` | `string` | — |
| `ruleId` | `string \| null` | — |
| `severity` | `CRITICAL\|HIGH\|MEDIUM\|LOW\|INFO` | уровень критичности — **есть** |
| `confidence` | `HIGH\|MEDIUM\|LOW` | — |
| `title` | `string` | — |
| `description` | `string \| null` | обоснование — **частично**: текст правила, CWE, OWASP |
| `filePath` | `string \| null` | путь к файлу — **есть** |
| `startLine` | `number \| null` | номер строки — **есть** |
| `endLine` | `number \| null` | — |
| `codeSnippet` | `string \| null` | фрагмент кода — **есть**; для секретов `***REDACTED***` |
| `requirementId` | — | **ОТСУТСТВУЕТ** — идентификатор нарушенного требования ИБ |
| `requirementText` | — | **ОТСУТСТВУЕТ** — формулировка требования |
| `functionName` / `className` / `configParameter` | — | **ОТСУТСТВУЕТ** — наименование функции, класса, параметра |
| `recommendation` | — | **ОТСУТСТВУЕТ** в этой схеме; рекомендация модели хранится отдельно в `ai_analyses.metadata.recommendation` |

### Статусы сканера

| Статус | Значение |
|---|---|
| `QUEUED` | поставлен в очередь |
| `RUNNING` | выполняется |
| `COMPLETED` | отработал и выдал разбираемый результат |
| `FAILED` | не запустился, упал, превысил таймаут или выдал нечитаемый отчёт |
| `SKIPPED` | сознательно отключён в активной политике |
| `INVALID` | результат не поддаётся интерпретации |

Различение `SKIPPED` и `COMPLETED` принципиально: отключённый сканер никогда не
представляется как «проверил и ничего не нашёл».

---

## 2. `scan_results.json` (ответ движка)

Формируется [security-engine/app/main.py](../security-engine/app/main.py),
сохраняется артефактом `security-scan-results` при самопроверке.

```json
{
  "status": "success",
  "duration_ms": 155784,
  "filesCount": 412,
  "repositoryPath": "/github/workspace",
  "scanners": {
    "semgrep":  { "status": "COMPLETED", "findingsCount": 4, "filesScanned": 389, "error": null },
    "gitleaks": { "status": "COMPLETED", "findingsCount": 0, "error": null },
    "trivy":    { "status": "COMPLETED", "findingsCount": 2, "error": null }
  },
  "findings": [
    {
      "scanner": "semgrep",
      "ruleId": "kmg-weak-hash-algorithm",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "title": "Используется устаревший алгоритм хеширования",
      "description": "CWE: CWE-327\nOWASP: A02:2021 - Cryptographic Failures",
      "filePath": "src/utils/hash.ts",
      "startLine": 12,
      "endLine": 12,
      "codeSnippet": "return crypto.createHash('md5').update(value).digest('hex');",
      "scanId": "ci-18472930012"
    }
  ]
}
```

Поле `status` принимает значения `success` (все запрошенные сканеры завершены),
`partial` (хотя бы один завершён) и `failed` (ни один не завершён). Поле
`duration_ms` — единственное место во всей системе, где фиксируется длительность
выполнения.

---

## 3. SARIF 2.1.0

Основной машиночитаемый отчёт. Схема — `https://json.schemastore.org/sarif-2.1.0.json`.

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "KMG AI Security Agent",
          "version": "1.0.0",
          "informationUri": "https://github.com/",
          "rules": [
            {
              "id": "semgrep/kmg-sql-injection-string-interpolation",
              "name": "KmgSqlInjectionStringInterpolation",
              "shortDescription": { "text": "SQL-запрос собирается конкатенацией недоверенного ввода" },
              "fullDescription": { "text": "CWE: CWE-89\nOWASP: A03:2021 - Injection" },
              "help": {
                "text": "CWE: CWE-89 …",
                "markdown": "**SQL-запрос собирается конкатенацией…**\n\n…\n\n_Обнаружено: semgrep · правило `kmg-sql-injection-string-interpolation`_"
              },
              "defaultConfiguration": { "level": "error" },
              "properties": {
                "tags": ["security", "semgrep", "severity:critical"],
                "security-severity": "9.5",
                "precision": "high"
              }
            },
            {
              "id": "kmg-control/audit_logging",
              "name": "AuditLogging",
              "shortDescription": { "text": "Функция ИБ: Аудит и журналирование" },
              "fullDescription": { "text": "Журналирование присутствует только в части обработчиков…" },
              "defaultConfiguration": { "level": "warning" },
              "properties": {
                "tags": ["security", "security-control", "control:audit_logging"],
                "security-severity": "6.0"
              }
            }
          ]
        }
      },
      "automationDetails": { "id": "kmg-ai/security-scan/owner/repository" },
      "versionControlProvenance": [
        {
          "repositoryUri": "https://github.com/owner/repository",
          "revisionId": "4f2c1ab9e7d05836c1b4a92e7f30d8c5a1b6e402",
          "branch": "main"
        }
      ],
      "results": [
        {
          "ruleId": "semgrep/kmg-sql-injection-string-interpolation",
          "ruleIndex": 0,
          "level": "error",
          "message": { "text": "SQL-запрос собирается конкатенацией недоверенного ввода" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/auth/auth.service.ts" },
                "region": { "startLine": 42, "endLine": 42 }
              }
            }
          ],
          "partialFingerprints": { "primaryLocationLineHash": "a1b2c3d4e5f60718293a4b5c6d7e8f90" },
          "properties": { "scanner": "semgrep", "severity": "CRITICAL", "confidence": "HIGH" }
        }
      ],
      "properties": {
        "scanId": "3f9a1c2e-0b7d-4a51-9e28-6c4f0d5b7a13",
        "policyResult": "BLOCK",
        "riskScore": 10,
        "totalFindings": 6,
        "exportedResults": 6,
        "exportedControls": 1,
        "truncated": false
      }
    }
  ]
}
```

Особенности реализации:

| Свойство | Значение |
|---|---|
| Соответствие severity | `CRITICAL → error / 9.5`, `HIGH → error / 7.5`, `MEDIUM → warning / 5.0`, `LOW → note / 3.0`, `INFO → note / 1.0` |
| Контроли ИБ | `MISSING → warning / 6.0`, `PARTIAL → note / 4.0` |
| Отпечаток | SHA-256 от `scanner\|ruleId\|filePath\|codeSnippet`, первые 32 символа — позволяет GitHub отслеживать находку между прогонами |
| Ограничение | 5000 результатов; при превышении `properties.truncated = true` |
| Путь | всегда относительный; ведущие `./` и `/` удаляются |
| Строка | при отсутствии подставляется `1` (SARIF требует положительное значение) |
| Контроли без доказательства | **не экспортируются** — Code Scanning требует location, а выдумывать его недопустимо |

`buildEncoded` дополнительно сжимает документ gzip и кодирует base64 — это формат,
требуемый API GitHub Code Scanning.

---

## 4. Markdown job summary

Записывается в `GITHUB_STEP_SUMMARY` функцией `emitCiArtifacts`.

```markdown
## 🛡️ KMG AI — проверка безопасности

🛑 **Сборка заблокирована: найдены критические уязвимости**

**Вердикт политики:** `BLOCK`  ·  **Риск:** 10/10
**Enforcement:** CI BLOCKING · local hooks ADVISORY
**Проверено файлов:** 128  ·  **Сканеры:** semgrep=COMPLETED, gitleaks=COMPLETED, trivy=COMPLETED

🔴 CRITICAL 2 · 🟠 HIGH 1 · 🟡 MEDIUM 3 · 🔵 LOW 0

| Severity | Файл | Проблема | Сканер |
|---|---|---|---|
| CRITICAL | `src/auth/auth.service.ts:42` | SQL-запрос собирается конкатенацией недоверенного ввода | semgrep |
| CRITICAL | `src/config/credentials.ts:7` | Exposed secret: aws-access-token | gitleaks |
| HIGH | `src/api/webhook.service.ts:88` | Запрос по адресу из пользовательского ввода | semgrep |

- Critical vulnerabilities detected (2) or risk score threshold exceeded (10.0/7.0).
```

Заголовок выбирается по четырём состояниям: проверка не завершена, сборка
заблокирована, пройдена с замечаниями, уязвимостей не найдено. Таблица
ограничена 25 строками.

---

## 5. Markdown комментарий в pull request

Два варианта в зависимости от пути интеграции.

Из workflow «под ключ» ([examples/ai-security.yml](../examples/ai-security.yml)):

```markdown
🛑 **KMG AI: слияние заблокировано — критические уязвимости**

🔴 Critical **2** · 🟠 High **1** · 🟡 Medium **3** · 🔵 Low **0**

Оценка риска: **10/10**

Разбор каждой находки — во вкладке **Security → Code scanning**.
```

Из серверной части при webhook-сценарии — `GithubStatusService.renderComment`.

Отдельная формулировка предусмотрена для незавершённой проверки:

> ⚠️ **Проверка не завершена** — вердикт не вынесен. Пустой список находок здесь
> НЕ означает, что код безопасен.

---

## 6. Markdown сводка аудитора

Генерируется моделью (`InvestigationService.writeReport`), сохраняется в
`ai_analyses` с `type = 'finding_analysis'`, отображается в интерфейсе
компонентом [MarkdownView.tsx](../frontend/src/components/MarkdownView.tsx).

Структура задана системной инструкцией: «Общая оценка», «Ключевые риски», «Что
исправить в первую очередь», «Ограничения проверки». При наличии свёрнутых
дубликатов текст предваряется строкой вида:

> AI разобрал все 47 находок: 18 уникальных дефектов (29 повторов того же
> правила в том же файле объединены).

Этот отчёт носит справочный характер и на решение политики не влияет.

---

## Статусы требований ИБ

**NOT IMPLEMENTED.** Ни один из отчётов не содержит раздела `requirements` со
статусом по каждому из восьми требований. Требование п. 4.6.3 ТЗ о наличии
статуса по каждому требованию, включая те, по которым нарушений не выявлено, не
выполнено.

Косвенно близкую информацию даёт `GET /api/scans/:id/controls` — матрица десяти
контролей ИБ:

```json
{
  "controls": [
    {
      "control": "AUDIT_LOGGING",
      "title": "Аудит и журналирование",
      "status": "PARTIAL",
      "confidence": "MEDIUM",
      "summary": "Найден централизованный логгер, но события отказа в доступе не журналируются.",
      "risk": "Без журнала событий ИБ инцидент невозможно обнаружить и расследовать.",
      "recommendation": "Добавить запись аудита в обработчик отказа в доступе.",
      "evidence": [
        { "filePath": "src/common/logger.ts", "line": 14,
          "snippet": "export const logger = createLogger({ level: 'info' });",
          "note": "Структурное логирование" }
      ]
    }
  ],
  "summary": {
    "total": 10, "implemented": 4, "partial": 3, "missing": 2,
    "notApplicable": 1, "unknown": 0, "coverage": 61
  }
}
```

Это контроли, а не требования ИБ-01…ИБ-08, и их статусы (`IMPLEMENTED` /
`PARTIAL` / `MISSING` / `NOT_APPLICABLE` / `UNKNOWN`) не совпадают с требуемыми
ТЗ (`PASS` / `VIOLATION` / `INSUFFICIENT_EVIDENCE`).

---

## Целевая схема для соответствия ТЗ

Схема ниже **не реализована**. Приводится как спецификация, чтобы сопоставление с
требованиями п. 4.6 было однозначным.

```json
{
  "metadata": {
    "commit_id": "4f2c1ab9e7d05836c1b4a92e7f30d8c5a1b6e402",
    "branch": "main",
    "repository": "owner/repository",
    "started_at": "2026-09-24T09:14:02.118Z",
    "finished_at": "2026-09-24T09:16:37.902Z",
    "duration_seconds": 155,
    "result": "BLOCK",
    "exit_code": 1,
    "violations_count": 2,
    "scanners": { "semgrep": "COMPLETED", "gitleaks": "COMPLETED", "trivy": "COMPLETED" },
    "llm": { "provider": "groq", "model": "openai/gpt-oss-120b", "available": true }
  },

  "requirements": {
    "IB-01": { "status": "PASS", "evidence_count": 3, "violations": [] },
    "IB-02": { "status": "VIOLATION", "evidence_count": 2, "violations": ["v-001"] },
    "IB-03": { "status": "PASS", "evidence_count": 1, "violations": [] },
    "IB-04": { "status": "VIOLATION", "evidence_count": 1, "violations": ["v-002"] },
    "IB-05": { "status": "INSUFFICIENT_EVIDENCE", "evidence_count": 0, "violations": [],
               "reason": "Приложение не ведёт локальных журналов на файловой системе" },
    "IB-06": { "status": "VIOLATION", "evidence_count": 0, "violations": ["v-003"] },
    "IB-07": { "status": "VIOLATION", "evidence_count": 4, "violations": ["v-004"] },
    "IB-08": { "status": "PASS", "evidence_count": 2, "violations": [] }
  },

  "violations": [
    {
      "id": "v-002",
      "requirement_id": "IB-04",
      "requirement_text": "Пароли должны храниться в виде значений функций формирования ключа bcrypt, argon2 или scrypt.",
      "file_path": "src/auth/auth.service.ts",
      "line_start": 58,
      "line_end": 60,
      "symbol": { "type": "method", "name": "AuthService.register" },
      "evidence": "const hash = crypto.createHash('sha256').update(password).digest('hex');",
      "explanation": "Пароль хешируется SHA-256 — быстрой хеш-функцией общего назначения без адаптивного KDF. Подбор по словарю выполняется на порядки быстрее, чем при bcrypt/argon2/scrypt.",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "detected_by": ["semgrep", "llm"],
      "recommendation": "Заменить на argon2id либо bcrypt с cost >= 12; перехешировать существующие значения при следующем успешном входе."
    }
  ],

  "additional_findings": [
    {
      "id": "f-014",
      "category": "dependency-vulnerability",
      "file_path": "package.json",
      "line_start": 21,
      "evidence": "\"lodash\": \"4.17.15\"",
      "explanation": "CVE-2021-23337: command injection в lodash < 4.17.21.",
      "severity": "HIGH",
      "confidence": "HIGH",
      "detected_by": ["trivy"],
      "recommendation": "Обновить до 4.17.21 или выше.",
      "blocks_pipeline": false
    }
  ]
}
```

### Дополнительные находки

Согласно п. 4.8.1 ТЗ дополнительные дефекты безопасности приводятся отдельным
разделом и основанием для прерывания пайплайна **не являются**. В целевой схеме
это выражено массивом `additional_findings` с полем `blocks_pipeline: false`.

**В текущей реализации разделения нет.** Все находки лежат в одном массиве
`findings`, и любая из них уровня `CRITICAL` приводит к `BLOCK` — независимо от
того, связана ли она с обязательным требованием ИБ. См.
[DECISION_ENGINE.md](DECISION_ENGINE.md#расхождение-с-тз).

### Дедупликация

Поле `detected_by: ["semgrep", "trivy", "llm"]` в целевой схеме решает задачу
из п. 23 постановки: одна проблема, найденная несколькими инструментами, должна
давать одну нормализованную находку.

**В текущей реализации дедупликации между сканерами нет.** Semgrep и Trivy,
обнаружив один и тот же дефект, создают две независимые записи `Finding`, и обе
попадают в счётчики и в SARIF. Дедупликация существует только внутри AI-триажа
по ключу `filePath::ruleId` и влияет лишь на расход токенов.

---

## Сводка соответствия п. 4.6 ТЗ

| Пункт | Требование | Состояние |
|---|---|---|
| 4.6.1 | JSON-отчёт | PASS — `kmg-scan-report.json`, SARIF |
| 4.6.1 | Markdown-представление | PARTIAL — job summary и комментарий PR, отдельного файла нет |
| 4.6.2 | Идентификатор и формулировка нарушенного требования ИБ | **NOT IMPLEMENTED** |
| 4.6.2 | Путь к файлу | PASS |
| 4.6.2 | Номер строки | PASS |
| 4.6.2 | Наименование функции / класса / параметра | **NOT IMPLEMENTED** |
| 4.6.2 | Фрагмент кода | PASS (`codeSnippet`) |
| 4.6.2 | Обоснование несоответствия | PARTIAL — описание правила и CWE/OWASP; привязки к требованию нет |
| 4.6.2 | Уровень критичности | PASS |
| 4.6.2 | Рекомендация по устранению | PARTIAL — есть в `ai_analyses.metadata`, в отчёте CI отсутствует |
| 4.6.3 | Идентификатор коммита | PARTIAL — в SARIF (`versionControlProvenance`), в JSON-отчёте нет |
| 4.6.3 | Время начала и завершения | **NOT IMPLEMENTED** — есть в БД (`startedAt`/`completedAt`), в отчёты не попадает |
| 4.6.3 | Длительность проверки | PARTIAL — `duration_ms` в ответе движка, в итоговый отчёт не переносится |
| 4.6.3 | Общий результат | PASS |
| 4.6.3 | Количество выявленных нарушений | PASS (`counts`) |
| 4.6.3 | Статус по каждому требованию ИБ | **NOT IMPLEMENTED** |
| 4.6.4 | Указание конкретного местоположения | PASS — находка без `filePath` в схеме возможна, но на практике сканеры его дают |
| 4.6.5 | Общий результат соответствует коду завершения | PASS — `shouldFailProcess` выводит код из того же `verdict` |
