# Безопасность самого агента

Агент обрабатывает недоверенный вход: проверяемый репозиторий может быть
подготовлен злонамеренно. Документ описывает реализованные меры защиты и
выявленные при аудите пробелы.

Навигация: [README](README.md) · [LLM](LLM.md) ·
[ARCHITECTURE](ARCHITECTURE.md) · [LIMITATIONS](LIMITATIONS.md)

---

## Модель угроз

**Основное положение: проверяемый репозиторий — это UNTRUSTED INPUT.**

Агент не исполняет код проверяемого проекта. Ни один компонент не вызывает
`npm install`, `pip install`, `make`, `go build` и не запускает скрипты
проверяемого проекта. Анализ выполняется исключительно чтением файлов и запуском
внешних сканеров, которым рабочая область передаётся как каталог данных.

Векторы, которые учитывались:

| Вектор | Описание |
|---|---|
| Path traversal через архив | запись файла вне рабочей области при распаковке |
| Path traversal через pre-push payload | то же через поле `path` в JSON-запросе |
| Path traversal при чтении файла | доступ к файлам вне рабочей области через API |
| Символические и жёсткие ссылки | ссылка наружу при безопасном имени записи |
| Архивная бомба | исчерпание диска при распаковке |
| Инъекция промпта | строки в коде проекта, адресованные языковой модели |
| Раскрытие секретов | попадание найденных секретов в отчёт, журнал или внешний API |
| Утечка учётных данных агента | токены GitHub, ключи Groq, JWT |
| Инъекция в команду оболочки | подстановка в строку команды |

---

## Проверка архива

Реализовано в [tar-inspector.ts](../backend/src/ci/tar-inspector.ts) — разбор
tar-заголовков **до** вызова `tar`.

Обоснование, зафиксированное в комментарии к файлу: полагаться на сам `tar`
нельзя, поскольку busybox-реализация молча срезает ведущие `../` и в листинге
отдаёт уже нормализованный путь — проверка по выводу `tar -tzf` traversal не
обнаруживает. Реализация `tar` в образе является деталью окружения и может
измениться при обновлении базового образа.

| Проверка | Реализация |
|---|---|
| Абсолютный путь (`/etc/passwd`) | `isUnsafePath` — отклоняется |
| Windows-путь (`C:\…`) | `isUnsafePath` — отклоняется |
| Выход через `..` в любом сегменте | `isUnsafePath` — отклоняется |
| Длинное имя (GNU-расширение, typeFlag `L`) | разбирается отдельно и тоже проверяется |
| Символическая ссылка наружу (typeFlag `2`) | цель ссылки проверяется |
| Жёсткая ссылка наружу (typeFlag `1`) | цель ссылки проверяется |
| Архивная бомба по объёму | не более 2 ГБ после распаковки |
| Архивная бомба по числу записей | не более 200 000 записей |
| Не tar / пустой архив | отклоняется |
| Размер входного архива | `CI_MAX_ARCHIVE_BYTES`, по умолчанию 80 МБ → HTTP 413 |

Отклонённый архив даёт `BadRequestException` до записи чего-либо на диск.

**Пробел:** `inspectTarGz` не покрыт ни одним тестом. Для компонента,
единственная задача которого — отражать атаку, это существенно. См.
[TESTING.md](TESTING.md).

---

## Проверка путей pre-push payload

Реализовано в `PrepushService.safeRelativePath`:

```ts
const cleaned = raw.replace(/\\/g, '/').replace(/^\.\//, '');
if (cleaned.startsWith('/') || /^[a-zA-Z]:/.test(cleaned)) return null;
const normalized = path.posix.normalize(cleaned);
if (normalized.startsWith('..') || normalized.split('/').includes('..')) return null;
if (!normalized || normalized === '.') return null;
return normalized;
```

Отклоняются: абсолютные пути, Windows-пути, любой выход через `..` (проверяется и
до, и после нормализации), пустые пути. Отклонённый путь записывается в журнал с
уровнем `warn` и пропускается — запрос целиком не отклоняется.

Дополнительно ограничен суммарный объём: `MAX_TOTAL_BYTES = 20 МБ`, превышение
даёт `BadRequestException`. Лимит тела запроса на уровне express —
`API_BODY_LIMIT`, по умолчанию 25 МБ.

**Пробел:** тестами не покрыто.

---

## Проверка путей при чтении файлов

Два места, оба защищены.

`ArchitectureService.readFileContent`:

```ts
const normalized = path.normalize(relativePath).replace(/^(\.\.(\/|\\|$))+/, '');
const fullPath = path.resolve(workspacePath, normalized);
if (!fullPath.startsWith(path.resolve(workspacePath))) {
  throw new Error('Access denied: path traversal prevented');
}
```

`InvestigationService.readContext` и `readWholeFile`:

```ts
const resolved = path.resolve(workspacePath, filePath);
if (!resolved.startsWith(path.resolve(workspacePath))) return '';
```

Проверка выполняется после `path.resolve`, то есть на уже нормализованном пути —
это корректный порядок.

---

## Запуск внешних процессов

Полный перечень мест, где агент запускает внешние программы.

| Место | Способ запуска | Оболочка | Таймаут | Оценка |
|---|---|---|---|---|
| [semgrep_scanner.py](../security-engine/app/scanners/semgrep_scanner.py) | `asyncio.create_subprocess_exec` | нет | 300 с | корректно |
| [gitleaks_scanner.py](../security-engine/app/scanners/gitleaks_scanner.py) | `asyncio.create_subprocess_exec` | нет | 180 с | корректно |
| [trivy_scanner.py](../security-engine/app/scanners/trivy_scanner.py) | `asyncio.create_subprocess_exec` | нет | 300 с | корректно |
| [ci.service.ts](../backend/src/ci/ci.service.ts) — распаковка | `execFile('tar', ['-xzf', …])` | нет | 180 с | корректно |
| [kmg-guard.mjs](../tools/git-hooks/kmg-guard.mjs) | `execFileSync('git', [...])` | нет | — | корректно, аргументы массивом |
| [repository.service.ts](../backend/src/repository/repository.service.ts) | **`exec(строка)`** | **да** | 90 с | **пробел, см. ниже** |

Все аргументы, попадающие в процессы сканеров, являются константами; проверяемый
код передаётся как рабочий каталог (`cwd`) и цель `.`, а не как аргумент
командной строки. Имена файлов проверяемого проекта в командную строку не
попадают ни в одном случае.

### Пробел: клонирование через оболочку

```ts
async runCommand(cmd: string, cwd: string, timeout = 90000) {
  return execAsync(cmd, { cwd, timeout });   // promisify(child_process.exec)
}

await this.runCommand(`git clone --depth 1 ${branchArg} ${cloneUrl} .`, workspacePath, 90000);
```

`child_process.exec` выполняет команду через оболочку — это эквивалент
`shell=True`. В строку подставляются:

* `cloneUrl`, содержащий `repo.fullName` и OAuth-токен;
* `branchArg`, содержащий `targetBranch`.

Оба значения происходят из базы данных. `repo.fullName` попадает туда из ответа
GitHub API либо из параметра `?repository=owner/name` эндпоинта `/api/ci/scan`,
где выполняется только разбиение по `/` без проверки допустимых символов.
`targetBranch` приходит из тела `POST /api/scans` либо из webhook.

Две проблемы:

1. **Потенциальная инъекция в команду оболочки** при имени ветки или репозитория,
   содержащем метасимволы оболочки.
2. **Раскрытие токена.** OAuth-токен GitHub попадает в командную строку и виден в
   списке процессов хоста, а при ошибке — в тексте исключения.

Статус: **security gap**. Исправление:

```ts
// вместо exec со строкой
await execFileAsync('git', ['clone', '--depth', '1', '--branch', targetBranch, cloneUrl, '.'],
                    { cwd: workspacePath, timeout: 90000 });
```

Токен следует передавать через заголовок (`git -c http.extraHeader=…`) или через
`credential helper`, а не в составе URL. Дополнительно — проверять `fullName`
регулярным выражением `^[\w.-]+/[\w.-]+$` и имя ветки — на отсутствие
метасимволов.

---

## Обращение с секретами

### Секреты, найденные в проверяемом коде

| Мера | Где |
|---|---|
| Gitleaks запускается с `--redact` | [gitleaks_scanner.py](../security-engine/app/scanners/gitleaks_scanner.py) |
| Нормализатор принудительно ставит `codeSnippet: "***REDACTED***"` для находок Gitleaks | [normalizer.py](../security-engine/app/scanners/normalizer.py) |
| То же для секретов Trivy | там же |
| Встроенный резерв редактирует находки с флагом `isSecret` | [builtin-scanner.service.ts](../backend/src/scan/builtin-scanner.service.ts) |
| Содержимое файла для интерфейса проходит `redactSecrets` (8 шаблонов) | [architecture.service.ts](../backend/src/scan/architecture.service.ts) |
| Guard не печатает `codeSnippet`, равный `***REDACTED***` | [kmg-guard.mjs](../tools/git-hooks/kmg-guard.mjs) |
| `explainFinding` редактирует фрагмент перед отправкой в модель | [groq.service.ts](../backend/src/ai/groq.service.ts) |

### Учётные данные самого агента

| Мера | Где |
|---|---|
| Токен GitHub хранится зашифрованным (AES-256-CBC) | [repository.service.ts](../backend/src/repository/repository.service.ts), `decrypt` |
| Ключи Groq не логируются — только `key #N` | [groq.service.ts](../backend/src/ai/groq.service.ts) |
| Ответы об ошибках редактируются глобально | [global-exception.filter.ts](../backend/src/common/filters/global-exception.filter.ts) + [secret-redactor.ts](../backend/src/common/utils/secret-redactor.ts) |
| `SecretRedactor.redactObject` чистит поля по имени (`password`, `token`, `apiKey`, `authorization`, …) | [secret-redactor.ts](../backend/src/common/utils/secret-redactor.ts) |
| Шаблоны редактирования: GitHub, Groq, AWS, JWT, URI PostgreSQL | там же |
| Токен KMG передаётся через `git config kmg.token`, а не через окружение | [install.sh](../tools/git-hooks/install.sh) |
| `.env` в `.gitignore`, в репозитории только `.env.example` | [.gitignore](../.gitignore) |

### Пробелы

| № | Пробел | Последствие | Исправление |
|---|---|---|---|
| 1 | Окно кода при триаже (`readContext`) **не редактируется** перед отправкой в Groq — в отличие от `explainFinding` | если находка расположена рядом с жёстко зашитым секретом, значение уйдёт во внешний API | применить ту же функцию редактирования в `buildEvidence` |
| 2 | Токен GitHub попадает в командную строку `git clone` | виден в списке процессов хоста | см. раздел о запуске процессов |
| 3 | `docker-compose.yml` содержит значения по умолчанию для пароля БД, `JWT_SECRET` и `ENCRYPTION_KEY` | при развёртывании «как есть» используются известные значения | убрать значения по умолчанию, сделать переменные обязательными |
| 4 | `.env.example` содержит правдоподобные значения паролей вместо явных заглушек | провоцирует использование как есть | заменить на `<PASSWORD>`, `<SECRET>`, `<API_KEY>` |

Пробел №3 — наиболее заметный при внешней оценке: файл
[docker-compose.yml](../docker-compose.yml) задаёт конкретный пароль базы данных
как значение по умолчанию, а также фиксированные `JWT_SECRET` и `ENCRYPTION_KEY`.
Для локального запуска это удобно, для любого другого — недопустимо.

---

## Защита от инъекции промпта

Подробно — [LLM.md](LLM.md#защита-от-инъекции-промпта). Кратко:

| Мера | Состояние |
|---|---|
| Инструкции только в `role: system`, код проекта только в `role: user` | реализовано |
| Код проекта помещается в размеченный блок | реализовано |
| Объём фрагмента жёстко ограничен | реализовано |
| Ответ модели валидируется против собранных признаков | реализовано |
| Вердикт CI не зависит от ответа модели | реализовано — основная защита |
| `PromptInjectionGuard` на маршрутах `scans` и `cicd` | реализовано |
| `PromptInjectionGuard` на `/api/ci/scan` и `/api/prepush/check` | **не применён** |
| Явное указание в системном промпте, что код — данные | **отсутствует** |
| Шаблоны детектора на языках, кроме английского | **отсутствуют** |

Middleware не применён именно к тем двум маршрутам, через которые в систему
поступает недоверенный код. Для `/api/ci/scan` это отчасти объяснимо — тело
запроса бинарное, и проверка по нему бессмысленна; защиту следует переносить на
уровень содержимого промпта.

---

## Сетевое взаимодействие

| Направление | Назначение | Когда |
|---|---|---|
| `api.groq.com` | обращения к модели | при включённом AI-анализе |
| `github.com` | клонирование репозитория | при сканировании через OAuth |
| `api.github.com` | commit status, комментарии PR, Code Scanning | при CI-сканах |
| Реестр Semgrep | дополнительные наборы правил | **по умолчанию выключено** (`SEMGREP_REGISTRY_CONFIG` пусто) |
| Зеркало базы Trivy | обновление базы уязвимостей | предзагружается при сборке образа |

Проверяемый код наружу передаётся только в двух видах: как фрагменты в промптах
к Groq и как содержимое находок при выгрузке SARIF в GitHub Code Scanning.
Полностью отключить передачу можно параметром `?ai=off` у `/api/ci/scan` либо
флагом `aiAnalysis: false` в политике.

**SSRF.** Адреса внешних сервисов задаются конфигурацией
(`SECURITY_ENGINE_URL`, `KMG_API_URL`, константы Groq и GitHub) и не берутся из
проверяемого кода. Возможности заставить агент обратиться к произвольному
адресу, поместив его в проверяемый проект, не обнаружено.

---

## Изоляция

| Мера | Состояние |
|---|---|
| Рабочая область в отдельном каталоге на скан | реализовано |
| Удаление рабочей области в блоке `finally` | реализовано в `CiService` и `PrepushService` |
| Отдельный контейнер для сканеров | реализовано |
| Ограничение ресурсов контейнера (CPU, память) | **не задано** в `docker-compose.yml` |
| Запуск от непривилегированного пользователя | **не настроен** — контейнеры работают от `root` |
| `read_only` файловая система, `cap_drop` | **не настроено** |
| Сетевая изоляция движка | **не настроена** — порт 8000 опубликован наружу |

Публикация порта 8000 существенна: `POST /scan` не требует авторизации и
принимает произвольный `repository_path`. В сетевой конфигурации по умолчанию
любой, кто имеет доступ к хосту, может запустить сканирование любого каталога,
видимого контейнеру, и получить содержимое найденных фрагментов кода.

Рекомендация: убрать публикацию порта 8000 из `docker-compose.yml` — backend
обращается к движку по внутреннему имени `security-engine:8000` и во внешней
публикации не нуждается.

---

## Контроль доступа к API самого агента

| Мера | Состояние |
|---|---|
| JWT-авторизация на `/api/scans`, `/api/ci/*`, `/api/prepush/*`, `/api/dashboard`, `/api/system` | реализовано (`JwtAuthGuard`) |
| Изоляция данных по пользователю | реализовано — выборки фильтруются по `userId` |
| Проверка подписи webhook | реализовано (`GITHUB_WEBHOOK_SECRET`) |
| Ограничение частоты запросов | реализовано — `ThrottlerModule`, 100 запросов за 60 с |
| Исключение из ограничения для CI-сканов | `@SkipThrottle()` на `/api/ci/scan` — обоснованно, скан долгий |
| CORS ограничен `FRONTEND_URL` | реализовано |
| Глобальная валидация входа | реализовано — `ValidationPipe` с `whitelist` и `forbidNonWhitelisted` |
| Авторизация на `POST /scan` движка | **отсутствует** |

---

## Сводка пробелов

| № | Пробел | Критичность | Файл |
|---|---|---|---|
| 1 | `exec` со строкой при клонировании; токен в командной строке | высокая | [repository.service.ts](../backend/src/repository/repository.service.ts) |
| 2 | Порт движка опубликован наружу, `POST /scan` без авторизации | высокая | [docker-compose.yml](../docker-compose.yml) |
| 3 | Секреты по умолчанию в `docker-compose.yml` | высокая | [docker-compose.yml](../docker-compose.yml) |
| 4 | Окно кода при триаже не редактируется перед отправкой в Groq | средняя | [investigation.service.ts](../backend/src/agent/investigation.service.ts) |
| 5 | `PromptInjectionGuard` не покрывает `/api/ci/scan` и `/api/prepush/check` | средняя | [app.module.ts](../backend/src/app.module.ts) |
| 6 | Контейнеры работают от `root`, лимиты ресурсов не заданы | средняя | [docker-compose.yml](../docker-compose.yml) |
| 7 | `inspectTarGz` и `safeRelativePath` не покрыты тестами | средняя | [TESTING.md](TESTING.md) |
| 8 | В системном промпте нет явного указания, что код — данные | низкая | [LLM.md](LLM.md) |
| 9 | `.env.example` содержит правдоподобные значения вместо заглушек | низкая | [.env.example](../.env.example) |

Настоящий раздел является результатом ручного аудита кода в рамках подготовки
документации. Автоматической проверкой агента самим собой эти пробелы не
обнаруживаются: пробелы 1, 2, 3, 6 относятся к категориям, которых нет в
наборе правил, а пробел 4 является архитектурным.
