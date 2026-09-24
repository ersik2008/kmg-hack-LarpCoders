# KMG local security feedback

Локальные Git-хуки дают разработчику быстрый результат, но **никогда не блокируют**
`git commit` или `git push`. Security verdict остаётся реальным (`PASS`, `REVIEW`,
`BLOCK` или `INCOMPLETE`); меняется только точка enforcement.

```
LOCAL DEVELOPER MACHINE                    GITHUB CI / PR CHECK
──────────────────────                    ────────────────────
pre-commit → scan → advisory → commit     scan → policy → required check
pre-push   → scan → advisory → push       BLOCK/INCOMPLETE → job failure → merge blocked
```

Local hooks provide immediate feedback without blocking developer workflow.
CI is the authoritative enforcement point. GitHub branch protection must make the
KMG AI Security check required before merge.

При локальном `BLOCK` хук показывает findings, `Security policy: BLOCK` и сообщает,
что push/commit разрешён. CI/GitHub применяет тот же policy verdict и останавливает
build/merge до исправления проблем. Сканеры Semgrep, Gitleaks и Trivy, Policy Engine,
scan records и findings не отключаются и не подменяются `PASS`.

## Что именно проверяется

Хук берёт **точное содержимое blob-ов, которые git собирается отправить**
(`git show <sha>:<path>`), а не рабочую копию. То есть проверяется ровно тот код,
который попадёт в репозиторий.

* новая ветка на remote → все файлы новых коммитов;
* существующая ветка → `git diff <remote_sha>..<local_sha>`;
* `pre-commit` → содержимое индекса (`git show :<path>`).

Бинарные файлы и файлы больше `KMG_MAX_FILE_KB` пропускаются.

## Установка

```sh
# 1. Установить хуки в нужный репозиторий
./tools/git-hooks/install.sh /path/to/your/repo

# 2. Указать токен сессии KMG (Настройки → Security → «Проверка до push»)
git -C /path/to/your/repo config --local kmg.token  <TOKEN>
git -C /path/to/your/repo config --local kmg.apiurl http://localhost:3000/api
```

Существующие хуки сохраняются как `<hook>.kmg-backup`.

Требования: Node.js 18+ в `PATH` и запущенный backend KMG.

## Поведение

| Ситуация | pre-push | pre-commit | CI / GitHub Check |
|---|---|---|---|
| Критическая уязвимость (вердикт `BLOCK`) | warning, push разрешён | warning, commit разрешён | job failure, merge blocked |
| `REVIEW` / некритичные находки | warning, push разрешён | warning, commit разрешён | применяется policy repository |
| Уязвимостей нет (`PASS`) | push разрешён | commit разрешён | check successful |
| Сканер упал / backend недоступен | warning, push разрешён | warning, commit разрешён | fail-closed (`KMG_FAIL_OPEN=0`), job failure |

`KMG_FAIL_OPEN` не делает локальные hooks advisory — они advisory независимо от этой
настройки. Этот флаг сохраняет прежний смысл только для CI: `1` явно разрешает build,
если scan вообще не удалось выполнить; он не меняет `BLOCK` на `PASS` и не разрешает
CI при полученном `BLOCK`.

## Настройки

Читаются в порядке: переменная окружения → `git config` → `.kmg.json` в корне репозитория.

| env | git config | по умолчанию | назначение |
|---|---|---|---|
| `KMG_API_URL` | `kmg.apiurl` | `http://localhost:3000/api` | адрес backend |
| `KMG_TOKEN` | `kmg.token` | — | токен сессии KMG (обязателен) |
| `KMG_REPOSITORY` | `kmg.repository` | из URL remote | `owner/name` для привязки результата |
| `KMG_BLOCK_ON` | `kmg.blockon` | вердикт политики | `CRITICAL` / `HIGH` / `ANY` |
| `KMG_FAIL_OPEN` | `kmg.failopen` | `0` | `1` — разрешить CI build, если scan не выполнился; не влияет на local advisory |
| `KMG_MAX_FILES` | `kmg.maxfiles` | `400` | максимум файлов в одной проверке |
| `KMG_MAX_FILE_KB` | `kmg.maxfilekb` | `512` | максимальный размер файла |
| `KMG_TIMEOUT_MS` | `kmg.timeoutms` | `300000` | таймаут запроса |
| `KMG_GUARD_PATH` | `kmg.guardpath` | `<repo>/tools/git-hooks/kmg-guard.mjs` | путь к скрипту |

## CI integration and branch protection

GitHub Action/composite action запускает `node tools/git-hooks/kmg-guard.mjs ci`.
В этом mode `BLOCK`, `INCOMPLETE`, failed scanner или unavailable backend завершаются
кодом `1`, когда `KMG_FAIL_OPEN=0`. GitHub Check содержит verdict, risk score, counts
по CRITICAL/HIGH/MEDIUM/LOW, scanner status, policy reasons и SARIF report.

В branch protection добавьте KMG security check в required checks. Так feature branch
можно push-ить для совместной работы, но PR с `BLOCK` не будет смержен.

## Удаление

```sh
rm .git/hooks/pre-push .git/hooks/pre-commit
# при наличии: mv .git/hooks/pre-push.kmg-backup .git/hooks/pre-push
```
