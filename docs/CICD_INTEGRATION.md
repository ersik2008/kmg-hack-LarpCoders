# Интеграция KMG AI в CI/CD

Проверка безопасности встраивается в процесс разработки на трёх уровнях. Все три
используют один и тот же движок (Semgrep + Gitleaks + Trivy) и одну и ту же
политику, поэтому локальный результат и результат в CI совпадают.

```
 разработчик                     CI/CD                        GitHub
 ───────────                     ─────                        ──────
 git commit ──► pre-commit  (только предупреждение, exit 0)
 git push   ──► pre-push    (только предупреждение, exit 0)
                                 │
                                 ├─► workflow ──► POST /api/ci/scan ──► SARIF
                                 │                (весь репозиторий)     │
                                 │                                       ├─► вкладка Security
                                 │                                       ├─► комментарий в PR
                                 │                                       └─► exit 1 при BLOCK
                                 │
                                 └─► webhook ──► скан ──► commit status
                                                          + branch protection
```

**Самый простой путь** — раздел 2: положить один YML-файл в репозиторий и задать
два секрета. Ни webhook, ни публичный адрес KMG для этого не нужны.
См. [CI_API.md](CI_API.md).

---

## 1. Локально: git-хуки

Единственное место, где проверка происходит **до** попадания кода в репозиторий.
См. [tools/git-hooks/README.md](../tools/git-hooks/README.md).

> **Хуки не блокируют работу.** Они показывают находки и вердикт политики, но
> всегда завершаются кодом 0 — и при `BLOCK`, и при недоступном backend.
> Обязательным контрольным шагом является CI: там тот же код выполняется в
> режиме `ci` и при `BLOCK` или незавершённой проверке возвращает 1. Реализация —
> функция `enforcementMode` в
> [kmg-guard.mjs](../tools/git-hooks/kmg-guard.mjs), поведение закреплено тестами
> 1–6 и 12 в [kmg-guard.test.mjs](../tools/git-hooks/kmg-guard.test.mjs).
> Подробнее — [CI_CD.md](CI_CD.md#локальный-режим-разработчика).

```sh
./tools/git-hooks/install.sh /path/to/your/repo
git -C /path/to/your/repo config --local kmg.token <TOKEN>
```

---

## 2. GitHub Actions — решение «под ключ»

Самодостаточный workflow, который кладётся в любой репозиторий: упаковывает код,
отправляет на `/api/ci/scan`, получает SARIF и публикует его в GitHub.
Полное описание — [CI_API.md](CI_API.md), готовый файл —
[`examples/ai-security.yml`](../examples/ai-security.yml).

```yaml
name: AI Security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
  pull-requests: write
# ... далее по файлу examples/ai-security.yml
```

Нужны только два секрета в репозитории: `KMG_API_URL` и `KMG_TOKEN`.

### Вариант через composite action (по изменённым файлам)

Проверяет не весь репозиторий, а дифф — быстрее, но без полного AI-разбора.

### Готовый Action

В репозиторий, который нужно проверять, добавьте workflow:

```yaml
name: Security
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # нужен базовый коммит для диффа

      - uses: <owner>/kmg@main    # этот репозиторий
        with:
          api-url: ${{ secrets.KMG_API_URL }}
          token:   ${{ secrets.KMG_TOKEN }}
          block-on: policy        # вердикт из настроек KMG
```

Результат:

* **exit 1** при вердикте `BLOCK` — сборка падает, PR нельзя слить, если
  проверка включена в branch protection;
* **Job Summary** — таблица находок с файлом, строкой, severity и сканером;
* **outputs** — `verdict`, `critical`, `high`, `blocked`, `report`;
* **kmg-scan-report.json** — полный отчёт для артефактов.

### Параметры

| Вход | По умолчанию | Назначение |
|---|---|---|
| `api-url` | — | адрес KMG API |
| `token` | — | токен сессии KMG (только через secrets) |
| `block-on` | `policy` | `policy` / `CRITICAL` / `HIGH` / `ANY` |
| `fail-open` | `false` | `true` — не валить сборку, если проверка не выполнилась |
| `paths` | `changed` | `changed` (дифф) или `all` (весь репозиторий) |
| `max-files` | `400` | лимит файлов на одну проверку |

### Использование outputs

```yaml
      - uses: <owner>/kmg@main
        id: security
        with:
          api-url: ${{ secrets.KMG_API_URL }}
          token:   ${{ secrets.KMG_TOKEN }}
          fail-open: 'true'       # не валим сборку, решаем сами

      - name: Заблокировать релиз при критических находках
        if: steps.security.outputs.critical != '0'
        run: exit 1

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: ${{ steps.security.outputs.report }}
```

---

## 3. GitHub webhook → статус на коммите

Этот путь не требует изменений в проверяемом репозитории: KMG сам реагирует на
события и публикует вердикт обратно в GitHub.

### Настройка

1. Откройте в KMG страницу «Репозитории» — список подтягивается из GitHub автоматически.
2. В GitHub: **Settings → Webhooks → Add webhook**
   * Payload URL: `https://<ваш-kmg>/api/cicd/webhook/github`
   * Content type: `application/json`
   * Secret: значение `GITHUB_WEBHOOK_SECRET` из `.env`
   * События: **Pushes** и **Pull requests**
3. Чтобы блокировать слияние: **Settings → Branches → Branch protection rule** →
   *Require status checks to pass* → отметить **`KMG AI / security-gate`**.

### Что происходит

| Событие | Действие |
|---|---|
| `push` в ветку из `CICD_BRANCHES` | запускается скан, на коммит публикуется статус |
| `pull_request` (opened / synchronize / reopened) | сканируется head PR, публикуется статус **и** комментарий с таблицей находок |

Состояния статуса `KMG AI / security-gate`:

| Состояние | Когда |
|---|---|
| `pending` | скан запущен |
| `success` | вердикт `PASS` или `REVIEW` |
| `failure` | вердикт `BLOCK` — критические уязвимости |
| `error` | скан не завершился — **вердикт не вынесен** |

`error` — принципиальный случай: «проверку выполнить не удалось» не равно
«уязвимостей нет», поэтому такой коммит тоже не проходит gate.

### Переменные

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `GITHUB_WEBHOOK_SECRET` | — | подпись webhook (HMAC SHA-256) |
| `CICD_BRANCHES` | `main,master,develop` | ветки, для которых запускается скан по push |

---

## 4. SARIF и GitHub Code Scanning

Находки выгружаются в **SARIF 2.1.0** — формат, который понимают все инструменты
анализа кода. GitHub принимает его в Code Scanning: находки появляются во
вкладке **Security** репозитория, размечаются прямо на строках изменённых
файлов, а историю и снятие с контроля GitHub ведёт сам.

### Из интерфейса

На странице скана — кнопки **SARIF** (скачать файл) и **В GitHub Security**
(опубликовать во вкладку Security).

### Из CI

GitHub Action делает это сам: `kmg-guard.mjs ci` пишет `kmg-results.sarif`, а
шаг `github/codeql-action/upload-sarif` его публикует. Нужно только дать права:

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # обязательно для выгрузки SARIF
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: <owner>/kmg@main
        with:
          api-url: ${{ secrets.KMG_API_URL }}
          token:   ${{ secrets.KMG_TOKEN }}
          upload-sarif: 'true'      # по умолчанию уже true
```

### Через webhook

Скан, запущенный webhook-ом, выгружает SARIF автоматически — дополнительно
настраивать нечего.

### Что попадает в отчёт

| Источник | Уровень в GitHub |
|---|---|
| CRITICAL / HIGH находки | `error` (security-severity 9.5 / 7.5) |
| MEDIUM | `warning` (5.0) |
| LOW / INFO | `note` (3.0 / 1.0) |
| Нереализованная функция ИБ | `warning` (6.0) |
| Частично реализованная функция ИБ | `note` (4.0) |

Функции ИБ попадают в отчёт **только с подтверждением из кода**: Code Scanning
требует ссылку на файл и строку, а придумывать её нельзя.

Каждая находка несёт `partialFingerprints`, поэтому GitHub отслеживает её между
сканами, а не заводит заново на каждом прогоне.

### Требуемые права

| Путь | Что нужно |
|---|---|
| GitHub Action | `permissions: security-events: write` в workflow |
| Кнопка в UI / webhook | OAuth-право `security_events` |

Право `security_events` добавлено в запрос авторизации. **Аккаунты, вошедшие
раньше, его не имеют** — выгрузка вернёт понятную ошибку с просьбой войти
заново. Для приватных репозиториев Code Scanning требует GitHub Advanced
Security.

---

## 5. Другие CI (GitLab CI, Jenkins, Azure DevOps)

Тот же скрипт работает в любом CI — нужен только Node.js 18+ и доступ к KMG API.

### GitLab CI

```yaml
security:
  image: node:20
  script:
    - git fetch --deepen=50 || true
    - node tools/git-hooks/kmg-guard.mjs ci
  variables:
    KMG_API_URL: "$KMG_API_URL"
    KMG_TOKEN: "$KMG_TOKEN"
    KMG_BASE_REF: "$CI_MERGE_REQUEST_DIFF_BASE_SHA"
    KMG_HEAD_REF: "$CI_COMMIT_SHA"
  artifacts:
    when: always
    paths: [kmg-scan-report.json]
```

### Jenkins

```groovy
stage('Security') {
  steps {
    withCredentials([string(credentialsId: 'kmg-token', variable: 'KMG_TOKEN')]) {
      sh '''
        export KMG_API_URL=https://kmg.example.com/api
        export KMG_BASE_REF=$GIT_PREVIOUS_SUCCESSFUL_COMMIT
        export KMG_HEAD_REF=$GIT_COMMIT
        node tools/git-hooks/kmg-guard.mjs ci
      '''
    }
  }
}
```

Ненулевой код возврата останавливает сборку в любой из этих систем.

---

## Принцип, общий для всех уровней

Проверка, которая **не выполнилась**, никогда не считается пройденной. Недоступный
backend, упавший сканер, пустой workspace — всё это даёт `INCOMPLETE`, а не `PASS`,
и останавливает конвейер. Обойти можно только осознанно: `git push --no-verify`
или `fail-open: true`.
