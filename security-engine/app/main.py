from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import asyncio
import hmac
import logging
import os
import shutil
import time
from .scanners.semgrep_scanner import run_semgrep
from .scanners.gitleaks_scanner import run_gitleaks
from .scanners.trivy_scanner import run_trivy
from .scanners.normalizer import normalize_semgrep, normalize_gitleaks, normalize_trivy

app = FastAPI(title="KMG Security Engine API")

# --- Доступ к движку ---------------------------------------------------------
#
# POST /scan принимает произвольный repository_path и возвращает фрагменты
# найденного кода. Без ограничений любой, кто достучится до порта, мог бы
# просканировать любой каталог, видимый контейнеру. Поэтому:
#
#   1. ENGINE_TOKEN: если задан, запрос без верного заголовка X-Engine-Token
#      отклоняется (401). Если не задан — прежний открытый режим для локальной
#      разработки; в лог при старте пишется предупреждение.
#   2. ENGINE_ALLOWED_ROOT: сканировать можно только каталоги внутри этого корня
#      (по умолчанию — общий том рабочих областей). Значение «*» отключает
#      проверку и допустимо только в изолированной среде CI.
ENGINE_TOKEN = os.environ.get("ENGINE_TOKEN", "").strip()
ALLOWED_ROOT = os.environ.get("ENGINE_ALLOWED_ROOT", "/tmp/kmg_workspaces").strip()

_log = logging.getLogger("uvicorn.error")
if not ENGINE_TOKEN:
    _log.warning(
        "ENGINE_TOKEN не задан: POST /scan доступен без авторизации. Допустимо только для "
        "локальной разработки; при любом другом развёртывании задайте ENGINE_TOKEN."
    )
if ALLOWED_ROOT == "*":
    _log.warning("ENGINE_ALLOWED_ROOT=*: ограничение каталогов отключено.")


def require_engine_token(x_engine_token: Optional[str] = Header(default=None)) -> None:
    if not ENGINE_TOKEN:
        return
    # compare_digest: сравнение за постоянное время, без утечки по таймингу.
    if not x_engine_token or not hmac.compare_digest(x_engine_token, ENGINE_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid or missing engine token")


def path_is_allowed(path: str) -> bool:
    if ALLOWED_ROOT == "*":
        return True
    # realpath раскрывает симлинки и «..»: иначе /tmp/kmg_workspaces/../../etc проходил бы.
    real = os.path.realpath(path)
    root = os.path.realpath(ALLOWED_ROOT)
    return real == root or real.startswith(root.rstrip(os.sep) + os.sep)

IGNORED_DIRS = {
    '.git', 'node_modules', 'dist', 'build', '.next', 'coverage',
    '.cache', 'vendor', '__pycache__', '.idea', '.vscode', '.venv', 'venv',
}


ALL_SCANNERS = ("semgrep", "gitleaks", "trivy")


class ScanRequest(BaseModel):
    repository_path: str
    scan_id: str
    # Which scanners to run. Omitted -> all of them. A scanner left out here is
    # reported as SKIPPED (deliberately not run), never as COMPLETED with zero
    # findings, so the policy engine can tell "clean" from "not checked".
    scanners: Optional[List[str]] = None


def count_source_files(root: str) -> int:
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        total += len(filenames)
    return total


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "security-engine",
        "tools": {
            "semgrep": tool_available("semgrep"),
            "gitleaks": tool_available("gitleaks"),
            "trivy": tool_available("trivy"),
        },
    }


@app.post("/scan", dependencies=[Depends(require_engine_token)])
async def full_scan(request: ScanRequest):
    repo_path = request.repository_path

    if not path_is_allowed(repo_path):
        # Один и тот же ответ для «нет такого каталога» и «каталог вне корня»
        # раскрывал бы существование путей вне разрешённой области.
        raise HTTPException(status_code=403, detail="Repository path is outside the allowed workspace root")

    if not os.path.isdir(repo_path):
        raise HTTPException(status_code=404, detail=f"Repository path not found: {repo_path}")

    files_count = count_source_files(repo_path)
    if files_count == 0:
        # An empty workspace can never produce a trustworthy "no findings" result.
        raise HTTPException(
            status_code=422,
            detail=f"Workspace '{repo_path}' contains no files to scan",
        )

    try:
        start_time = time.time()

        requested = (
            {s.strip().lower() for s in request.scanners if s and s.strip()}
            if request.scanners is not None
            else set(ALL_SCANNERS)
        )

        async def skipped():
            return {"status": "SKIPPED", "data": None, "error": "Disabled in the active policy"}

        # Scanners are independent: run them concurrently so one slow tool does
        # not push the whole request past the backend's HTTP timeout.
        semgrep_res, gitleaks_res, trivy_res = await asyncio.gather(
            run_semgrep(repo_path) if "semgrep" in requested else skipped(),
            run_gitleaks(repo_path) if "gitleaks" in requested else skipped(),
            run_trivy(repo_path) if "trivy" in requested else skipped(),
            return_exceptions=True,
        )

        def unwrap(result, name, empty):
            # A crashing scanner coroutine must surface as FAILED, never as "no findings".
            if isinstance(result, BaseException):
                return {"status": "FAILED", "data": empty, "error": f"{name} crashed: {result}"}
            return result

        semgrep_res = unwrap(semgrep_res, "Semgrep", {"results": []})
        gitleaks_res = unwrap(gitleaks_res, "Gitleaks", [])
        trivy_res = unwrap(trivy_res, "Trivy", {})

        # Normalize findings for completed scanners only
        semgrep_findings = []
        if semgrep_res.get("status") == "COMPLETED":
            semgrep_findings = normalize_semgrep(semgrep_res.get("data", {}), request.scan_id, repo_path)

        gitleaks_findings = []
        if gitleaks_res.get("status") == "COMPLETED":
            gitleaks_findings = normalize_gitleaks(gitleaks_res.get("data", []), request.scan_id, repo_path)

        trivy_findings = []
        if trivy_res.get("status") == "COMPLETED":
            trivy_findings = normalize_trivy(trivy_res.get("data", {}), request.scan_id, repo_path)

        all_findings = []
        all_findings.extend(semgrep_findings)
        all_findings.extend(gitleaks_findings)
        all_findings.extend(trivy_findings)

        statuses = [
            res.get("status")
            for name, res in (("semgrep", semgrep_res), ("gitleaks", gitleaks_res), ("trivy", trivy_res))
            if name in requested
        ]
        if statuses and all(s == "COMPLETED" for s in statuses):
            overall_status = "success"
        elif any(s == "COMPLETED" for s in statuses):
            overall_status = "partial"
        else:
            overall_status = "failed"

        return {
            "status": overall_status,
            "duration_ms": int((time.time() - start_time) * 1000),
            "filesCount": files_count,
            "repositoryPath": repo_path,
            "scanners": {
                "semgrep": {
                    "status": semgrep_res.get("status"),
                    "findingsCount": len(semgrep_findings),
                    "filesScanned": semgrep_res.get("filesScanned"),
                    "error": semgrep_res.get("error"),
                },
                "gitleaks": {
                    "status": gitleaks_res.get("status"),
                    "findingsCount": len(gitleaks_findings),
                    "error": gitleaks_res.get("error"),
                },
                "trivy": {
                    "status": trivy_res.get("status"),
                    "findingsCount": len(trivy_findings),
                    "error": trivy_res.get("error"),
                },
            },
            "findings": all_findings,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
