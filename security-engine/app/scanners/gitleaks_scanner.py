import asyncio
import json
import os
import tempfile
from typing import Dict, Any

GITLEAKS_TIMEOUT = int(os.environ.get("GITLEAKS_TIMEOUT_SECONDS", "180"))


async def run_gitleaks(repo_path: str) -> Dict[str, Any]:
    """
    Runs Gitleaks over the workspace files.

    Status contract:
      COMPLETED - gitleaks executed and produced a parsable report
      FAILED    - binary missing, crashed, timed out, or wrote no report at all

    Gitleaks ships its rules inside the binary, so this scanner works offline.
    """
    if not os.path.isdir(repo_path):
        return {"status": "FAILED", "data": [], "error": f"Workspace path not found: {repo_path}"}

    report_path = None
    process = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            report_path = tmp.name

        # --no-git: the workspace is a shallow clone / materialised file set, so
        # scan the files on disk rather than commit history.
        # cwd = repo_path and --source '.' keep reported paths repo-relative.
        process = await asyncio.create_subprocess_exec(
            'gitleaks', 'detect',
            '--source', '.',
            '--report-format', 'json',
            '--report-path', report_path,
            '--no-git',
            '--redact',
            '--exit-code', '1',
            cwd=repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=GITLEAKS_TIMEOUT)
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
            return {
                "status": "FAILED",
                "data": [],
                "error": f"Gitleaks timed out after {GITLEAKS_TIMEOUT}s",
            }

        stderr_str = stderr.decode('utf-8', errors='replace') if stderr else ''

        # Exit code 0: no leaks. 1: leaks found. >=2: fatal error.
        if process.returncode not in (0, 1):
            return {
                "status": "FAILED",
                "data": [],
                "error": f"Gitleaks failed with exit code {process.returncode}: {stderr_str[:300]}",
            }

        if not os.path.exists(report_path):
            return {
                "status": "FAILED",
                "data": [],
                "error": "Gitleaks exited successfully but wrote no report file — result cannot be trusted",
            }

        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()

        if not content:
            # Gitleaks writes an empty file when there is nothing to report.
            results = []
        else:
            try:
                results = json.loads(content)
            except json.JSONDecodeError as je:
                return {
                    "status": "FAILED",
                    "data": [],
                    "error": f"Failed to parse Gitleaks JSON report: {je}",
                }

        if results is None:
            results = []

        if not isinstance(results, list):
            return {
                "status": "FAILED",
                "data": [],
                "error": f"Unexpected Gitleaks report shape: {type(results).__name__}",
            }

        from ..gitignore import GitIgnoreMatcher
        matcher = GitIgnoreMatcher(repo_path)
        filtered_results = [
            r for r in results
            if isinstance(r, dict) and not matcher.is_ignored(r.get('File', ''))
        ]

        return {"status": "COMPLETED", "data": filtered_results, "error": None}


    except FileNotFoundError:
        return {"status": "FAILED", "data": [], "error": "Gitleaks CLI not found in system PATH"}
    except Exception as e:
        return {"status": "FAILED", "data": [], "error": f"Gitleaks execution error: {e}"}
    finally:
        if report_path and os.path.exists(report_path):
            try:
                os.remove(report_path)
            except Exception:
                pass
