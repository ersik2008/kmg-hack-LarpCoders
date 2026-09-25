import asyncio
import json
import os
import tempfile
from typing import Dict, Any

TRIVY_TIMEOUT = int(os.environ.get("TRIVY_TIMEOUT_SECONDS", "300"))
TRIVY_SCANNERS = os.environ.get("TRIVY_SCANNERS", "vuln,misconfig,secret")
TRIVY_CACHE_DIR = os.environ.get("TRIVY_CACHE_DIR", "/root/.cache/trivy")


async def run_trivy(repo_path: str) -> Dict[str, Any]:
    """
    Runs Trivy filesystem scan (dependencies + misconfiguration).

    Status contract:
      COMPLETED - trivy executed and produced a parsable report
      FAILED    - binary missing, DB unavailable, crashed, timed out, or no report

    Trivy needs its vulnerability DB: when it cannot be downloaded the scanner
    reports FAILED instead of an empty (and misleading) result set.
    """
    if not os.path.isdir(repo_path):
        return {"status": "FAILED", "data": {}, "error": f"Workspace path not found: {repo_path}"}

    report_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            report_path = tmp.name

        cmd = [
            'trivy', 'fs',
            '--format', 'json',
            '--output', report_path,
            '--scanners', TRIVY_SCANNERS,
            '--cache-dir', TRIVY_CACHE_DIR,
            '--timeout', f'{TRIVY_TIMEOUT}s',
            '--no-progress',
            '-q',
            '.',                 # cwd is repo_path -> targets are repo-relative
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return {"status": "FAILED", "data": {}, "error": "Trivy CLI not found in system PATH"}

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=TRIVY_TIMEOUT + 30)
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
            return {
                "status": "FAILED",
                "data": {},
                "error": f"Trivy timed out after {TRIVY_TIMEOUT}s",
            }

        stderr_str = stderr.decode('utf-8', errors='replace') if stderr else ''

        if process.returncode != 0:
            return {
                "status": "FAILED",
                "data": {},
                "error": f"Trivy failed with exit code {process.returncode}: {stderr_str[:300]}",
            }

        if not os.path.exists(report_path):
            return {
                "status": "FAILED",
                "data": {},
                "error": "Trivy exited successfully but wrote no report file — result cannot be trusted",
            }

        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()

        if not content:
            return {
                "status": "FAILED",
                "data": {},
                "error": "Trivy wrote an empty report — result cannot be interpreted as 'no vulnerabilities'",
            }

        try:
            results = json.loads(content)
        except json.JSONDecodeError as je:
            return {"status": "FAILED", "data": {}, "error": f"Failed to parse Trivy JSON output: {je}"}

        if not isinstance(results, dict):
            return {
                "status": "FAILED",
                "data": {},
                "error": f"Unexpected Trivy report shape: {type(results).__name__}",
            }

        from ..gitignore import GitIgnoreMatcher
        matcher = GitIgnoreMatcher(repo_path)
        if isinstance(results.get('Results'), list):
            results['Results'] = [
                res for res in results['Results']
                if isinstance(res, dict) and not matcher.is_ignored(res.get('Target', ''))
            ]

        return {"status": "COMPLETED", "data": results, "error": None}


    except Exception as e:
        return {"status": "FAILED", "data": {}, "error": f"Trivy execution error: {e}"}
    finally:
        if report_path and os.path.exists(report_path):
            try:
                os.remove(report_path)
            except Exception:
                pass
