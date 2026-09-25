import asyncio
import json
import os
from typing import Dict, Any, List
from ..gitignore import GitIgnoreMatcher

# Rule sets bundled with the image: the KMG baseline plus the official
# open-source Semgrep security rules. They always work, with or without network
# access to the Semgrep registry.
_DEFAULT_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "rules"
)


def _bundled_rule_dirs():
    raw = os.environ.get("SEMGREP_RULES_DIRS") or os.environ.get("SEMGREP_RULES_DIR") or _DEFAULT_RULES_DIR
    return [d.strip() for d in raw.split(",") if d.strip()]

# Optional extra registry rulesets, e.g. "auto" or "p/default".
# Empty by default so a scan never silently depends on registry availability.
REGISTRY_CONFIG = os.environ.get("SEMGREP_REGISTRY_CONFIG", "").strip()

SEMGREP_TIMEOUT = int(os.environ.get("SEMGREP_TIMEOUT_SECONDS", "300"))
# Per-rule/per-file timeout handed to semgrep itself (seconds, 0 = no limit).
SEMGREP_RULE_TIMEOUT = os.environ.get("SEMGREP_RULE_TIMEOUT", "30")


async def _run_semgrep_config(repo_path: str, configs: List[str]) -> Dict[str, Any]:
    """
    Runs one semgrep invocation over the given --config list.

    Local rule sets are passed together so the workspace is walked once; a
    registry ruleset gets its own invocation so that its failure cannot take the
    bundled rules down with it.
    """
    config = ', '.join(configs)
    cmd = [
        'semgrep', 'scan',
        '--json',
        '-q',
        '--metrics', 'off',
        '--disable-version-check',
        '--timeout', SEMGREP_RULE_TIMEOUT,
    ]
    for cfg in configs:
        cmd += ['--config', cfg]
    cmd.append('.')                 # cwd is repo_path -> result paths are repo-relative

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return {"ok": False, "error": "Semgrep CLI not found in system PATH", "data": None}

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SEMGREP_TIMEOUT)
    except asyncio.TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
        return {
            "ok": False,
            "error": f"Semgrep timed out after {SEMGREP_TIMEOUT}s (config: {config})",
            "data": None,
        }

    stdout_str = stdout.decode('utf-8', errors='replace') if stdout else ''
    stderr_str = stderr.decode('utf-8', errors='replace') if stderr else ''

    if not stdout_str.strip():
        return {
            "ok": False,
            "error": f"Semgrep produced no output (exit code {process.returncode}, config: {config}): {stderr_str[:300]}",
            "data": None,
        }

    try:
        data = json.loads(stdout_str)
    except json.JSONDecodeError as je:
        return {
            "ok": False,
            "error": f"Invalid Semgrep JSON output (config: {config}): {je} (stderr: {stderr_str[:200]})",
            "data": None,
        }

    if not isinstance(data, dict) or 'results' not in data:
        return {
            "ok": False,
            "error": f"Unexpected Semgrep output shape (config: {config}): {stdout_str[:200]}",
            "data": None,
        }

    # Exit codes: 0 = ran cleanly, 1 = findings with --error. Anything else is a
    # real failure even if some JSON was emitted.
    if process.returncode not in (0, 1):
        fatal = _fatal_errors(data)
        detail = '; '.join(fatal) if fatal else stderr_str[:300]
        return {
            "ok": False,
            "error": f"Semgrep exited with code {process.returncode} (config: {config}): {detail}",
            "data": data,
        }

    return {"ok": True, "error": None, "data": data}


CODE_EXTENSIONS = {
    '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.go', '.java', '.rb',
    '.php', '.cs', '.c', '.cc', '.cpp', '.h', '.hpp', '.rs', '.kt', '.scala',
    '.swift', '.sh', '.bash', '.tf', '.yaml', '.yml', '.json',
}

IGNORED_DIRS = {
    '.git', 'node_modules', 'dist', 'build', '.next', 'coverage', '.cache',
    'vendor', '__pycache__', '.idea', '.vscode', '.venv', 'venv',
}


def _has_analysable_code(root: str) -> bool:
    """True when the workspace contains at least one file Semgrep could analyse."""
    matcher = GitIgnoreMatcher(root)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace('\\', '/')
        if rel_dir == '.':
            rel_dir = ''
        dirnames[:] = [
            d for d in dirnames
            if d not in IGNORED_DIRS and not matcher.is_ignored(f"{rel_dir}/{d}" if rel_dir else d)
        ]
        for name in filenames:
            rel_file = f"{rel_dir}/{name}" if rel_dir else name
            if not matcher.is_ignored(rel_file) and os.path.splitext(name)[1].lower() in CODE_EXTENSIONS:
                return True
    return False



def _fatal_errors(data: Dict[str, Any]) -> List[str]:
    """Extracts semgrep errors that mean rules did not run (config/rule load failures)."""
    messages = []
    for err in data.get('errors', []) or []:
        if not isinstance(err, dict):
            continue
        level = (err.get('level') or '').lower()
        err_type = err.get('type')
        if isinstance(err_type, dict):
            err_type = err_type.get('type') or str(err_type)
        err_type = str(err_type or '')
        # Per-file parse errors are normal on mixed repos; config/rule errors are not.
        if level in ('error', 'fatal') and 'parse' not in err_type.lower():
            messages.append(f"{err_type}: {(err.get('message') or '')[:200]}")
    return messages


async def run_semgrep(repo_path: str) -> Dict[str, Any]:
    """
    Runs Semgrep over the workspace.

    Status contract (consumed by the policy engine):
      COMPLETED - semgrep really executed and really analysed files
      FAILED    - semgrep could not run, crashed, timed out, or analysed 0 files

    "0 findings" is only reported as COMPLETED when semgrep demonstrably scanned
    source files, so a broken scanner can never turn into a PASS verdict.
    """
    if not os.path.isdir(repo_path):
        return {"status": "FAILED", "data": {"results": []}, "error": f"Workspace path not found: {repo_path}"}

    bundled = [d for d in _bundled_rule_dirs() if os.path.isdir(d)]
    missing = [d for d in _bundled_rule_dirs() if not os.path.isdir(d)]

    # One group = one semgrep process. All bundled rule dirs share a process.
    config_groups: List[List[str]] = []
    if bundled:
        config_groups.append(bundled)
    if REGISTRY_CONFIG:
        config_groups.extend([[c.strip()] for c in REGISTRY_CONFIG.split(',') if c.strip()])

    if not config_groups:
        return {
            "status": "FAILED",
            "data": {"results": []},
            "error": f"No Semgrep ruleset available (missing rule directories: {', '.join(missing) or 'none configured'})",
        }

    merged_results: List[Any] = []
    scanned_paths: set = set()
    warnings: List[str] = []
    any_ok = False
    primary_error = None

    if missing:
        warnings.append(f"Configured rule directories not found: {', '.join(missing)}")

    for idx, group in enumerate(config_groups):
        res = await _run_semgrep_config(repo_path, group)
        data = res.get("data") or {}
        config = ', '.join(group)

        if res["ok"]:
            any_ok = True
            merged_results.extend(data.get('results', []) or [])
            for p in (data.get('paths', {}) or {}).get('scanned', []) or []:
                scanned_paths.add(p)
            fatal = _fatal_errors(data)
            if fatal:
                warnings.append(f"{config}: {'; '.join(fatal[:3])}")
        else:
            if idx == 0:
                primary_error = res["error"]
            else:
                warnings.append(res["error"])

    if not any_ok:
        return {
            "status": "FAILED",
            "data": {"results": []},
            "error": primary_error or '; '.join(warnings) or "Semgrep failed for every configured ruleset",
        }

    if not scanned_paths:
        # Analysing nothing is only acceptable when there was nothing to analyse.
        # If the workspace does hold source files, semgrep silently skipped them
        # and the run must not be read as "no vulnerabilities".
        if _has_analysable_code(repo_path):
            return {
                "status": "FAILED",
                "data": {"results": merged_results},
                "error": (
                    "Semgrep ran but analysed 0 of the repository's source files — the result "
                    "cannot be interpreted as 'no vulnerabilities'. "
                    + ('; '.join(warnings) if warnings else '')
                ).strip(),
            }

        warnings.append("Repository contains no files supported by Semgrep — SAST coverage is empty")

    return {
        "status": "COMPLETED",
        "data": {"results": merged_results, "paths": {"scanned": sorted(scanned_paths)}},
        "error": '; '.join(warnings) if warnings else None,
        "filesScanned": len(scanned_paths),
    }
