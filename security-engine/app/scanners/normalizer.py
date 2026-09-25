import os

ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

# Recent Semgrep releases redact the matched source lines in JSON output and
# emit this placeholder instead. Findings must still show the real code, so the
# lines are read back from the workspace.
SEMGREP_REDACTED_LINES = {"requires login", "requires login to view", ""}


def _read_source_lines(repo_path: str, rel_path: str, start, end, context: int = 0) -> str:
    if not repo_path or not rel_path or not start:
        return ""
    try:
        full = os.path.join(repo_path, rel_path)
        if not os.path.isfile(full):
            return ""
        with open(full, 'r', encoding='utf-8', errors='replace') as fh:
            lines = fh.read().splitlines()
        first = max(0, int(start) - 1 - context)
        last = min(len(lines), int(end or start) + context)
        return "\n".join(lines[first:last])[:2000]
    except Exception:
        return ""



def _rel_path(raw_path, repo_path: str = "") -> str:
    """
    Normalises a scanner-reported path to a repository-relative POSIX path.

    Scanners are invoked with cwd=<workspace> and target '.', but some still
    report absolute paths or a './' prefix. Findings must carry repo-relative
    paths, otherwise the UI cannot open the file and the pre-push hook cannot
    map a finding back to a source line.
    """
    if not raw_path:
        return ""

    path = str(raw_path).replace("\\", "/")

    if repo_path:
        base = str(repo_path).replace("\\", "/").rstrip("/")
        if base and path.startswith(base + "/"):
            path = path[len(base) + 1:]
        elif base and path == base:
            return ""

    while path.startswith("./"):
        path = path[2:]

    return path.lstrip("/")


def _safe_line(value):
    try:
        line = int(value)
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def normalize_semgrep(raw_data: dict, scan_id: str, repo_path: str = "") -> list:
    findings = []
    results = (raw_data or {}).get('results', []) or []
    matcher = None
    if repo_path and os.path.isdir(repo_path):
        from ..gitignore import GitIgnoreMatcher
        matcher = GitIgnoreMatcher(repo_path)

    # Semgrep rule severity -> KMG scale. Rules may pin an explicit KMG severity
    # through metadata.kmg_severity (bundled ruleset does this for RCE/SQLi/...).
    severity_map = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }

    for r in results:
        rel_path = _rel_path(r.get('path'), repo_path)
        if matcher and matcher.is_ignored(rel_path):
            continue

        extra = r.get('extra', {}) or {}
        metadata = extra.get('metadata', {}) or {}

        declared = str(metadata.get('kmg_severity') or '').upper()
        if declared in ALLOWED_SEVERITIES:
            severity = declared
        else:
            severity = severity_map.get(str(extra.get('severity', 'WARNING')).upper(), 'MEDIUM')

        confidence = str(metadata.get('confidence') or 'HIGH').upper()
        if confidence not in {"HIGH", "MEDIUM", "LOW"}:
            confidence = "HIGH"

        message = (extra.get('message') or '').strip()
        rule_id = r.get('check_id') or 'semgrep-rule'
        title = message.split('\n')[0][:120] or rule_id

        description_parts = [message]
        if metadata.get('cwe'):
            cwe = metadata['cwe']
            description_parts.append(f"CWE: {', '.join(cwe) if isinstance(cwe, list) else cwe}")
        if metadata.get('owasp'):
            owasp = metadata['owasp']
            description_parts.append(f"OWASP: {', '.join(owasp) if isinstance(owasp, list) else owasp}")

        start_line = _safe_line((r.get('start') or {}).get('line'))
        end_line = _safe_line((r.get('end') or {}).get('line'))

        snippet = (extra.get('lines') or '').strip()
        if snippet.lower() in SEMGREP_REDACTED_LINES:
            snippet = _read_source_lines(repo_path, rel_path, start_line, end_line)
        snippet = snippet[:2000]

        findings.append({
            "scanner": "semgrep",
            "ruleId": rule_id,
            "severity": severity,
            "confidence": confidence,
            "title": title,
            "description": "\n".join(p for p in description_parts if p),
            "filePath": rel_path,
            "startLine": start_line,
            "endLine": end_line,
            "codeSnippet": snippet,
            "scanId": scan_id,
        })
    return findings


def normalize_gitleaks(raw_data: list, scan_id: str, repo_path: str = "") -> list:
    findings = []
    matcher = None
    if repo_path and os.path.isdir(repo_path):
        from ..gitignore import GitIgnoreMatcher
        matcher = GitIgnoreMatcher(repo_path)

    for r in raw_data or []:
        if not isinstance(r, dict):
            continue

        rel_path = _rel_path(r.get('File'), repo_path)
        if matcher and matcher.is_ignored(rel_path):
            continue

        rule_id = r.get('RuleID') or r.get('Rule') or 'gitleaks-secret'
        description = r.get('Description') or f"Secret of type {rule_id}"
        commit = r.get('Commit') or ''

        detail = [
            f"{description}.",
            "A live credential committed to the repository must be considered compromised: "
            "rotate it and remove it from the code and from git history.",
        ]
        if commit:
            detail.append(f"Commit: {commit}")

        findings.append({
            "scanner": "gitleaks",
            "ruleId": rule_id,
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "title": f"Exposed secret: {rule_id}",
            "description": " ".join(detail),
            "filePath": rel_path,
            "startLine": _safe_line(r.get('StartLine')),
            "endLine": _safe_line(r.get('EndLine')),
            "codeSnippet": "***REDACTED***",  # Never expose raw secrets
            "scanId": scan_id,
        })
    return findings


def normalize_trivy(raw_data: dict, scan_id: str, repo_path: str = "") -> list:
    findings = []
    results = (raw_data or {}).get('Results', []) or []
    matcher = None
    if repo_path and os.path.isdir(repo_path):
        from ..gitignore import GitIgnoreMatcher
        matcher = GitIgnoreMatcher(repo_path)

    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "INFO",
    }

    for res in results:
        target = _rel_path(res.get('Target', ''), repo_path)
        if matcher and matcher.is_ignored(target):
            continue


        # Vulnerabilities (dependencies)
        for vuln in res.get('Vulnerabilities', []) or []:
            vuln_id = vuln.get('VulnerabilityID') or 'UNKNOWN-VULN'
            pkg = vuln.get('PkgName') or 'dependency'
            installed = vuln.get('InstalledVersion') or '?'
            fixed = vuln.get('FixedVersion')

            description = " ".join(filter(None, [
                vuln.get('Title') or '',
                vuln.get('Description') or '',
                f"Installed: {pkg}@{installed}.",
                f"Fixed in: {fixed}." if fixed else "No fixed version published yet.",
            ]))

            findings.append({
                "scanner": "trivy",
                "ruleId": vuln_id,
                "severity": severity_map.get(str(vuln.get('Severity', 'MEDIUM')).upper(), 'MEDIUM'),
                "confidence": "HIGH",
                "title": f"{pkg}@{installed}: {vuln_id}",
                "description": description[:4000],
                "filePath": target,
                "startLine": _safe_line((vuln.get('DataSource') or {}).get('StartLine')),
                "endLine": None,
                "codeSnippet": None,
                "scanId": scan_id,
            })

        # Misconfigurations
        for misconf in res.get('Misconfigurations', []) or []:
            misconf_id = misconf.get('ID') or 'TRIVY-MISCONF'
            cause = misconf.get('CauseMetadata') or {}
            description = " ".join(filter(None, [
                misconf.get('Description') or '',
                f"Resolution: {misconf.get('Resolution')}" if misconf.get('Resolution') else '',
            ]))

            findings.append({
                "scanner": "trivy",
                "ruleId": misconf_id,
                "severity": severity_map.get(str(misconf.get('Severity', 'MEDIUM')).upper(), 'MEDIUM'),
                "confidence": "HIGH",
                "title": (misconf.get('Title') or misconf_id)[:120],
                "description": description[:4000],
                "filePath": target,
                "startLine": _safe_line(cause.get('StartLine')),
                "endLine": _safe_line(cause.get('EndLine')),
                "codeSnippet": None,
                "scanId": scan_id,
            })

        # Secrets (trivy's own secret scanner)
        for secret in res.get('Secrets', []) or []:
            rule_id = secret.get('RuleID') or 'TRIVY-SECRET'
            findings.append({
                "scanner": "trivy",
                "ruleId": rule_id,
                "severity": severity_map.get(str(secret.get('Severity', 'CRITICAL')).upper(), 'CRITICAL'),
                "confidence": "HIGH",
                "title": f"Exposed secret: {secret.get('Title') or rule_id}"[:120],
                "description": (secret.get('Title') or 'Hardcoded secret detected by Trivy') +
                               ". Rotate the credential and remove it from the repository.",
                "filePath": target,
                "startLine": _safe_line(secret.get('StartLine')),
                "endLine": _safe_line(secret.get('EndLine')),
                "codeSnippet": "***REDACTED***",
                "scanId": scan_id,
            })

    return findings
