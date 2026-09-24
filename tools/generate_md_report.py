#!/usr/bin/env python3
"""
Генерация Markdown-отчёта из scan_results.json (ТЗ п. 4.6.1).

Используется в CI для формирования kmg-self-scan-report.md из результатов
self-scan (Python security engine: Semgrep / Gitleaks / Trivy).
Для полного отчёта Агента с привязкой к требованиям ИБ-01…ИБ-08 используется
kmg-report.md, формируемый action.yml через kmg-guard.mjs.

Использование:
    python3 tools/generate_md_report.py scan_results.json > kmg-self-scan-report.md
    python3 tools/generate_md_report.py scan_results.json kmg-self-scan-report.md
"""

import json
import sys
import os
from datetime import datetime, timezone

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def cell(value: str) -> str:
    """Экранирует символы, нарушающие Markdown-таблицу."""
    return str(value or "—").replace("|", "\\|").replace("\r\n", " ").replace("\n", " ").strip()


def location(finding: dict) -> str:
    path = finding.get("filePath") or ""
    line = finding.get("startLine")
    if not path:
        return "—"
    return f"`{path}:{line}`" if line else f"`{path}`"


def build_report(data: dict, source_file: str) -> str:
    now = datetime.now(timezone.utc).isoformat()
    status = data.get("status", "unknown")
    duration_ms = data.get("duration_ms")
    files_count = data.get("filesCount", "?")
    findings = data.get("findings") or []
    scanners = data.get("scanners") or {}

    # Подсчёт по severity
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)

    # Итоговый статус для отчёта
    if status == "failed":
        result_label = "⚠️ ПРОВЕРКА НЕ ВЫПОЛНЕНА"
        result_note  = "Не все сканеры завершились успешно. Отсутствие находок **не означает** отсутствие уязвимостей."
        exit_code = 2
    elif critical > 0:
        result_label = "🛑 ЗАБЛОКИРОВАНО"
        result_note  = f"Выявлено {critical} критических проблем. Слияние заблокировано."
        exit_code = 1
    elif status in ("success", "partial"):
        result_label = "✅ ПРОЙДЕНО"
        result_note  = "Критических уязвимостей не обнаружено."
        exit_code = 0
    else:
        result_label = "⚠️ ЧАСТИЧНЫЙ РЕЗУЛЬТАТ"
        result_note  = "Часть сканеров не завершилась. Результат неполный."
        exit_code = 2

    out = []

    out.append("# Отчёт KMG AI Security Agent — Self-Scan\n")
    out.append(f"> **{result_label}** — {result_note}\n")

    # ---- Сводка (ТЗ п. 4.6.3) ----
    out.append("## Сводка\n")
    out.append("| Параметр | Значение |")
    out.append("|---|---|")
    out.append(f"| Источник отчёта | `{os.path.basename(source_file)}` |")
    out.append(f"| Дата формирования | {now} |")
    if duration_ms is not None:
        out.append(f"| Длительность сканирования | {duration_ms / 1000:.1f} с |")
    out.append(f"| Проверено файлов | {files_count} |")
    out.append(f"| Статус сканирования | `{status}` |")
    out.append(f"| Общий результат | **{result_label}** |")
    out.append(f"| Код завершения | `{exit_code}` |")
    out.append(f"| 🔴 Критических | {critical} |")
    out.append(f"| 🟠 Высоких | {high} |")
    out.append(f"| 🟡 Средних | {counts.get('MEDIUM', 0)} |")
    out.append(f"| 🔵 Низких | {counts.get('LOW', 0)} |")
    out.append(f"| ⚪ Информационных | {counts.get('INFO', 0)} |")
    out.append("")

    # ---- Статус сканеров ----
    out.append("## Статус сканеров\n")
    out.append("| Сканер | Статус | Находок | Ошибка |")
    out.append("|---|---|---|---|")
    if isinstance(scanners, dict):
        scanner_items = scanners.items()
    elif isinstance(scanners, list):
        scanner_items = [(s if isinstance(s, str) else str(s.get("name", f"scanner_{i}")), s if isinstance(s, dict) else {"status": "UNKNOWN"}) for i, s in enumerate(scanners)]
    else:
        scanner_items = []

    for name, rec in scanner_items:
        s = rec.get("status", "?") if isinstance(rec, dict) else str(rec)
        icon = "✅" if s == "COMPLETED" else ("➖" if s == "SKIPPED" else "❌")
        err = cell(rec.get("error") or "") if isinstance(rec, dict) else ""
        findings_count = rec.get('findingsCount', 0) if isinstance(rec, dict) else 0
        out.append(f"| **{name}** | {icon} {s} | {findings_count} | {err[:100]} |")
    out.append("")

    # ---- Находки (ТЗ п. 4.6.2) ----
    out.append("## Находки\n")

    if not findings:
        if exit_code == 2:
            out.append("_Вердикт не вынесен: проверка не выполнена. Об отсутствии уязвимостей утверждать нельзя._\n")
        else:
            out.append("_Уязвимостей и критических нарушений не обнаружено._\n")
    else:
        # Сортировка: CRITICAL → HIGH → MEDIUM → LOW → INFO
        sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99))

        out.append("| Severity | Место | Сканер | Правило | Описание |")
        out.append("|---|---|---|---|---|")
        for f in sorted_findings[:200]:
            sev = f.get("severity", "INFO")
            emoji = SEVERITY_EMOJI.get(sev, "")
            scanner = f.get("scanner", "?")
            rule = cell(f.get("ruleId") or "")
            title = cell(f.get("title") or "")[:110]
            loc = location(f)
            out.append(f"| {emoji} {sev} | {loc} | {scanner} | {rule[:60]} | {title} |")

        if len(findings) > 200:
            out.append(f"\n_Показано 200 из {len(findings)}. Полный список — в `scan_results.json`._")
        out.append("")

        # Детали критических и высоких (ТЗ п. 4.6.2: фрагмент кода + обоснование + рекомендация)
        critical_high = [f for f in sorted_findings if f.get("severity") in ("CRITICAL", "HIGH")]
        if critical_high:
            out.append("## Детали критических и высоких находок\n")
            for i, f in enumerate(critical_high[:30], 1):
                sev = f.get("severity", "")
                emoji = SEVERITY_EMOJI.get(sev, "")
                out.append(f"### {i}. {emoji} {sev} — {cell(f.get('title') or f.get('ruleId') or '?')}\n")
                out.append(f"**Сканер:** {f.get('scanner', '?')}  ")
                out.append(f"**Правило:** `{f.get('ruleId') or '—'}`  ")
                out.append(f"**Место:** {location(f)}\n")

                description = (f.get("description") or "").strip()
                if description:
                    out.append(f"**Описание.** {cell(description)[:600]}\n")

                snippet = f.get("codeSnippet") or ""
                if snippet and snippet != "***REDACTED***":
                    out.append("**Фрагмент кода.**\n")
                    out.append("```")
                    out.append(snippet[:800])
                    out.append("```\n")
                elif snippet == "***REDACTED***":
                    out.append("**Фрагмент кода.** `***REDACTED***` (секрет — значение скрыто)\n")

                out.append("**Рекомендация.** Устраните уязвимость согласно описанию правила.\n")

            if len(critical_high) > 30:
                out.append(f"_Показано 30 из {len(critical_high)}. Остальные — в `scan_results.json`._\n")

    # ---- Требования ИБ-01…ИБ-08 (ТЗ п. 4.5, 4.6.3) ----
    out.append("## Статус обязательных требований ИБ (ТЗ п. 4.5)\n")
    out.append("> **Примечание.** Этот отчёт сформирован из результатов self-scan (Semgrep/Gitleaks/Trivy).")
    out.append("> Полная проверка требований ИБ-01…ИБ-08 по детерминированным чекерам выполняется")
    out.append("> через KMG backend и отражена в `kmg-report.md` (артефакт `kmg-security-report`).\n")

    REQUIREMENTS = [
        ("ИБ-01", "Разграничение доступа к административному функционалу", "CRITICAL"),
        ("ИБ-02", "Проверка сессии и токена на стороне сервера",            "CRITICAL"),
        ("ИБ-03", "Защита канала передачи данных (TLS ≥ 1.2)",              "HIGH"),
        ("ИБ-04", "Криптографическая защита персональных данных при хранении","CRITICAL"),
        ("ИБ-05", "Защита локальных журналов приложения",                   "HIGH"),
        ("ИБ-06", "Ссылки на нормативную базу в документации проекта",      "MEDIUM"),
        ("ИБ-07", "Журналирование пользователей и событий СУБД (сквозное)", "HIGH"),
        ("ИБ-08", "Контроль выгрузки персональных данных",                  "CRITICAL"),
    ]

    out.append("| ID | Требование | Severity | Статус self-scan |")
    out.append("|---|---|---|---|")
    for req_id, title, sev in REQUIREMENTS:
        # Ищем находки сканеров, связанные с темой требования (упрощённая эвристика)
        keywords_map = {
            "ИБ-01": ["admin", "role", "rbac", "authorization"],
            "ИБ-02": ["session", "token", "jwt", "auth", "cookie"],
            "ИБ-03": ["tls", "ssl", "https", "http:", "insecure"],
            "ИБ-04": ["password", "hash", "bcrypt", "argon", "encrypt", "crypto", "md5", "sha1"],
            "ИБ-05": ["log", "journal", "audit", "encrypt"],
            "ИБ-06": ["README", "doc", "норматив", "закон", "ГОСТ", "27001"],
            "ИБ-07": ["audit", "log", "event", "db", "database"],
            "ИБ-08": ["export", "download", "personal", "admin", "role"],
        }
        kw = keywords_map.get(req_id, [])
        related = [
            f for f in findings
            if any(k.lower() in (f.get("title") or "").lower() or
                   k.lower() in (f.get("ruleId") or "").lower()
                   for k in kw)
        ]
        if related:
            worst = min(related, key=lambda f: SEVERITY_ORDER.get(f.get("severity","INFO"), 99))
            w_sev = worst.get("severity", "INFO")
            status_cell = f"⚠️ {len(related)} находок (severity: {w_sev})"
        else:
            status_cell = "➖ Нет связанных находок — см. kmg-report.md"
        out.append(f"| **{req_id}** | {title} | {sev} | {status_cell} |")
    out.append("")

    # ---- Нормативная база ИБ-06 (проверяем себя) ----
    out.append("## Нормативная база (ТЗ п. 3.1, требование ИБ-06)\n")
    out.append("Следующие акты и стандарты должны быть упомянуты в документации проекта:\n")
    acts = [
        ("3.1.1", "Закон РК № 418-V «О кибербезопасности» (24.11.2015)"),
        ("3.1.2", "Закон РК № 94-V «О персональных данных и их защите» (21.05.2013)"),
        ("3.1.3", "Единые требования в области ИКТ и ИБ (ПП РК от 20.12.2016 № 832)"),
        ("3.1.4", "СТ РК ISO/IEC 27001-2023"),
        ("3.1.5", "СТ РК ISO/IEC 27002-2023"),
        ("3.1.6", "СТ РК 1073-2007 «Средства криптографической защиты информации»"),
    ]
    for clause, title in acts:
        out.append(f"- **{clause}** {title}")
    out.append("")

    return "\n".join(out)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    if len(sys.argv) < 2:
        print(f"Использование: {sys.argv[0]} <scan_results.json> [output.md]", file=sys.stderr)
        sys.exit(1)

    source_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        with open(source_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"Файл не найден: {source_file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Ошибка разбора JSON: {e}", file=sys.stderr)
        sys.exit(1)

    report = build_report(data, source_file)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Отчёт записан: {output_file}", file=sys.stderr)
    else:
        print(report)


if __name__ == "__main__":
    main()
