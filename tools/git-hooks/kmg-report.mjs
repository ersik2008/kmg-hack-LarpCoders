/**
 * Отчёт Агента (ТЗ п. 4.6): машиночитаемый JSON и представление в Markdown.
 *
 * Оба формата строятся из одного и того же ответа backend и одного и того же
 * кода завершения, поэтому не могут разойтись между собой и с решением
 * пайплайна (п. 4.6.5): `metadata.result` и `metadata.exit_code` выводятся из
 * единственного значения `exitCode`.
 *
 * Модуль не обращается ни к сети, ни к файловой системе — только формирует
 * структуры. Запись файлов делает kmg-guard.mjs.
 */

export const REQUIREMENT_ORDER = [
  'ИБ-01', 'ИБ-02', 'ИБ-03', 'ИБ-04', 'ИБ-05', 'ИБ-06', 'ИБ-07', 'ИБ-08',
];

const RESULT_BY_EXIT = { 0: 'PASS', 1: 'BLOCK', 2: 'ERROR' };
const EXIT_MEANING = {
  0: 'нарушений Требований ИБ не выявлено',
  1: 'выявлены нарушения Требований ИБ',
  2: 'проверка не выполнена',
};

const STATUS_LABEL = {
  PASS: 'PASS',
  VIOLATION: 'VIOLATION',
  INSUFFICIENT_EVIDENCE: 'INSUFFICIENT_EVIDENCE',
  NOT_APPLICABLE: 'NOT_APPLICABLE',
};

const SECRET_PATTERNS = [
  [/ghp_[A-Za-z0-9]{30,}/g, 'ghp_***REDACTED***'],
  [/github_pat_[A-Za-z0-9_]{50,}/g, 'github_pat_***REDACTED***'],
  [/gsk_[A-Za-z0-9]{30,}/g, 'gsk_***REDACTED***'],
  [/AKIA[0-9A-Z]{16}/g, 'AKIA***REDACTED***'],
  [/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/g, '[JWT_REDACTED]'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[PRIVATE_KEY_REDACTED]'],
  [/(postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:@\s/]+:[^@\s]+@/gi, '$1://***:***@'],
  [/((?:api[_-]?key|secret|token|password|passwd)["'\s]*[:=]["'\s]*)[^\s"',;}{]{6,}/gi, '$1***REDACTED***'],
];

/**
 * Последний рубеж перед публикацией: в отчёт не должны попадать секреты, даже
 * если сканер по ошибке вернул значение (критерий «отсутствие раскрытия
 * секретов» раздела 6 ТЗ).
 */
export function redact(value) {
  if (value === null || value === undefined) return value;
  let text = String(value);
  for (const [pattern, replacement] of SECRET_PATTERNS) text = text.replace(pattern, replacement);
  return text;
}

function orderRequirements(list) {
  const rank = id => {
    const i = REQUIREMENT_ORDER.indexOf(id);
    return i === -1 ? REQUIREMENT_ORDER.length : i;
  };
  return [...(list || [])].sort((a, b) => rank(a.requirementId) - rank(b.requirementId));
}

/** Плоский перечень нарушений по всем требованиям (ТЗ п. 4.6.2). */
export function collectViolations(result) {
  const out = [];
  let n = 0;
  for (const req of orderRequirements(result.requirements)) {
    if (req.status !== 'VIOLATION') continue;
    for (const v of req.violations || []) {
      n += 1;
      out.push({
        id: `v-${String(n).padStart(3, '0')}`,
        requirement_id: req.requirementId,
        requirement_text: req.requirementText,
        file_path: v.filePath ?? null,
        line_start: v.lineStart ?? null,
        line_end: v.lineEnd ?? null,
        symbol: v.symbol ?? null,
        evidence: redact(v.evidence),
        explanation: redact(v.explanation),
        severity: v.severity,
        confidence: v.confidence,
        recommendation: v.recommendation,
        detected_by: ['requirements-engine'],
      });
    }
  }
  return out;
}

/**
 * Прочие находки (ТЗ п. 4.8.1): приводятся отдельным разделом и основанием для
 * прерывания пайплайна не являются, если решение принято по требованиям ИБ.
 */
export function collectAdditionalFindings(result) {
  const blocksByPolicy = result.decisionBasis !== 'requirements';
  return (result.findings || []).map((f, i) => ({
    id: `f-${String(i + 1).padStart(3, '0')}`,
    file_path: f.filePath ?? null,
    line_start: f.startLine ?? null,
    line_end: f.endLine ?? null,
    rule_id: f.ruleId ?? null,
    title: redact(f.title),
    explanation: redact(f.description),
    evidence: f.codeSnippet === '***REDACTED***' ? '***REDACTED***' : redact(f.codeSnippet),
    severity: f.severity,
    confidence: f.confidence,
    detected_by: Array.isArray(f.detectedBy) && f.detectedBy.length ? f.detectedBy : [f.scanner],
    blocks_pipeline: blocksByPolicy && f.severity === 'CRITICAL',
  }));
}

/**
 * JSON-отчёт по п. 4.6.1 и 4.6.3 ТЗ.
 *
 * @param {object} result   ответ backend
 * @param {0|1|2}  exitCode код завершения, возвращаемый в CI
 * @param {object} [context] commitSha / startedAt / finishedAt, если backend их не вернул
 */
export function buildJsonReport(result, exitCode, context = {}) {
  const violations = collectViolations(result);
  const started = result.startedAt || context.startedAt || null;
  const finished = result.finishedAt || context.finishedAt || null;
  const duration =
    result.durationSeconds ??
    (started && finished ? Math.round((Date.parse(finished) - Date.parse(started)) / 100) / 10 : null);

  const requirements = {};
  for (const req of orderRequirements(result.requirements)) {
    requirements[req.requirementId] = {
      status: STATUS_LABEL[req.status] || req.status,
      title: req.title,
      confidence: req.confidence,
      summary: redact(req.summary),
      violations: violations.filter(v => v.requirement_id === req.requirementId).map(v => v.id),
      evidence: (req.evidence || []).slice(0, 12).map(e => ({
        file_path: e.filePath,
        line: e.line,
        snippet: redact(e.snippet),
        note: e.note,
        kind: e.kind,
      })),
      ...(req.insufficientReason ? { insufficient_reason: req.insufficientReason } : {}),
    };
  }

  return {
    metadata: {
      commit_id: result.commitSha || context.commitSha || null,
      repository: context.repository || null,
      branch: context.branch || null,
      started_at: started,
      finished_at: finished,
      duration_seconds: duration,
      result: RESULT_BY_EXIT[exitCode],
      exit_code: exitCode,
      violations_count: violations.length,
      violated_requirements: [...new Set(violations.map(v => v.requirement_id))],
      insufficient_requirements: result.insufficientRequirements || [],
      requirements_evaluated: requirements && Object.keys(requirements).length > 0,
      decision_basis: result.decisionBasis || 'severity',
      scope: context.scope || null,
      files_checked: result.filesChecked ?? null,
      scanners: Object.fromEntries(
        Object.entries(result.scanners || {}).map(([name, rec]) => [name, rec?.status ?? 'UNKNOWN']),
      ),
      reasons: (result.reasons || []).map(redact),
    },
    requirements,
    violations,
    additional_findings: collectAdditionalFindings(result),
  };
}

function cell(text) {
  return String(text ?? '—').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').trim();
}

function location(v) {
  if (!v.file_path) return '—';
  const line = v.line_start ? `:${v.line_start}${v.line_end && v.line_end !== v.line_start ? `-${v.line_end}` : ''}` : '';
  return `${v.file_path}${line}`;
}

/** Markdown-представление отчёта для чтения специалистом (ТЗ п. 4.6.1). */
export function buildMarkdownReport(result, exitCode, context = {}) {
  const json = buildJsonReport(result, exitCode, context);
  const m = json.metadata;
  const NL = '\n';
  const out = [];

  out.push('# Отчёт KMG AI Security Agent', '');

  const banner = exitCode === 0
    ? '✅ **Нарушений обязательных требований ИБ не выявлено.** Пайплайн продолжается.'
    : exitCode === 1
      ? '🛑 **Выявлены нарушения обязательных требований ИБ.** Слияние и развёртывание заблокированы.'
      : '⚠️ **Проверка не выполнена.** Вердикт не вынесен. Отсутствие находок в этом отчёте **не означает**, что код безопасен.';
  out.push(banner, '');

  out.push('## Сводка', '');
  out.push('| Параметр | Значение |', '|---|---|');
  out.push(`| Идентификатор коммита | \`${cell(m.commit_id)}\` |`);
  if (m.repository) out.push(`| Репозиторий | ${cell(m.repository)} |`);
  if (m.branch) out.push(`| Ветка | ${cell(m.branch)} |`);
  out.push(`| Начало проверки | ${cell(m.started_at)} |`);
  out.push(`| Завершение проверки | ${cell(m.finished_at)} |`);
  out.push(`| Длительность, с | ${cell(m.duration_seconds)} |`);
  out.push(`| Общий результат | **${m.result}** |`);
  out.push(`| Код завершения | \`${m.exit_code}\` — ${EXIT_MEANING[exitCode]} |`);
  out.push(`| Нарушений | ${m.violations_count} |`);
  out.push(`| Нарушены требования | ${m.violated_requirements.length ? m.violated_requirements.join(', ') : '—'} |`);
  out.push(`| Основание решения | ${m.decision_basis === 'requirements' ? 'статусы требований ИБ (ТЗ п. 4.3.3)' : m.decision_basis === 'incomplete' ? 'проверка не завершена' : 'severity находок (требования ИБ не оценивались)'} |`);
  if (m.scope) out.push(`| Объём анализа | ${m.scope === 'all' ? 'весь проект' : 'только изменённые файлы'} |`);
  if (m.files_checked != null) out.push(`| Проверено файлов | ${m.files_checked} |`);
  out.push('');

  out.push('## Статус по каждому требованию ИБ', '');
  if (Object.keys(json.requirements).length === 0) {
    // Две разные причины, и путать их нельзя: «не смогли проверить» и «проверяли
    // по диффу» требуют разных действий от того, кто читает отчёт.
    if (exitCode === 2) {
      out.push(
        '_Требования ИБ-01…ИБ-08 **не оценены**: проверка не выполнена (см. причину в разделе ' +
        '«Обоснование решения»). Статус по требованиям отсутствует, а не равен `PASS`._',
        '',
      );
    } else {
      out.push(
        '_Требования ИБ-01…ИБ-08 в этом прогоне **не оценивались**: анализ выполнялся по неполному ' +
        'набору файлов (только изменённые). Сквозные требования по диффу не устанавливаются — ' +
        'запустите проверку с полным объёмом (`paths: all`)._',
        '',
      );
    }
  } else {
    out.push('| ID | Требование | Статус | Нарушений | Обоснование |', '|---|---|---|---|---|');
    for (const [id, r] of Object.entries(json.requirements)) {
      const mark = r.status === 'PASS' ? '✅' : r.status === 'VIOLATION' ? '🛑' : r.status === 'NOT_APPLICABLE' ? '➖' : '⚠️';
      out.push(`| ${id} | ${cell(r.title)} | ${mark} ${r.status} | ${r.violations.length} | ${cell(r.summary).slice(0, 220)} |`);
    }
    out.push('');
    const insufficient = Object.entries(json.requirements).filter(([, r]) => r.status === 'INSUFFICIENT_EVIDENCE');
    if (insufficient.length) {
      out.push('**Недостаточно данных для вывода** (не является `PASS`):', '');
      for (const [id, r] of insufficient) out.push(`- **${id}** — ${cell(r.insufficient_reason || r.summary)}`);
      out.push('');
    }
  }

  out.push('## Нарушения', '');
  if (json.violations.length === 0 && exitCode === 2) {
    // При коде 2 нельзя утверждать «нарушений нет»: проверка не была выполнена.
    out.push('_Вердикт не вынесен: проверка не выполнена. Об отсутствии нарушений утверждать нельзя._', '');
  } else if (json.violations.length === 0) {
    out.push('_Нарушений обязательных требований ИБ не выявлено._', '');
  } else {
    for (const v of json.violations) {
      out.push(`### ${v.id} · ${v.requirement_id} · ${v.severity}`, '');
      out.push(`**Требование.** ${cell(v.requirement_text)}`, '');
      out.push(`**Место.** \`${location(v)}\`${v.symbol ? ` · ${cell(v.symbol)}` : ''}`, '');
      out.push('**Основание (фрагмент).**', '', '```', String(v.evidence ?? '').slice(0, 600), '```', '');
      out.push(`**В чём несоответствие.** ${cell(v.explanation)}`, '');
      out.push(`**Уверенность.** ${v.confidence}`, '');
      out.push(`**Рекомендация.** ${cell(v.recommendation)}`, '');
    }
  }

  out.push('## Дополнительные находки', '');
  out.push(
    '_Приводятся отдельно и, если решение принято по требованиям ИБ, пайплайн не прерывают ' +
    '(ТЗ п. 4.8.1)._',
    '',
  );
  if (json.additional_findings.length === 0) {
    out.push('_Дополнительных находок нет._', '');
  } else {
    out.push('| Severity | Место | Проблема | Обнаружено | Блокирует |', '|---|---|---|---|---|');
    for (const f of json.additional_findings.slice(0, 60)) {
      out.push(
        `| ${f.severity} | \`${location({ file_path: f.file_path, line_start: f.line_start, line_end: f.line_end })}\` | ` +
        `${cell(f.title).slice(0, 110)} | ${f.detected_by.join(', ')} | ${f.blocks_pipeline ? 'да' : 'нет'} |`,
      );
    }
    if (json.additional_findings.length > 60) {
      out.push('', `_Показано 60 из ${json.additional_findings.length}. Полный перечень — в JSON-отчёте._`);
    }
    out.push('');
  }

  out.push('## Сканеры', '');
  const scanners = Object.entries(m.scanners);
  out.push(scanners.length ? scanners.map(([n, s]) => `- **${n}**: ${s}`).join(NL) : '_нет данных_', '');

  if (m.reasons.length) {
    out.push('## Обоснование решения', '');
    for (const r of m.reasons) out.push(`- ${cell(r)}`);
    out.push('');
  }

  return out.join(NL);
}

/** Краткое перечисление нарушенных требований для журнала выполнения (ТЗ п. 4.3.5). */
export function violatedRequirementsLines(result) {
  const lines = [];
  for (const req of orderRequirements(result.requirements)) {
    if (req.status !== 'VIOLATION') continue;
    const n = (req.violations || []).length;
    const first = (req.violations || [])[0];
    const where = first?.filePath ? ` — ${first.filePath}${first.lineStart ? `:${first.lineStart}` : ''}` : '';
    lines.push(`${req.requirementId} ${req.title}${where}${n > 1 ? ` (+${n - 1})` : ''}`);
  }
  return lines;
}
