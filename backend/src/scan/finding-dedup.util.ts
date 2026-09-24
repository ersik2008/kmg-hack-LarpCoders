/**
 * Дедупликация находок между сканерами.
 *
 * Одна и та же проблема часто обнаруживается несколькими инструментами:
 * жёстко зашитый секрет — Gitleaks, Trivy и правило Semgrep одновременно;
 * слабый хеш — Semgrep и встроенный резерв. Без объединения отчёт содержит три
 * одинаковые записи, счётчики завышены, а оценка риска складывает вес одной
 * проблемы трижды — именно «дублирование находок» ТЗ называет в критериях
 * оценки точности выводов (раздел 6).
 *
 * Итог — ОДНА нормализованная находка с перечнем обнаруживших её инструментов:
 *   detectedBy: ['semgrep', 'trivy', 'gitleaks']
 */

export type FindingCategory =
  | 'secret'
  | 'sql-injection'
  | 'command-injection'
  | 'code-execution'
  | 'xss'
  | 'path-traversal'
  | 'ssrf'
  | 'weak-crypto'
  | 'jwt'
  | 'deserialization'
  | 'cors'
  | 'tls'
  | 'dependency'
  | 'misconfiguration'
  | 'other';

/** Правила определения класса проблемы по идентификатору правила и заголовку. */
const CATEGORY_RULES: Array<{ category: FindingCategory; pattern: RegExp }> = [
  { category: 'secret', pattern: /secret|password|passwd|credential|api[-_ ]?key|access[-_ ]?token|private[-_ ]?key|hardcoded[-_ ]?(?:key|token|pass)|gitleaks|aws-access|github-pat/i },
  { category: 'sql-injection', pattern: /sql[-_ ]?inject|sqli|raw[-_ ]?query|string[-_ ]?interpolation.*(?:query|sql)|sql.*(?:concat|interpol)/i },
  { category: 'command-injection', pattern: /command[-_ ]?inject|shell[-_ ]?inject|child[-_ ]?process|os[-_ ]?command|subprocess.*shell|exec\b.*(?:concat|user)/i },
  { category: 'code-execution', pattern: /dynamic[-_ ]?code|eval\b|new[-_ ]?function|code[-_ ]?execution|rce\b/i },
  { category: 'xss', pattern: /\bxss\b|cross[-_ ]?site[-_ ]?script|innerhtml|reflected/i },
  { category: 'path-traversal', pattern: /path[-_ ]?traversal|directory[-_ ]?traversal|arbitrary[-_ ]?file/i },
  { category: 'ssrf', pattern: /\bssrf\b|server[-_ ]?side[-_ ]?request/i },
  { category: 'jwt', pattern: /\bjwt\b|json[-_ ]?web[-_ ]?token|algorithm[-_ ]?none/i },
  { category: 'deserialization', pattern: /deserializ|pickle|yaml\.load|unserialize/i },
  { category: 'weak-crypto', pattern: /weak[-_ ]?(?:hash|crypto|cipher|random)|md5|sha-?1\b|insecure[-_ ]?random|math\.random|des\b|rc4|createhash/i },
  { category: 'cors', pattern: /\bcors\b|access-control-allow-origin/i },
  { category: 'tls', pattern: /\btls\b|\bssl\b|certificate|reject[-_ ]?unauthorized|verify\s*=\s*false/i },
];

export interface DedupInput {
  scanner: string;
  ruleId?: string | null;
  severity: string;
  confidence?: string | null;
  title?: string | null;
  description?: string | null;
  filePath?: string | null;
  startLine?: number | null;
  endLine?: number | null;
  codeSnippet?: string | null;
  [key: string]: unknown;
}

export type DedupOutput<T extends DedupInput> = T & {
  /** Инструменты, обнаружившие эту проблему (в порядке первого обнаружения). */
  detectedBy: string[];
  /** Идентификаторы правил каждого инструмента. */
  ruleIds: string[];
  category: FindingCategory;
};

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
const CONFIDENCE_RANK: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };

export function categoryOf(f: Pick<DedupInput, 'scanner' | 'ruleId' | 'title'>): FindingCategory {
  // Уязвимость зависимости — по идентификатору CVE/GHSA у Trivy, а не по словам в тексте.
  if (f.scanner === 'trivy' && /^(?:CVE|GHSA|OSV|GO|PYSEC)-/i.test(String(f.ruleId ?? ''))) return 'dependency';
  if (f.scanner === 'trivy' && /^(?:AVD|DS|KSV|TRIVY)-/i.test(String(f.ruleId ?? '')) && !/secret/i.test(String(f.ruleId))) {
    return 'misconfiguration';
  }

  const haystack = `${f.ruleId ?? ''} ${f.title ?? ''}`;
  for (const rule of CATEGORY_RULES) {
    if (rule.pattern.test(haystack)) return rule.category;
  }
  return 'other';
}

function normalizePath(p: string | null | undefined): string {
  return String(p ?? '').replace(/\\/g, '/').replace(/^\.?\//, '').toLowerCase();
}

/**
 * Ключ, по которому находки считаются одной проблемой.
 *
 *  - Уязвимость зависимости: файл + идентификатор CVE. Одна и та же CVE в
 *    package.json и package-lock.json — это разные места, а не дубликат, поэтому
 *    файл входит в ключ.
 *  - Прочее с известной категорией: файл + строка + категория. Разные правила
 *    Semgrep и Gitleaks на одной строке про один секрет сливаются.
 *  - Категория `other`: только полное совпадение (сканер, правило, файл, строка) —
 *    без уверенности в том, что это одно и то же, объединять нельзя.
 */
function dedupKey(f: DedupInput, category: FindingCategory): string {
  const file = normalizePath(f.filePath);
  const line = f.startLine ?? 0;

  if (category === 'dependency') return `dep|${file}|${String(f.ruleId ?? f.title ?? '').toLowerCase()}`;
  if (category === 'other') return `raw|${f.scanner}|${f.ruleId ?? ''}|${file}|${line}`;
  return `${category}|${file}|${line}`;
}

/**
 * Сливает дубликаты. Порядок первого появления сохраняется; в объединённой
 * находке берутся наибольшая критичность и уверенность, самый длинный
 * фрагмент кода и полное описание первой записи.
 */
export function dedupeFindings<T extends DedupInput>(findings: T[]): Array<DedupOutput<T>> {
  const groups = new Map<string, DedupOutput<T>>();

  for (const f of findings) {
    const category = categoryOf(f);
    const key = dedupKey(f, category);
    const existing = groups.get(key);

    if (!existing) {
      groups.set(key, {
        ...f,
        detectedBy: [f.scanner],
        ruleIds: f.ruleId ? [`${f.scanner}:${f.ruleId}`] : [],
        category,
      });
      continue;
    }

    if (!existing.detectedBy.includes(f.scanner)) existing.detectedBy.push(f.scanner);
    const ruleRef = f.ruleId ? `${f.scanner}:${f.ruleId}` : null;
    if (ruleRef && !existing.ruleIds.includes(ruleRef)) existing.ruleIds.push(ruleRef);

    if ((SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[existing.severity] ?? 0)) {
      existing.severity = f.severity;
    }
    if ((CONFIDENCE_RANK[String(f.confidence)] ?? 0) > (CONFIDENCE_RANK[String(existing.confidence)] ?? 0)) {
      existing.confidence = f.confidence;
    }
    // Секрет остаётся замаскированным, даже если другой инструмент его раскрыл.
    if (existing.codeSnippet === '***REDACTED***' || f.codeSnippet === '***REDACTED***') {
      existing.codeSnippet = '***REDACTED***';
    } else if (String(f.codeSnippet ?? '').length > String(existing.codeSnippet ?? '').length) {
      existing.codeSnippet = f.codeSnippet;
    }
    if (!existing.endLine && f.endLine) existing.endLine = f.endLine;
  }

  return [...groups.values()];
}

/** Сколько записей объединено — для журнала и отчёта. */
export function dedupStats(before: number, after: number) {
  return { before, after, merged: Math.max(0, before - after) };
}
