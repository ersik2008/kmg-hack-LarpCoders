import { Prisma, Severity, Confidence } from '../generated/prisma/client.js';

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const CONFIDENCES: Confidence[] = ['HIGH', 'MEDIUM', 'LOW'];

function clampString(value: unknown, max: number): string | null {
  if (value === null || value === undefined) return null;
  const str = String(value);
  if (!str.length) return null;
  return str.length > max ? str.slice(0, max) : str;
}

function toLine(value: unknown): number | null {
  const num = Number(value);
  return Number.isInteger(num) && num > 0 ? num : null;
}

/**
 * Converts a scanner/normalizer finding into a row Prisma will accept.
 *
 * Scanner output is external data: a single row with an out-of-enum severity or
 * a null title used to make the whole `createMany` throw, which turned a scan
 * that *did* detect vulnerabilities into a failed scan with zero findings.
 */
export function toFindingRow(scanId: string, f: any): Prisma.FindingCreateManyInput {
  const severity = SEVERITIES.includes(String(f?.severity).toUpperCase() as Severity)
    ? (String(f.severity).toUpperCase() as Severity)
    : 'MEDIUM';

  const confidence = CONFIDENCES.includes(String(f?.confidence).toUpperCase() as Confidence)
    ? (String(f.confidence).toUpperCase() as Confidence)
    : 'MEDIUM';

  const ruleId = clampString(f?.ruleId, 255);

  return {
    scanId,
    scanner: clampString(f?.scanner, 64) ?? 'unknown',
    ruleId,
    severity,
    confidence,
    title: clampString(f?.title, 500) ?? ruleId ?? 'Security finding',
    description: clampString(f?.description, 8000),
    filePath: clampString(f?.filePath, 1000),
    startLine: toLine(f?.startLine),
    endLine: toLine(f?.endLine),
    codeSnippet: clampString(f?.codeSnippet, 4000),
    // Инструменты, обнаружившие проблему (после дедупликации). Схема БД не меняется:
    // перечень хранится в существующем поле metadata.
    category: typeof f?.category === 'string' ? clampString(f.category, 64) : null,
    metadata: Array.isArray(f?.detectedBy)
      ? ({ detectedBy: f.detectedBy.map((s: unknown) => String(s)), ruleIds: Array.isArray(f?.ruleIds) ? f.ruleIds.map((s: unknown) => String(s)) : [] } as Prisma.InputJsonValue)
      : undefined,
  };
}
