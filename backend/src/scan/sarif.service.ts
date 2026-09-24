import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { createHash } from 'crypto';
import { gzipSync } from 'zlib';

import { PrismaService } from '../prisma/index.js';

/**
 * SARIF 2.1.0 export.
 *
 * SARIF is the interchange format every code-scanning tool speaks, and it is
 * what GitHub Code Scanning ingests. Producing it means the findings show up in
 * the repository's native Security tab — annotated on the exact lines, with
 * history and dismissal handled by GitHub — instead of living only in our
 * dashboard.
 *
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

/** GitHub rejects uploads above these limits, so results are capped. */
const MAX_RESULTS = 5000;

/**
 * GitHub renders `security-severity` as the Critical/High/Medium/Low label in
 * the Security tab, using the CVSS-like 0–10 scale.
 */
const SEVERITY_MAP: Record<string, { level: string; securitySeverity: string }> = {
  CRITICAL: { level: 'error', securitySeverity: '9.5' },
  HIGH: { level: 'error', securitySeverity: '7.5' },
  MEDIUM: { level: 'warning', securitySeverity: '5.0' },
  LOW: { level: 'note', securitySeverity: '3.0' },
  INFO: { level: 'note', securitySeverity: '1.0' },
};

const CONTROL_LEVEL: Record<string, { level: string; securitySeverity: string }> = {
  MISSING: { level: 'warning', securitySeverity: '6.0' },
  PARTIAL: { level: 'note', securitySeverity: '4.0' },
};

@Injectable()
export class SarifService {
  private readonly logger = new Logger(SarifService.name);

  constructor(private readonly prisma: PrismaService) {}

  /** Builds the SARIF document for a scan. */
  async build(userId: string, scanId: string): Promise<any> {
    const scan = await this.prisma.scan.findFirst({
      where: { id: scanId, userId },
      include: {
        repository: true,
        findings: true,
        controls: true,
        scanResult: true,
      },
    });

    if (!scan) throw new NotFoundException('Scan not found');

    const rules: any[] = [];
    const ruleIndex = new Map<string, number>();

    const addRule = (rule: any): number => {
      const existing = ruleIndex.get(rule.id);
      if (existing !== undefined) return existing;
      const index = rules.length;
      rules.push(rule);
      ruleIndex.set(rule.id, index);
      return index;
    };

    const results: any[] = [];

    // ----- scanner findings -----
    for (const finding of scan.findings) {
      if (results.length >= MAX_RESULTS) break;

      const severity = SEVERITY_MAP[finding.severity] || SEVERITY_MAP.MEDIUM;
      const ruleId = this.safeRuleId(finding.scanner, finding.ruleId);

      const index = addRule({
        id: ruleId,
        name: this.toPascalCase(finding.ruleId || finding.title),
        shortDescription: { text: this.clip(finding.title, 200) },
        fullDescription: { text: this.clip(finding.description || finding.title, 1000) },
        help: {
          text: this.clip(finding.description || finding.title, 1000),
          markdown: this.ruleHelp(finding),
        },
        defaultConfiguration: { level: severity.level },
        properties: {
          tags: ['security', finding.scanner, `severity:${finding.severity.toLowerCase()}`],
          'security-severity': severity.securitySeverity,
          precision: (finding.confidence || 'MEDIUM').toLowerCase() === 'high' ? 'high' : 'medium',
        },
      });

      results.push({
        ruleId,
        ruleIndex: index,
        level: severity.level,
        message: { text: this.clip(finding.title, 1000) },
        locations: [this.location(finding.filePath, finding.startLine, finding.endLine)],
        partialFingerprints: {
          // Stable across runs so GitHub can track a finding over time instead
          // of reopening it on every scan.
          primaryLocationLineHash: this.fingerprint(finding),
        },
        properties: {
          scanner: finding.scanner,
          severity: finding.severity,
          confidence: finding.confidence,
        },
      });
    }

    // ----- security controls that are missing or partial -----
    // Only controls backed by concrete evidence are exported: Code Scanning
    // needs a location, and inventing one would be worse than omitting it.
    for (const control of scan.controls) {
      if (results.length >= MAX_RESULTS) break;
      if (control.status !== 'MISSING' && control.status !== 'PARTIAL') continue;

      const evidence = Array.isArray(control.evidence) ? (control.evidence as any[]) : [];
      const first = evidence.find(e => e?.filePath);
      if (!first) continue;

      const mapped = CONTROL_LEVEL[control.status];
      const ruleId = `kmg-control/${control.control.toLowerCase()}`;

      const index = addRule({
        id: ruleId,
        name: this.toPascalCase(control.control),
        shortDescription: { text: `Функция ИБ: ${control.title}` },
        fullDescription: { text: this.clip(control.summary, 1000) },
        help: {
          text: this.clip(control.recommendation || control.summary, 1000),
          markdown: [
            `**${control.title}** — ${control.status === 'MISSING' ? 'контроль не реализован' : 'контроль реализован частично'}`,
            '',
            this.clip(control.summary, 1000),
            control.risk ? `\n**Риск:** ${this.clip(control.risk, 500)}` : '',
            control.recommendation ? `\n**Что сделать:** ${this.clip(control.recommendation, 500)}` : '',
          ].join('\n'),
        },
        defaultConfiguration: { level: mapped.level },
        properties: {
          tags: ['security', 'security-control', `control:${control.control.toLowerCase()}`],
          'security-severity': mapped.securitySeverity,
        },
      });

      results.push({
        ruleId,
        ruleIndex: index,
        level: mapped.level,
        message: { text: `${control.title}: ${this.clip(control.summary, 800)}` },
        locations: [this.location(first.filePath, first.line || 1, first.line || 1)],
        partialFingerprints: {
          primaryLocationLineHash: createHash('sha256')
            .update(`${control.control}|${first.filePath}`)
            .digest('hex')
            .slice(0, 32),
        },
        properties: { controlStatus: control.status },
      });
    }

    const truncated = results.length >= MAX_RESULTS;

    return {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'KMG AI Security Agent',
              informationUri: 'https://github.com/',
              version: '1.0.0',
              rules,
            },
          },
          // Lets GitHub group runs of the same check across commits.
          automationDetails: { id: `kmg-ai/security-scan/${scan.repository.fullName}` },
          versionControlProvenance: scan.commitSha
            ? [
                {
                  repositoryUri: scan.repository.url,
                  revisionId: scan.commitSha,
                  branch: scan.branch || scan.repository.defaultBranch,
                },
              ]
            : undefined,
          results,
          properties: {
            scanId: scan.id,
            policyResult: scan.policyResult,
            riskScore: scan.riskScore,
            totalFindings: scan.findings.length,
            exportedResults: results.length,
            // Контроли без подтверждения из кода намеренно не экспортируются:
            // Code Scanning требует location, а выдумывать его нельзя.
            exportedControls: results.filter(r => String(r.ruleId).startsWith('kmg-control/')).length,
            truncated,
          },
        },
      ],
    };
  }

  /** SARIF must be gzipped and base64-encoded for the Code Scanning API. */
  async buildEncoded(userId: string, scanId: string): Promise<{ sarif: any; encoded: string }> {
    const sarif = await this.build(userId, scanId);
    const encoded = gzipSync(Buffer.from(JSON.stringify(sarif), 'utf8')).toString('base64');
    return { sarif, encoded };
  }

  // ------------------------------------------------------------------ helpers

  private location(filePath: string | null, startLine: number | null, endLine: number | null) {
    // A relative URI is required: an absolute path would not match anything in
    // the repository tree.
    const uri = (filePath || 'unknown').replace(/\\/g, '/').replace(/^\.?\//, '');
    const start = startLine && startLine > 0 ? startLine : 1;
    const end = endLine && endLine >= start ? endLine : start;

    return {
      physicalLocation: {
        artifactLocation: { uri },
        region: { startLine: start, endLine: end },
      },
    };
  }

  private fingerprint(finding: { scanner: string; ruleId: string | null; filePath: string | null; codeSnippet: string | null }) {
    return createHash('sha256')
      .update([finding.scanner, finding.ruleId || '', finding.filePath || '', (finding.codeSnippet || '').trim()].join('|'))
      .digest('hex')
      .slice(0, 32);
  }

  private ruleHelp(finding: { description: string | null; title: string; scanner: string; ruleId: string | null }) {
    return [
      `**${finding.title}**`,
      '',
      finding.description || '',
      '',
      `_Обнаружено: ${finding.scanner}${finding.ruleId ? ` · правило \`${finding.ruleId}\`` : ''}_`,
    ].join('\n');
  }

  /** SARIF rule ids must be stable and free of whitespace. */
  private safeRuleId(scanner: string, ruleId: string | null): string {
    const base = (ruleId || 'unknown-rule').replace(/\s+/g, '-');
    return `${scanner}/${base}`.slice(0, 250);
  }

  private toPascalCase(value: string): string {
    return (value || 'Rule')
      .split(/[^a-zA-Z0-9]+/)
      .filter(Boolean)
      .map(part => part.charAt(0).toUpperCase() + part.slice(1))
      .join('')
      .slice(0, 120) || 'Rule';
  }

  private clip(value: string | null, max: number): string {
    if (!value) return '';
    return value.length > max ? `${value.slice(0, max)}…` : value;
  }
}
