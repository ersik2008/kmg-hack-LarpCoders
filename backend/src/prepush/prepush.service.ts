import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { randomUUID } from 'crypto';

import { PrismaService } from '../prisma/index.js';
import { ExitCode, PolicyService, ScannerStatusRecord, exitCodeFor } from '../policy/policy.service.js';
import { RequirementsService } from '../requirements/requirements.service.js';
import type { RequirementResult } from '../requirements/requirement-definitions.js';
import { BuiltinScannerService } from '../scan/builtin-scanner.service.js';
import { toFindingRow } from '../scan/finding-row.util.js';
import { dedupeFindings } from '../scan/finding-dedup.util.js';
import { PrePushCheckDto } from './dto/prepush-check.dto.js';
import { EventsService } from '../events/events.service.js';

const ALL_SCANNERS = ['semgrep', 'gitleaks', 'trivy'] as const;

// Согласовано с API_BODY_LIMIT (45mb): 30 МБ сырых данных ≈ 40 МБ в base64.
const MAX_TOTAL_BYTES = 30 * 1024 * 1024;

export interface PrePushFindingView {
  scanner: string;
  ruleId: string | null;
  severity: string;
  confidence: string;
  title: string;
  description: string | null;
  filePath: string | null;
  startLine: number | null;
  endLine: number | null;
  codeSnippet: string | null;
  /** Инструменты, обнаружившие эту проблему (после дедупликации). */
  detectedBy: string[];
}

export interface PrePushCheckResult {
  /** BLOCK / REVIEW / PASS, or null when the scan could not be completed. */
  verdict: 'BLOCK' | 'REVIEW' | 'PASS' | null;
  statusText: string;
  /** true => policy requires enforcement; local hooks remain advisory. */
  blocked: boolean;
  /** true => the scan itself did not finish; a verdict cannot be trusted. */
  incomplete: boolean;
  riskScore: number | null;
  reasons: string[];
  counts: Record<string, number>;
  findings: PrePushFindingView[];
  scanners: Record<string, ScannerStatusRecord>;
  filesChecked: number;
  scanId: string | null;
  /** Ссылка на скан, из которого CI может выгрузить SARIF. */
  sarifAvailable: boolean;
  engineUsed: 'security-engine' | 'builtin-fallback' | 'none';
  /** Сводная часть отчёта (ТЗ п. 4.6.3). */
  commitSha: string | null;
  startedAt: string;
  finishedAt: string;
  durationSeconds: number;
  /** Код завершения по ТЗ п. 4.3.3: 0 / 1 / 2. */
  exitCode: ExitCode;
  /**
   * Оценивались ли требования ИБ. Только при scope=all: сквозные требования
   * (ТЗ п. 1.19) по диффу не устанавливаются, и выдавать вывод по неполному
   * набору файлов было бы подменой.
   */
  requirementsEvaluated: boolean;
  requirements: RequirementResult[];
  violatedRequirements: string[];
  insufficientRequirements: string[];
  decisionBasis: 'requirements' | 'severity' | 'incomplete';
}

@Injectable()
export class PrepushService {
  private readonly logger = new Logger(PrepushService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
    private readonly policyService: PolicyService,
    private readonly builtinScanner: BuiltinScannerService,
    private readonly events: EventsService,
    private readonly requirements: RequirementsService,
  ) {}

  /**
   * Scans the exact file contents a developer is about to push, before git
   * transfers anything to the remote. The response preserves the policy
   * verdict; local hooks report it and CI turns it into a non-zero exit code.
   */
  async check(userId: string, dto: PrePushCheckDto): Promise<PrePushCheckResult> {
    if (!dto.files || dto.files.length === 0) {
      throw new BadRequestException('No files supplied for the pre-push check');
    }

    const startedAtMs = Date.now();
    const workspaceRoot =
      this.configService.get<string>('WORKSPACES_ROOT') || path.join(os.tmpdir(), 'kmg_workspaces');
    const checkId = randomUUID();
    const workspacePath = path.join(workspaceRoot, `prepush-${checkId}`, 'repository');

    const scanners: Record<string, ScannerStatusRecord> = {
      semgrep: { status: 'QUEUED', findingsCount: 0, error: null },
      gitleaks: { status: 'QUEUED', findingsCount: 0, error: null },
      trivy: { status: 'QUEUED', findingsCount: 0, error: null },
    };

    try {
      const written = await this.materialize(workspacePath, dto.files);

      if (written === 0) {
        throw new BadRequestException('None of the supplied files could be written to the scan workspace');
      }

      // Same gate configuration the repository scan uses.
      const policySettings = await this.policyService.getSettings();
      const enabledScanners = ALL_SCANNERS.filter(name => policySettings.scanners[name]);

      for (const name of ALL_SCANNERS) {
        if (!policySettings.scanners[name]) {
          scanners[name].status = 'SKIPPED';
          scanners[name].error = 'Disabled in the active policy';
        }
      }

      const { findings, engineUsed } = await this.runScanners(
        workspacePath,
        checkId,
        scanners,
        enabledScanners as unknown as string[],
        dto.stage,
      );

      // Одна проблема, найденная несколькими инструментами, — одна запись (detectedBy).
      const normalized = dedupeFindings(findings).map(f => toFindingRow('', f));

      // Требования ИБ оцениваются только по полному набору файлов. При scope=changed
      // они не оцениваются вовсе: это честнее, чем вывод по диффу.
      const evaluateRequirements = dto.stage === 'ci' && dto.scope === 'all';
      const requirementsOutcome = evaluateRequirements
        ? await this.requirements.evaluate(workspacePath, `Pre-push ${checkId}`)
        : null;

      const evalResult = this.policyService.evaluate({
        // The policy engine works on persisted Finding rows; the shape produced
        // by toFindingRow is compatible with the fields it reads.
        findings: normalized as any,
        requirements: requirementsOutcome?.results,
        scanners,
        repositoryStatus: 'READY',
        requiredScanners: enabledScanners as unknown as string[],
        thresholds: policySettings,
      });

      const counts = {
        CRITICAL: normalized.filter(f => f.severity === 'CRITICAL').length,
        HIGH: normalized.filter(f => f.severity === 'HIGH').length,
        MEDIUM: normalized.filter(f => f.severity === 'MEDIUM').length,
        LOW: normalized.filter(f => f.severity === 'LOW').length,
        INFO: normalized.filter(f => f.severity === 'INFO').length,
      };

      // BLOCK and INCOMPLETE remain real policy decisions. The caller decides
      // whether to apply them as local advisory feedback or CI enforcement.
      const blocked = evalResult.isBlocked || evalResult.isIncomplete || evalResult.violatedRequirements.length > 0;

      const persisted = await this.persist(userId, dto, evalResult, normalized, scanners, counts, engineUsed);
      const scanId = persisted?.scanId ?? null;

      if (persisted && requirementsOutcome) {
        await this.requirements.save(persisted.scanId, requirementsOutcome.results);
      }
      const finishedAtMs = Date.now();

      // Страница репозиториев ждёт результат push-проверки: событие доводит
      // вердикт до открытых вкладок сразу, без ожидания следующего опроса.
      if (persisted) {
        this.events.emit({
          type: 'scan.completed',
          userId,
          scanId: persisted.scanId,
          repositoryId: persisted.repositoryId,
          payload: {
            repository: dto.repository ?? null,
            verdict: evalResult.result,
            blocked,
            branch: dto.branch ?? null,
          },
        });
      }

      this.logger.log(
        `Pre-push check ${checkId} (${dto.repository || 'unknown repo'}): ` +
          `${normalized.length} findings, verdict=${evalResult.result ?? evalResult.statusText}, blocked=${blocked}`,
      );

      return {
        verdict: (evalResult.violatedRequirements.length > 0
          ? 'BLOCK'
          : evalResult.result) as PrePushCheckResult['verdict'],
        statusText: evalResult.statusText,
        blocked,
        incomplete: evalResult.isIncomplete,
        riskScore: evalResult.riskScore,
        reasons: evalResult.reasons,
        counts,
        findings: normalized.map(f => ({
          scanner: f.scanner,
          ruleId: f.ruleId ?? null,
          severity: f.severity,
          confidence: f.confidence,
          title: f.title,
          description: f.description ?? null,
          filePath: f.filePath ?? null,
          startLine: f.startLine ?? null,
          endLine: f.endLine ?? null,
          codeSnippet: f.codeSnippet ?? null,
          detectedBy: Array.isArray((f.metadata as any)?.detectedBy) ? (f.metadata as any).detectedBy : [f.scanner],
        })),
        scanners,
        filesChecked: written,
        scanId,
        sarifAvailable: Boolean(scanId),
        engineUsed,
        commitSha: dto.commitSha ?? null,
        startedAt: dto.startedAt || new Date(startedAtMs).toISOString(),
        finishedAt: new Date(finishedAtMs).toISOString(),
        durationSeconds: Math.round((finishedAtMs - startedAtMs) / 100) / 10,
        exitCode: exitCodeFor(evalResult),
        requirementsEvaluated: Boolean(requirementsOutcome),
        requirements: requirementsOutcome?.results ?? [],
        violatedRequirements: evalResult.violatedRequirements,
        insufficientRequirements: evalResult.insufficientRequirements,
        decisionBasis: evalResult.basis,
      };
    } finally {
      await fs.rm(path.dirname(workspacePath), { recursive: true, force: true }).catch(() => {});
    }
  }

  /** Токен доступа к движку (если настроен): движок без него принимает любой путь. */
  private engineHeaders(): Record<string, string> {
    const token = this.configService.get<string>('ENGINE_TOKEN');
    return token ? { 'X-Engine-Token': token } : {};
  }

  /** Writes the pushed blobs into an isolated workspace the scanners can read. */
  private async materialize(workspacePath: string, files: PrePushCheckDto['files']): Promise<number> {
    await fs.mkdir(workspacePath, { recursive: true });

    let written = 0;
    let totalBytes = 0;

    for (const file of files) {
      const relPath = this.safeRelativePath(file.path);
      if (!relPath) {
        this.logger.warn(`Rejected unsafe path in pre-push payload: ${file.path}`);
        continue;
      }

      let buffer: Buffer;
      try {
        buffer = Buffer.from(file.contentBase64, 'base64');
      } catch {
        this.logger.warn(`Rejected undecodable content for ${relPath}`);
        continue;
      }

      totalBytes += buffer.length;
      if (totalBytes > MAX_TOTAL_BYTES) {
        throw new BadRequestException(
          `Pre-push payload exceeds ${Math.round(MAX_TOTAL_BYTES / 1024 / 1024)}MB. Push smaller batches.`,
        );
      }

      const target = path.join(workspacePath, relPath);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, buffer);
      written++;
    }

    return written;
  }

  /** Rejects absolute paths and any traversal outside the workspace. */
  private safeRelativePath(raw: string): string | null {
    if (!raw) return null;
    const cleaned = raw.replace(/\\/g, '/').replace(/^\.\//, '');
    if (cleaned.startsWith('/') || /^[a-zA-Z]:/.test(cleaned)) return null;
    const normalized = path.posix.normalize(cleaned);
    if (normalized.startsWith('..') || normalized.split('/').includes('..')) return null;
    if (!normalized || normalized === '.') return null;
    return normalized;
  }

  private async runScanners(
    workspacePath: string,
    checkId: string,
    scanners: Record<string, ScannerStatusRecord>,
    enabledScanners: string[],
    stage?: string,
  ): Promise<{ findings: any[]; engineUsed: PrePushCheckResult['engineUsed'] }> {
    const securityEngineUrl = this.configService.get<string>('SECURITY_ENGINE_URL', 'http://localhost:8000');
    // Проверка в CI охватывает весь проект (ТЗ п. 4.4.1) и идёт дольше диффа перед
    // push: ей нужен тот же бюджет, что у полного скана, а не 5 минут «быстрого» хука.
    const timeout = stage === 'ci'
      ? Number(this.configService.get<string>('SECURITY_ENGINE_TIMEOUT_MS', '600000')) || 600000
      : Number(this.configService.get<string>('PREPUSH_ENGINE_TIMEOUT_MS', '300000')) || 300000;

    const startedAt = new Date().toISOString();
    for (const name of enabledScanners) {
      scanners[name].status = 'RUNNING';
      scanners[name].startedAt = startedAt;
    }

    try {
      const { data } = await firstValueFrom(
        this.httpService.post(
          `${securityEngineUrl}/scan`,
          { repository_path: workspacePath, scan_id: `prepush-${checkId}`, scanners: enabledScanners },
          { timeout, headers: this.engineHeaders() },
        ),
      );

      const finishedAt = new Date().toISOString();
      if (data?.scanners) {
        for (const name of enabledScanners) {
          const rec = data.scanners[name];
          if (rec) {
            scanners[name].status = rec.status;
            scanners[name].findingsCount = rec.findingsCount || 0;
            scanners[name].error = rec.error ?? null;
            scanners[name].finishedAt = finishedAt;
          }
        }
      }

      const engineFindings = Array.isArray(data?.findings) ? data.findings : [];
      const allFailed = enabledScanners.every(n => scanners[n].status !== 'COMPLETED');

      if (allFailed) {
        const fallback = await this.runFallback(workspacePath, scanners);
        return { findings: [...engineFindings, ...fallback], engineUsed: 'builtin-fallback' };
      }

      return { findings: engineFindings, engineUsed: 'security-engine' };
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.response?.statusText;
      const message = detail ? `${err.message} (${detail})` : err.message;
      this.logger.error(`Pre-push: security engine unavailable: ${message}`);

      const finishedAt = new Date().toISOString();
      for (const name of enabledScanners) {
        scanners[name].status = 'FAILED';
        scanners[name].error = `Security engine unavailable: ${message}`;
        scanners[name].finishedAt = finishedAt;
      }

      const fallback = await this.runFallback(workspacePath, scanners);
      return { findings: fallback, engineUsed: fallback.length >= 0 ? 'builtin-fallback' : 'none' };
    }
  }

  /**
   * Best-effort local analysis so the developer still gets actionable output
   * when the engine is down. It never satisfies the required-scanner policy,
   * so the verdict stays "incomplete" and the push is still blocked.
   */
  private async runFallback(
    workspacePath: string,
    scanners: Record<string, ScannerStatusRecord>,
  ): Promise<any[]> {
    try {
      const findings = await this.builtinScanner.scanWorkspace(workspacePath);
      scanners['builtin_fallback'] = {
        status: 'COMPLETED',
        findingsCount: findings.length,
        error: null,
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
      };
      return findings;
    } catch (err: any) {
      scanners['builtin_fallback'] = {
        status: 'FAILED',
        findingsCount: 0,
        error: err.message,
      };
      return [];
    }
  }

  /** Stores the pre-push check as a normal scan so it shows up in the UI. */
  private async persist(
    userId: string,
    dto: PrePushCheckDto,
    evalResult: ReturnType<PolicyService['evaluate']>,
    rows: ReturnType<typeof toFindingRow>[],
    scanners: Record<string, ScannerStatusRecord>,
    counts: Record<string, number>,
    engineUsed: string,
  ): Promise<{ scanId: string; repositoryId: string } | null> {
    if (!dto.repository) return null;

    const repo = await this.prisma.repository.findFirst({ where: { fullName: dto.repository } });
    if (!repo) {
      this.logger.warn(`Pre-push check for unknown repository '${dto.repository}' — result not persisted`);
      return null;
    }

    try {
      const scan = await this.prisma.scan.create({
        data: {
          userId,
          repositoryId: repo.id,
          status: evalResult.isIncomplete ? 'FAILED' : 'COMPLETED',
          branch: dto.branch ?? null,
          commitSha: dto.commitSha ?? null,
          startedAt: new Date(),
          completedAt: new Date(),
          riskScore: evalResult.riskScore,
          policyResult: evalResult.result,
          errorMessage: evalResult.isIncomplete ? evalResult.reasons.join('; ') : null,
        },
      });

      if (rows.length > 0) {
        await this.prisma.finding.createMany({
          data: rows.map(r => ({ ...r, scanId: scan.id })),
        });
      }

      await this.prisma.scanResult.create({
        data: {
          scanId: scan.id,
          totalFindings: rows.length,
          criticalCount: counts.CRITICAL,
          highCount: counts.HIGH,
          mediumCount: counts.MEDIUM,
          lowCount: counts.LOW,
          infoCount: counts.INFO,
          riskScore: evalResult.riskScore ?? 0,
          policyResult: evalResult.result ?? 'REVIEW',
          summary: JSON.stringify({
            stage: evalResult.isIncomplete ? 'PARTIAL' : 'COMPLETED',
            isIncomplete: evalResult.isIncomplete,
            trigger: dto.stage || 'pre-push',
            engineUsed,
            scanners,
            policyResult: evalResult.result,
            policyReasons: evalResult.reasons,
            statusText: evalResult.statusText,
            riskScore: evalResult.riskScore,
            filesCount: dto.files.length,
            branch: dto.branch,
            commitSha: dto.commitSha,
            remote: dto.remote,
            scannersUsed: Object.keys(scanners),
          }),
        },
      });

      return { scanId: scan.id, repositoryId: repo.id };
    } catch (err: any) {
      // Never fail the developer's push because of a bookkeeping problem.
      this.logger.error(`Failed to persist pre-push scan: ${err.message}`);
      return null;
    }
  }
}
