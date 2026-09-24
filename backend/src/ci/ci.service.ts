import { BadRequestException, Injectable, Logger, PayloadTooLargeException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { createHash } from 'crypto';

import { PrismaService } from '../prisma/index.js';
import { ExitCode, PolicyService, ScannerStatusRecord, exitCodeFor } from '../policy/policy.service.js';
import { RequirementsService } from '../requirements/requirements.service.js';
import type { RequirementResult } from '../requirements/requirement-definitions.js';
import { toFindingRow } from '../scan/finding-row.util.js';
import { dedupeFindings } from '../scan/finding-dedup.util.js';
import { DeadlineExceededError, withDeadline } from '../common/utils/deadline.js';
import { SarifService } from '../scan/sarif.service.js';
import { AgentService } from '../agent/agent.service.js';
import { inspectTarGz } from './tar-inspector.js';

const execFileAsync = promisify(execFile);

const ALL_SCANNERS = ['semgrep', 'gitleaks', 'trivy'] as const;

export interface CiScanRequest {
  archive: Buffer;
  repository: string; // owner/name
  githubRepoId?: number;
  commitSha?: string;
  ref?: string;
  prNumber?: number;
  aiMode: 'full' | 'off';
}

export interface CiScanOutcome {
  scanId: string;
  verdict: string; // BLOCK | REVIEW | PASS | INCOMPLETE
  incomplete: boolean;
  riskScore: number | null;
  counts: Record<string, number>;
  reasons: string[];
  scanners: Record<string, ScannerStatusRecord>;
  filesScanned: number;
  aiAnalysisSucceeded: boolean;
  sarif: any;
  /** Сводная часть отчёта (ТЗ п. 4.6.3). */
  commitSha: string | null;
  startedAt: string;
  finishedAt: string;
  durationSeconds: number;
  /** Код завершения по ТЗ п. 4.3.3: 0 / 1 / 2. */
  exitCode: ExitCode;
  /** Статус каждого из требований ИБ-01…ИБ-08, включая не нарушенные. */
  requirements: RequirementResult[];
  violatedRequirements: string[];
  insufficientRequirements: string[];
  /** basis = requirements: решение принято по требованиям ИБ, а не по severity. */
  decisionBasis: 'requirements' | 'severity' | 'incomplete';
}

/**
 * Полный анализ архива кода, присланного из CI.
 *
 * Отличие от /api/prepush/check: тот работает по изменённым файлам и рассчитан
 * на git-хук, где важна скорость. Сюда приходит весь репозиторий из GitHub
 * Actions, прогоняется тот же конвейер, что и при ручном сканировании
 * (Semgrep + Gitleaks + Trivy, затем AI), и наружу отдаётся готовый SARIF,
 * который GitHub принимает в Code Scanning.
 *
 * Репозиторий не обязан быть подключён к KMG через OAuth: workflow сам
 * сообщает owner/name и числовой id из github-контекста.
 */
@Injectable()
export class CiService {
  private readonly logger = new Logger(CiService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
    private readonly policyService: PolicyService,
    private readonly sarifService: SarifService,
    private readonly agentService: AgentService,
    private readonly requirements: RequirementsService,
  ) {}

  private get maxArchiveBytes(): number {
    return Number(this.configService.get<string>('CI_MAX_ARCHIVE_BYTES', String(80 * 1024 * 1024)));
  }

  async scanArchive(userId: string, request: CiScanRequest): Promise<CiScanOutcome> {
    if (!request.archive?.length) {
      throw new BadRequestException('Тело запроса пустое: ожидается архив .tar.gz');
    }
    if (request.archive.length > this.maxArchiveBytes) {
      throw new PayloadTooLargeException(
        `Архив больше ${Math.round(this.maxArchiveBytes / 1024 / 1024)} МБ. ` +
          'Исключите из него node_modules, dist и бинарные артефакты.',
      );
    }

    const repository = await this.resolveRepository(request);
    const scan = await this.prisma.scan.create({
      data: {
        userId,
        repositoryId: repository.id,
        status: 'CLONING',
        branch: this.branchFromRef(request.ref) || repository.defaultBranch,
        commitSha: request.commitSha || null,
        startedAt: new Date(),
      },
    });

    const workspaceRoot =
      this.configService.get<string>('WORKSPACES_ROOT') || path.join(os.tmpdir(), 'kmg_workspaces');
    const workspacePath = path.join(workspaceRoot, `ci-${scan.id}`, 'repository');

    try {
      const filesScanned = await this.unpack(request.archive, workspacePath);
      this.logger.log(
        `CI-скан ${scan.id}: ${request.repository} @ ${(request.commitSha || '').slice(0, 7)} — ${filesScanned} файлов`,
      );

      return await this.runPipeline(userId, scan.id, workspacePath, filesScanned, request);
    } catch (err: any) {
      await this.prisma.scan
        .update({
          where: { id: scan.id },
          data: { status: 'FAILED', errorMessage: String(err.message).slice(0, 500), completedAt: new Date() },
        })
        .catch(() => {});
      throw err;
    } finally {
      await fs.rm(path.dirname(workspacePath), { recursive: true, force: true }).catch(() => {});
    }
  }

  // ------------------------------------------------------------- распаковка

  /**
   * Распаковывает tar.gz в изолированный каталог.
   *
   * Содержимое архива — недоверенные данные, поэтому список записей сначала
   * проверяется: абсолютные пути и выходы через «..» отклоняются до того, как
   * tar что-либо запишет на диск.
   */
  private async unpack(archive: Buffer, workspacePath: string): Promise<number> {
    await fs.mkdir(workspacePath, { recursive: true });
    const archivePath = path.join(path.dirname(workspacePath), 'upload.tar.gz');
    await fs.writeFile(archivePath, archive);

    try {
      // Заголовки разбираются до вызова tar: вывод `tar -tzf` уже нормализован
      // (busybox срезает ведущие «../»), поэтому traversal по нему не виден.
      const inspection = inspectTarGz(archive);
      if (inspection.rejection) {
        throw new BadRequestException(`Архив отклонён: ${inspection.rejection}`);
      }
      this.logger.debug(
        `Архив принят: ${inspection.entries} записей, ` +
          `${Math.round(inspection.totalBytes / 1024)} КБ после распаковки`,
      );

      await execFileAsync('tar', ['-xzf', archivePath, '-C', workspacePath], {
        maxBuffer: 32 * 1024 * 1024,
        timeout: 180_000,
      });
    } catch (err: any) {
      if (err instanceof BadRequestException) throw err;
      throw new BadRequestException(`Не удалось распаковать архив: ${String(err.message).slice(0, 200)}`);
    } finally {
      await fs.rm(archivePath, { force: true }).catch(() => {});
    }

    const count = await this.countFiles(workspacePath);
    if (count === 0) {
      throw new BadRequestException('В архиве нет файлов для анализа');
    }
    return count;
  }

  private async countFiles(dir: string): Promise<number> {
    const ignored = new Set(['.git', 'node_modules', 'dist', 'build', '.next', 'vendor', '__pycache__']);
    let count = 0;

    const walk = async (current: string, depth: number) => {
      if (depth > 12 || count > 50_000) return;
      let entries;
      try {
        entries = await fs.readdir(current, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        if (entry.isDirectory()) {
          if (!ignored.has(entry.name)) await walk(path.join(current, entry.name), depth + 1);
        } else if (entry.isFile()) {
          count++;
        }
      }
    };

    await walk(dir, 0);
    return count;
  }

  // --------------------------------------------------------------- конвейер

  private async runPipeline(
    userId: string,
    scanId: string,
    workspacePath: string,
    filesScanned: number,
    request: CiScanRequest,
  ): Promise<CiScanOutcome> {
    const startedAtMs = Date.now();
    const policySettings = await this.policyService.getSettings();
    const enabledScanners = ALL_SCANNERS.filter(name => policySettings.scanners[name]);

    const scanners: Record<string, ScannerStatusRecord> = {
      semgrep: { status: 'QUEUED', findingsCount: 0, error: null },
      gitleaks: { status: 'QUEUED', findingsCount: 0, error: null },
      trivy: { status: 'QUEUED', findingsCount: 0, error: null },
    };
    for (const name of ALL_SCANNERS) {
      if (!policySettings.scanners[name]) {
        scanners[name].status = 'SKIPPED';
        scanners[name].error = 'Отключён в активной политике';
      }
    }

    await this.prisma.scan.update({ where: { id: scanId }, data: { status: 'SCANNING' } });

    const engineUrl = this.configService.get<string>('SECURITY_ENGINE_URL', 'http://localhost:8000');
    const timeout = Number(this.configService.get<string>('SECURITY_ENGINE_TIMEOUT_MS', '600000')) || 600_000;

    let engineFindings: any[] = [];
    const startedAt = new Date().toISOString();
    for (const name of enabledScanners) {
      scanners[name].status = 'RUNNING';
      scanners[name].startedAt = startedAt;
    }

    try {
      const { data } = await firstValueFrom(
        this.httpService.post(
          `${engineUrl}/scan`,
          { repository_path: workspacePath, scan_id: scanId, scanners: enabledScanners },
          { timeout, headers: this.engineHeaders() },
        ),
      );

      const finishedAt = new Date().toISOString();
      for (const name of enabledScanners) {
        const rec = data?.scanners?.[name];
        if (rec) {
          scanners[name].status = rec.status;
          scanners[name].findingsCount = rec.findingsCount || 0;
          scanners[name].error = rec.error ?? null;
          scanners[name].finishedAt = finishedAt;
        }
      }
      engineFindings = Array.isArray(data?.findings) ? data.findings : [];
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.response?.statusText;
      const message = detail ? `${err.message} (${detail})` : err.message;
      this.logger.error(`CI-скан ${scanId}: движок недоступен — ${message}`);
      const finishedAt = new Date().toISOString();
      for (const name of enabledScanners) {
        scanners[name].status = 'FAILED';
        scanners[name].error = `Security engine недоступен: ${message}`;
        scanners[name].finishedAt = finishedAt;
      }
    }

    if (engineFindings.length > 0) {
      const deduped = dedupeFindings(engineFindings);
      this.logger.log(`CI-скан ${scanId}: находок ${engineFindings.length} → ${deduped.length} после объединения дубликатов между сканерами`);
      const rows = deduped.map(f => toFindingRow(scanId, f));
      try {
        await this.prisma.finding.createMany({ data: rows });
      } catch (err: any) {
        this.logger.warn(`Массовая вставка находок не удалась (${err.message}), вставляю по одной`);
        for (const row of rows) {
          await this.prisma.finding.create({ data: row }).catch(() => {});
        }
      }
    }

    // AI-анализ: разбор находок, цепочки атак и проверка функций ИБ.
    // Падение этого этапа не отменяет результаты сканеров.
    let aiSucceeded = false;
    if (request.aiMode === 'full' && policySettings.aiAnalysis) {
      await this.prisma.scan.update({ where: { id: scanId }, data: { status: 'ANALYZING' } });
      const aiBudgetMs = Number(this.configService.get<string>('AI_STAGE_BUDGET_MS', '480000')) || 480_000;
      try {
        await withDeadline(this.agentService.investigateScan(scanId, workspacePath), aiBudgetMs, 'AI-анализ');
        aiSucceeded = true;
      } catch (err: any) {
        // Исчерпание бюджета — не сбой проверки: вердикт по требованиям ИБ и
        // сканерам от AI не зависит (ТЗ п. 4.7.2: завершаемся корректно, отчёт
        // формируется в объёме выполненного).
        this.logger.warn(
          `CI-скан ${scanId}: AI-анализ ${err instanceof DeadlineExceededError ? 'прерван по бюджету времени' : 'не выполнен'} — ${err.message}`,
        );
      }
    }

    // Обязательные Требования ИБ-01…ИБ-08 (ТЗ п. 4.5). Проверка детерминирована,
    // не зависит ни от сканеров, ни от языковой модели и выполняется даже при
    // отключённом AI-анализе. Здесь анализируется весь проект (ТЗ п. 4.4.1).
    const requirementsOutcome = await this.requirements.evaluate(workspacePath, `CI-скан ${scanId}`);
    await this.requirements.save(scanId, requirementsOutcome.results);

    const findings = await this.prisma.finding.findMany({ where: { scanId } });
    const evalResult = this.policyService.evaluate({
      findings,
      requirements: requirementsOutcome.results,
      scanners,
      repositoryStatus: 'READY',
      requiredScanners: enabledScanners as unknown as string[],
      thresholds: policySettings,
    });

    const counts = {
      CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
      HIGH: findings.filter(f => f.severity === 'HIGH').length,
      MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
      LOW: findings.filter(f => f.severity === 'LOW').length,
      INFO: findings.filter(f => f.severity === 'INFO').length,
    };

    const summary = JSON.stringify({
      stage: evalResult.isIncomplete ? 'PARTIAL' : 'COMPLETED',
      isIncomplete: evalResult.isIncomplete,
      trigger: request.prNumber ? 'ci-pull_request' : 'ci-push',
      scanners,
      aiAnalysisSucceeded: aiSucceeded,
      policyResult: evalResult.result,
      policyReasons: evalResult.reasons,
      statusText: evalResult.statusText,
      riskScore: evalResult.riskScore,
      filesCount: filesScanned,
      branch: this.branchFromRef(request.ref),
      commitSha: request.commitSha,
      prNumber: request.prNumber,
      scannersUsed: Object.keys(scanners),
      policySettings,
      requirements: requirementsOutcome.results.map(r => ({
        requirementId: r.requirementId, status: r.status, summary: r.summary,
      })),
      violatedRequirements: evalResult.violatedRequirements,
      decisionBasis: evalResult.basis,
    });

    await this.prisma.scanResult.upsert({
      where: { scanId },
      create: {
        scanId,
        totalFindings: findings.length,
        criticalCount: counts.CRITICAL,
        highCount: counts.HIGH,
        mediumCount: counts.MEDIUM,
        lowCount: counts.LOW,
        infoCount: counts.INFO,
        riskScore: evalResult.riskScore ?? 0,
        policyResult: evalResult.result ?? 'REVIEW',
        summary,
      },
      update: {
        totalFindings: findings.length,
        criticalCount: counts.CRITICAL,
        highCount: counts.HIGH,
        mediumCount: counts.MEDIUM,
        lowCount: counts.LOW,
        infoCount: counts.INFO,
        riskScore: evalResult.riskScore ?? 0,
        policyResult: evalResult.result ?? 'REVIEW',
        summary,
      },
    });

    await this.prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'COMPLETED',
        riskScore: evalResult.riskScore,
        policyResult: evalResult.result,
        errorMessage: evalResult.isIncomplete ? evalResult.reasons.join('; ') : null,
        completedAt: new Date(),
      },
    });

    const sarif = await this.sarifService.build(userId, scanId);

    this.logger.log(
      `CI-скан ${scanId} завершён: вердикт=${evalResult.result ?? evalResult.statusText}, ` +
        `находок=${findings.length}, AI=${aiSucceeded}`,
    );

    const finishedAtMs = Date.now();

    return {
      scanId,
      // Нарушенное требование — это BLOCK, даже если сканер не завершился.
      verdict:
        evalResult.violatedRequirements.length > 0
          ? 'BLOCK'
          : evalResult.isIncomplete ? 'INCOMPLETE' : evalResult.result || 'UNKNOWN',
      incomplete: evalResult.isIncomplete,
      riskScore: evalResult.riskScore,
      counts,
      reasons: evalResult.reasons,
      scanners,
      filesScanned,
      aiAnalysisSucceeded: aiSucceeded,
      sarif,
      commitSha: request.commitSha ?? null,
      startedAt: new Date(startedAtMs).toISOString(),
      finishedAt: new Date(finishedAtMs).toISOString(),
      durationSeconds: Math.round((finishedAtMs - startedAtMs) / 100) / 10,
      exitCode: exitCodeFor(evalResult),
      requirements: requirementsOutcome.results,
      violatedRequirements: evalResult.violatedRequirements,
      insufficientRequirements: evalResult.insufficientRequirements,
      decisionBasis: evalResult.basis,
    };
  }

  // ------------------------------------------------------------------ utils

  /** Токен доступа к движку (если настроен): движок без него принимает любой путь. */
  private engineHeaders(): Record<string, string> {
    const token = this.configService.get<string>('ENGINE_TOKEN');
    return token ? { 'X-Engine-Token': token } : {};
  }

  /**
   * Репозиторий из CI может быть не подключён к KMG через OAuth, поэтому
   * запись заводится по данным из github-контекста. Если числового id нет,
   * он выводится из полного имени — детерминированно, чтобы повторные запуски
   * не плодили дубликаты.
   */
  private async resolveRepository(request: CiScanRequest) {
    const [owner, name] = (request.repository || '').split('/');
    if (!owner || !name) {
      throw new BadRequestException('Некорректное имя репозитория, ожидается "owner/name"');
    }

    const githubId =
      request.githubRepoId && Number.isInteger(request.githubRepoId)
        ? request.githubRepoId
        : this.syntheticId(request.repository);

    return this.prisma.repository.upsert({
      where: { githubId },
      update: { name, fullName: request.repository, owner },
      create: {
        githubId,
        name,
        fullName: request.repository,
        owner,
        defaultBranch: this.branchFromRef(request.ref) || 'main',
        url: `https://github.com/${request.repository}`,
      },
    });
  }

  /** Стабильный положительный int32 из полного имени репозитория. */
  private syntheticId(fullName: string): number {
    const hash = createHash('sha256').update(fullName).digest();
    return hash.readUInt32BE(0) % 2_000_000_000;
  }

  private branchFromRef(ref?: string): string | null {
    if (!ref) return null;
    const branch = ref.replace(/^refs\/heads\//, '').replace(/^refs\/pull\/(\d+)\/.*$/, 'pr-$1');
    return branch || null;
  }
}
