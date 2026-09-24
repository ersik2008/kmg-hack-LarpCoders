import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/index.js';
import { RepositoryService } from '../repository/repository.service.js';
import { AgentService } from '../agent/agent.service.js';
import { PolicyService, ScannerStatusRecord } from '../policy/policy.service.js';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

import { BuiltinScannerService } from './builtin-scanner.service.js';
import { ArchitectureService } from './architecture.service.js';
import { OllamaService } from '../ai/ollama.service.js';
import { toFindingRow } from './finding-row.util.js';
import { dedupeFindings } from './finding-dedup.util.js';
import { withDeadline } from '../common/utils/deadline.js';
import { GithubStatusService, GateReport } from '../github/github-status.service.js';
import { SarifService } from './sarif.service.js';
import { EventsService } from '../events/events.service.js';
import { RequirementsService } from '../requirements/requirements.service.js';

export interface StartScanOptions {
  branch?: string;
  /** What kicked the scan off. CI triggers publish the verdict back to GitHub. */
  trigger?: 'manual' | 'push' | 'pull_request';
  /** PR number, when the scan was triggered by a pull_request webhook. */
  prNumber?: number;
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

@Injectable()
export class ScanService {
  private readonly logger = new Logger(ScanService.name);

  constructor(
    private prisma: PrismaService,
    private repositoryService: RepositoryService,
    private agentService: AgentService,
    private policyService: PolicyService,
    private httpService: HttpService,
    private configService: ConfigService,
    private builtinScanner: BuiltinScannerService,
    private architectureService: ArchitectureService,
    private groqService: OllamaService,
    private githubStatus: GithubStatusService,
    private sarifService: SarifService,
    private events: EventsService,
    private requirementsService: RequirementsService,
  ) {}

  async startScan(userId: string, repositoryId: string, options?: StartScanOptions) {
    const scan = await this.prisma.scan.create({
      data: {
        userId,
        repositoryId,
        status: 'PENDING',
        startedAt: new Date(),
      }
    });

    // Let GitHub show "checks running" right away for CI-triggered scans.
    if (options?.trigger && options.trigger !== 'manual') {
      this.announcePending(userId, repositoryId, scan.id).catch(() => {});
    }

    // Run pipeline asynchronously
    this.runPipeline(userId, repositoryId, scan.id, options).catch(err => {
      this.logger.error(`Pipeline uncaught failure for scan ${scan.id}: ${err.message}`);
      this.prisma.scan.update({
        where: { id: scan.id },
        data: {
          status: 'FAILED',
          errorMessage: `Pipeline error: ${err.message}`,
          completedAt: new Date()
        }
      }).catch(() => {});
    });

    return { scanId: scan.id, status: 'PENDING' };
  }

  private async runPipeline(
    userId: string,
    repositoryId: string,
    scanId: string,
    options?: StartScanOptions
  ) {
    let workspacePath: string | null = null;
    let repositoryStatus: 'READY' | 'FAILED' | 'INCOMPLETE' = 'INCOMPLETE';

    // Live gate configuration from the database — the Settings screen controls
    // which scanners actually run and where the BLOCK/REVIEW lines sit.
    const policySettings = await this.policyService.getSettings();
    const enabledScanners = (['semgrep', 'gitleaks', 'trivy'] as const).filter(
      name => policySettings.scanners[name],
    );

    const scanners: Record<string, ScannerStatusRecord> = {
      semgrep: { status: 'QUEUED', findingsCount: 0, error: null },
      gitleaks: { status: 'QUEUED', findingsCount: 0, error: null },
      trivy: { status: 'QUEUED', findingsCount: 0, error: null },
    };

    try {
      // 1. STAGE: PREPARING_WORKSPACE / CLONING (CASE B)
      await this.updateStatus(scanId, 'CLONING');
      let cloneMeta: any;

      try {
        cloneMeta = await this.repositoryService.cloneRepositoryWithMeta(
          userId,
          repositoryId,
          scanId,
          options?.branch,
        );
        workspacePath = cloneMeta.workspacePath;
      } catch (cloneErr: any) {
        // CASE B: Repository clone failed -> FAILED / INCOMPLETE. CANNOT BE PASS.
        this.logger.error(`Scan ${scanId} clone failed: ${cloneErr.message}`);
        await this.prisma.scan.update({
          where: { id: scanId },
          data: {
            status: 'FAILED',
            errorMessage: `Repository clone failed: ${cloneErr.message}`,
            completedAt: new Date(),
          }
        });
        await this.publishGate(userId, repositoryId, scanId, options, {
          state: 'error',
          description: 'Не удалось подготовить репозиторий — проверка не выполнена',
        }).catch(() => {});
        return;
      }

      // Persist branch and commit SHA
      await this.prisma.scan.update({
        where: { id: scanId },
        data: {
          branch: cloneMeta.branch,
          commitSha: cloneMeta.commitSha,
        }
      });

      // 2. STAGE: REPOSITORY_READY & INDEXING (CASE G)
      if (cloneMeta.fileCount <= 0) {
        // CASE G: Empty or damaged repository -> CANNOT BE PASS.
        const errMsg = 'Repository workspace contains 0 source files. Cannot verify security.';
        this.logger.warn(`Scan ${scanId} failed: ${errMsg}`);
        await this.prisma.scan.update({
          where: { id: scanId },
          data: {
            status: 'FAILED',
            errorMessage: errMsg,
            completedAt: new Date(),
          }
        });
        return;
      }

      repositoryStatus = 'READY';

      // 3. STAGE: SCANNING (Execute Real Scanners & Track Statuses: CASE C, D, E, F, H)
      await this.updateStatus(scanId, 'SCANNING');
      const scanStartTime = new Date().toISOString();
      for (const name of ['semgrep', 'gitleaks', 'trivy'] as const) {
        if (policySettings.scanners[name]) {
          scanners[name].status = 'RUNNING';
          scanners[name].startedAt = scanStartTime;
        } else {
          scanners[name].status = 'SKIPPED';
          scanners[name].error = 'Disabled in the active policy';
        }
      }

      const securityEngineUrl = this.configService.get<string>('SECURITY_ENGINE_URL', 'http://localhost:8000');
      // Semgrep + Gitleaks + Trivy on a real repository regularly needs several
      // minutes. The old 60s timeout aborted healthy scans and made every scan
      // look like "security engine unreachable".
      const engineTimeout = Number(this.configService.get<string>('SECURITY_ENGINE_TIMEOUT_MS', '600000')) || 600000;
      let engineFindings: any[] = [];
      let engineSuccess = false;

      try {
        const { data } = await firstValueFrom(
          this.httpService.post(`${securityEngineUrl}/scan`, {
            repository_path: workspacePath,
            scan_id: scanId,
            scanners: enabledScanners,
          }, { timeout: engineTimeout, headers: this.engineHeaders() })
        );

        if (data && data.scanners) {
          engineSuccess = true;
          const finishedAt = new Date().toISOString();

          // Semgrep
          if (data.scanners.semgrep) {
            scanners.semgrep.status = data.scanners.semgrep.status;
            scanners.semgrep.findingsCount = data.scanners.semgrep.findingsCount || 0;
            scanners.semgrep.error = data.scanners.semgrep.error;
            scanners.semgrep.finishedAt = finishedAt;
          }

          // Gitleaks
          if (data.scanners.gitleaks) {
            scanners.gitleaks.status = data.scanners.gitleaks.status;
            scanners.gitleaks.findingsCount = data.scanners.gitleaks.findingsCount || 0;
            scanners.gitleaks.error = data.scanners.gitleaks.error;
            scanners.gitleaks.finishedAt = finishedAt;
          }

          // Trivy
          if (data.scanners.trivy) {
            scanners.trivy.status = data.scanners.trivy.status;
            scanners.trivy.findingsCount = data.scanners.trivy.findingsCount || 0;
            scanners.trivy.error = data.scanners.trivy.error;
            scanners.trivy.finishedAt = finishedAt;
          }

          if (Array.isArray(data.findings)) {
            engineFindings = data.findings;
          }
        }
      } catch (engineErr: any) {
        // CASE F: Security engine crashed / unreachable
        const detail = engineErr?.response?.data?.detail || engineErr?.response?.statusText;
        const engineErrMsg = detail ? `${engineErr.message} (${detail})` : engineErr.message;
        this.logger.error(`Security engine unreachable or crashed: ${engineErrMsg}`);
        const finishedAt = new Date().toISOString();
        for (const name of enabledScanners) {
          scanners[name].status = 'FAILED';
          scanners[name].error = `Security engine unavailable: ${engineErrMsg}`;
          scanners[name].finishedAt = finishedAt;
        }
      }

      // Run the built-in scanner as an explicit fallback when the real engine was
      // unreachable *or* answered but produced no usable scanner run at all.
      // Without this, a fully failed engine silently yielded "0 findings".
      const allRequiredFailed = enabledScanners.every(
        name => scanners[name]?.status !== 'COMPLETED'
      );

      let fallbackFindings: any[] = [];
      if ((!engineSuccess || allRequiredFailed) && workspacePath) {
        this.logger.log(`Invoking fallback built-in scanner for scan ${scanId}`);
        fallbackFindings = await this.builtinScanner.scanWorkspace(workspacePath);
        scanners['builtin_fallback'] = {
          status: 'COMPLETED',
          findingsCount: fallbackFindings.length,
          error: null,
          startedAt: new Date().toISOString(),
          finishedAt: new Date().toISOString()
        };
      }

      // Одна проблема, найденная несколькими инструментами, — одна запись (detectedBy).
      const allFindingsToPersist = dedupeFindings([...engineFindings, ...fallbackFindings]);

      if (allFindingsToPersist.length > 0) {
        // Normalize defensively: one malformed row used to abort the whole
        // createMany, which turned a successful scan into "0 findings".
        const rows = allFindingsToPersist.map((f: any) => toFindingRow(scanId, f));
        try {
          await this.prisma.finding.createMany({ data: rows });
        } catch (persistErr: any) {
          this.logger.error(`Bulk finding persistence failed (${persistErr.message}), falling back to row-by-row insert`);
          let persisted = 0;
          for (const row of rows) {
            try {
              await this.prisma.finding.create({ data: row });
              persisted++;
            } catch (rowErr: any) {
              this.logger.warn(`Dropping unpersistable finding ${row.ruleId}: ${rowErr.message}`);
            }
          }
          if (persisted === 0) {
            throw new Error(`None of the ${rows.length} detected findings could be stored: ${persistErr.message}`);
          }
        }
      }

      // 4. STAGE: BUILDING_ARCHITECTURE (Graph A - Always created for real repo)
      let archResult: any = null;
      if (workspacePath) {
        try {
          archResult = await this.architectureService.analyzeWorkspace(workspacePath);
          this.logger.log(`Architecture extracted: ${archResult.nodes.length} nodes, ${archResult.filesCount} files`);
        } catch (archErr: any) {
          this.logger.warn(`Architecture extraction warning: ${archErr.message}`);
        }
      }

      // 5. STAGE: INVESTIGATING & AI_ANALYSIS (CASE I)
      await this.updateStatus(scanId, 'ANALYZING');
      let aiAnalysisSucceeded = false;
      try {
        if (workspacePath && policySettings.aiAnalysis) {
          const aiBudgetMs = Number(this.configService.get<string>('AI_STAGE_BUDGET_MS', '480000')) || 480_000;
          await withDeadline(this.agentService.investigateScan(scanId, workspacePath), aiBudgetMs, 'AI-анализ');
          aiAnalysisSucceeded = true;
        }
      } catch (agentErr: any) {
        // CASE I: AI Agent failed -> deterministic findings survive; scan continues
        this.logger.warn(`AI Agent investigation failed: ${agentErr.message}. Preserving deterministic scanner results.`);
      }

      // 6. STAGE: GRAPHING & RISK_ANALYSIS & POLICY_EVALUATION
      await this.updateStatus(scanId, 'GRAPHING');
      await this.updateStatus(scanId, 'RISK_CALCULATING');

      const allFindings = await this.prisma.finding.findMany({ where: { scanId } });
      const filesCount = archResult?.filesCount ?? cloneMeta.fileCount ?? 0;

      // Обязательные Требования ИБ-01…ИБ-08 (ТЗ п. 4.5): весь клонированный
      // проект, детерминированно, независимо от сканеров и от AI-анализа.
      const requirementsOutcome = workspacePath
        ? await this.requirementsService.evaluate(workspacePath, `Scan ${scanId}`)
        : null;
      if (requirementsOutcome) {
        await this.requirementsService.save(scanId, requirementsOutcome.results);
      }

      // 7. DETERMINISTIC POLICY EVALUATION
      const policyInput = {
        findings: allFindings,
        requirements: requirementsOutcome?.results,
        scanners,
        repositoryStatus,
        hasConfirmedAttackPaths: false,
        requiredScanners: enabledScanners as unknown as string[],
        thresholds: policySettings,
      };

      const evalResult = this.policyService.evaluate(policyInput);

      const criticalCount = allFindings.filter(f => f.severity === 'CRITICAL').length;
      const highCount = allFindings.filter(f => f.severity === 'HIGH').length;
      const mediumCount = allFindings.filter(f => f.severity === 'MEDIUM').length;
      const lowCount = allFindings.filter(f => f.severity === 'LOW').length;
      const infoCount = allFindings.filter(f => f.severity === 'INFO').length;

      // Determine final scan lifecycle status
      let finalStatus: 'COMPLETED' | 'FAILED' = 'COMPLETED';
      let overallStage: 'COMPLETED' | 'PARTIAL' | 'FAILED' = 'COMPLETED';

      if (evalResult.isIncomplete) {
        overallStage = 'PARTIAL';
      }

      // Summary data with explicit scanner statuses and policy reasons
      const summaryData = {
        stage: overallStage,
        // Consumed by the UI to raise the "scan incomplete" banner. Without it
        // a PARTIAL scan was rendered as a normal finished scan.
        isIncomplete: evalResult.isIncomplete,
        scanners,
        aiAnalysisSucceeded,
        policyResult: evalResult.result,
        riskScore: evalResult.riskScore,
        policyReasons: evalResult.reasons,
        statusText: evalResult.statusText,
        filesCount,
        linesCount: archResult?.linesCount || 0,
        languages: archResult?.languages || ['Source Code'],
        scannersUsed: Object.keys(scanners),
        policySettings,
        requirements: (requirementsOutcome?.results ?? []).map(r => ({
          requirementId: r.requirementId, status: r.status, summary: r.summary,
        })),
        violatedRequirements: evalResult.violatedRequirements,
        decisionBasis: evalResult.basis,
        fileTree: archResult?.fileTree || [],
        architectureNodes: archResult?.nodes || [],
        architectureEdges: archResult?.edges || [],
        branch: cloneMeta.branch,
        commitSha: cloneMeta.commitSha,
        scannerErrors: Object.entries(scanners)
          .filter(([, rec]) => rec.status !== 'COMPLETED' || rec.error)
          .map(([name, rec]) => ({ scanner: name, status: rec.status, error: rec.error || null })),
      };

      // scan_results.policyResult is NOT NULL and defaults to PASS, so an
      // undefined verdict used to be persisted as PASS. An incomplete scan is
      // never a pass: store REVIEW and keep the authoritative (nullable)
      // verdict on the scan row itself.
      const storedPolicyResult = evalResult.result ?? 'REVIEW';

      await this.prisma.scanResult.upsert({
        where: { scanId },
        create: {
          scanId,
          totalFindings: allFindings.length,
          criticalCount,
          highCount,
          mediumCount,
          lowCount,
          infoCount,
          riskScore: evalResult.riskScore ?? 0,
          policyResult: storedPolicyResult,
          summary: JSON.stringify(summaryData),
        },
        update: {
          totalFindings: allFindings.length,
          criticalCount,
          highCount,
          mediumCount,
          lowCount,
          infoCount,
          riskScore: evalResult.riskScore ?? 0,
          policyResult: storedPolicyResult,
          summary: JSON.stringify(summaryData),
        }
      });

      await this.prisma.scan.update({
        where: { id: scanId },
        data: {
          status: finalStatus,
          riskScore: evalResult.riskScore,
          policyResult: evalResult.result,
          errorMessage: evalResult.isIncomplete ? evalResult.reasons.join('; ') : null,
          completedAt: new Date(),
        }
      });

      this.logger.log(`Scan ${scanId} completed. Stage: ${overallStage}, Verdict: ${evalResult.result || 'NONE (PARTIAL)'}`);

      // Открытые вкладки узнают о готовом отчёте сразу: раньше событие слала
      // только pre-push проверка, а обычный скан заканчивался молча.
      this.events.emit({
        type: 'scan.completed',
        userId,
        scanId,
        repositoryId,
        payload: {
          verdict: evalResult.result,
          blocked: evalResult.isBlocked,
          status: finalStatus,
          riskScore: evalResult.riskScore,
        },
      });

      // Push the gate verdict back into GitHub so branch protection can act on it.
      await this.publishGate(userId, repositoryId, scanId, options, {
        state: evalResult.isIncomplete ? 'error' : evalResult.result === 'BLOCK' ? 'failure' : 'success',
        description: evalResult.isIncomplete
          ? 'Сканирование не завершено — вердикт не вынесен'
          : evalResult.result === 'BLOCK'
            ? (evalResult.violatedRequirements.length > 0
                ? `BLOCK: нарушены требования ИБ ${evalResult.violatedRequirements.join(', ')}`
                : `BLOCK: критических ${criticalCount}, high ${highCount} (риск ${evalResult.riskScore}/10)`)
            : evalResult.result === 'REVIEW'
              ? `REVIEW: найдено ${allFindings.length} проблем (риск ${evalResult.riskScore}/10)`
              : 'PASS: критических уязвимостей не найдено',
        counts: {
          CRITICAL: criticalCount, HIGH: highCount, MEDIUM: mediumCount, LOW: lowCount, INFO: infoCount,
        },
        reasons: evalResult.reasons,
        findings: allFindings
          .slice()
          .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
          .map(f => ({
            severity: f.severity,
            title: f.title,
            filePath: f.filePath,
            startLine: f.startLine,
            scanner: f.scanner,
            ruleId: f.ruleId,
          })),
      }).catch(err => this.logger.warn(`Gate publication failed: ${err.message}`));

      // Для CI-сканов дополнительно выгружаем SARIF в Code Scanning: находки
      // попадают во вкладку Security репозитория, с аннотациями на строках.
      if (options?.trigger && options.trigger !== 'manual') {
        this.uploadSarifToGithub(userId, scanId)
          .then(res => {
            if (res.uploaded) this.logger.log(`Scan ${scanId}: SARIF опубликован в Code Scanning`);
            else this.logger.warn(`Scan ${scanId}: SARIF не выгружен — ${res.error}`);
          })
          .catch(err => this.logger.warn(`SARIF upload failed: ${err.message}`));
      }

    } catch (pipelineErr: any) {
      this.logger.error(`Fatal error in scan pipeline ${scanId}: ${pipelineErr.message}`);
      await this.prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'FAILED',
          errorMessage: `Pipeline fatal error: ${pipelineErr.message}`,
          completedAt: new Date(),
        }
      }).catch(() => {});
      await this.publishGate(userId, repositoryId, scanId, options, {
        state: 'error',
        description: 'Сбой конвейера проверки — вердикт не вынесен',
      }).catch(() => {});
    }
  }

  /** Токен доступа к движку (если настроен): движок без него принимает любой путь. */
  private engineHeaders(): Record<string, string> {
    const token = this.configService.get<string>('ENGINE_TOKEN');
    return token ? { 'X-Engine-Token': token } : {};
  }

  /** Marks the commit as "running" as soon as a CI-triggered scan starts. */
  private async announcePending(userId: string, repositoryId: string, scanId: string) {
    const repo = await this.prisma.repository.findUnique({ where: { id: repositoryId } });
    const scan = await this.prisma.scan.findUnique({ where: { id: scanId } });
    if (!repo || !scan?.commitSha) return;
    await this.githubStatus.publishPending(userId, repo.fullName, scan.commitSha, scanId);
  }

  /**
   * Publishes the gate verdict to GitHub for CI-triggered scans: a commit
   * status always, plus a comment when the scan came from a pull request.
   * Manual scans stay inside the dashboard.
   */
  private async publishGate(
    userId: string,
    repositoryId: string,
    scanId: string,
    options: StartScanOptions | undefined,
    report: GateReport,
  ) {
    if (!options?.trigger || options.trigger === 'manual') return;

    const repo = await this.prisma.repository.findUnique({ where: { id: repositoryId } });
    const scan = await this.prisma.scan.findUnique({ where: { id: scanId } });
    if (!repo || !scan?.commitSha) {
      this.logger.warn(`Cannot publish gate for scan ${scanId}: repository or commit SHA unknown`);
      return;
    }

    await this.githubStatus.publishStatus(userId, repo.fullName, scan.commitSha, scanId, report);

    if (options.trigger === 'pull_request' && options.prNumber) {
      await this.githubStatus.publishPullRequestComment(
        userId, repo.fullName, options.prNumber, scanId, report,
      );
    }
  }

  /**
   * Updates the scan status and pushes the change to the open browser tabs.
   *
   * Without the event the UI only learned about progress on its next poll, so
   * a running scan looked frozen and a finished one needed a manual refresh.
   */
  private async updateStatus(scanId: string, status: any) {
    this.logger.log(`Scan ${scanId} status changed to ${status}`);
    const scan = await this.prisma.scan.update({
      where: { id: scanId },
      data: { status },
    });

    this.events.emit({
      type: 'scan.progress',
      userId: scan.userId,
      scanId: scan.id,
      repositoryId: scan.repositoryId,
      payload: { status },
    });
  }

  async getScanById(userId: string, scanId: string) {
    const scan = await this.prisma.scan.findFirst({
      where: { id: scanId, userId },
      include: {
        repository: true,
        findings: true,
        aiAnalyses: true,
        graphNodes: true,
        graphEdges: true,
        scanResult: true,
        controls: { orderBy: { control: 'asc' } },
      }
    });

    if (!scan) throw new NotFoundException('Scan not found');
    return scan;
  }

  async getUserScans(userId: string) {
    return this.prisma.scan.findMany({
      where: { userId },
      include: {
        repository: true,
        findings: true,
        scanResult: true,
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  /**
   * Findings of the latest COMPLETED scan of one repository, with the AI
   * verdict attached to each one.
   *
   * Aggregating every scan of every repository counted the same defect once per
   * run, so the totals grew with each re-scan instead of describing the current
   * state of a project.
   */
  async getLatestFindings(userId: string, repositoryId?: string) {
    const scan = await this.prisma.scan.findFirst({
      where: {
        userId,
        status: 'COMPLETED',
        ...(repositoryId ? { repositoryId } : {}),
      },
      include: {
        repository: true,
        findings: { orderBy: { createdAt: 'asc' } },
        aiAnalyses: { where: { type: 'finding_triage' } },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!scan) {
      return { scan: null, findings: [] };
    }

    const verdictByFinding = new Map<string, any>();
    for (const analysis of scan.aiAnalyses) {
      if (analysis.findingId) verdictByFinding.set(analysis.findingId, analysis.metadata);
    }

    return {
      scan: {
        id: scan.id,
        branch: scan.branch,
        commitSha: scan.commitSha,
        completedAt: scan.completedAt,
        createdAt: scan.createdAt,
        policyResult: scan.policyResult,
        riskScore: scan.riskScore,
        repository: scan.repository
          ? { id: scan.repository.id, name: scan.repository.name, fullName: scan.repository.fullName }
          : null,
      },
      findings: scan.findings.map(f => ({
        ...f,
        aiVerdict: verdictByFinding.get(f.id) ?? null,
      })),
    };
  }

  async buildSarif(userId: string, scanId: string) {
    return this.sarifService.build(userId, scanId);
  }

  /**
   * Publishes the scan to GitHub Code Scanning so the findings appear in the
   * repository's own Security tab rather than only in this dashboard.
   */
  async uploadSarifToGithub(userId: string, scanId: string) {
    const scan = await this.getScanById(userId, scanId);

    if (!scan.commitSha) {
      return { uploaded: false, error: 'У скана нет commit SHA — выгрузка в Code Scanning невозможна' };
    }

    const { encoded } = await this.sarifService.buildEncoded(userId, scanId);
    const result = await this.githubStatus.uploadSarif(
      userId,
      scan.repository.fullName,
      scan.commitSha,
      scan.branch || scan.repository.defaultBranch,
      encoded,
    );

    return {
      ...result,
      repository: scan.repository.fullName,
      commitSha: scan.commitSha,
      securityTabUrl: `${scan.repository.url}/security/code-scanning`,
    };
  }

  /**
   * Статус каждого из обязательных Требований ИБ-01…ИБ-08 (ТЗ п. 4.5, 4.6.3),
   * включая требования, нарушений по которым не выявлено.
   */
  async getRequirements(userId: string, scanId: string) {
    await this.getScanById(userId, scanId);
    return this.requirementsService.getForScan(scanId);
  }

  /**
   * Security-control matrix for a scan, with a roll-up the UI and the report
   * can show without recomputing it.
   */
  async getSecurityControls(userId: string, scanId: string) {
    await this.getScanById(userId, scanId);

    const controls = await this.prisma.securityControl.findMany({
      where: { scanId },
      orderBy: { control: 'asc' },
    });

    const count = (status: string) => controls.filter(c => c.status === status).length;

    return {
      controls,
      summary: {
        total: controls.length,
        implemented: count('IMPLEMENTED'),
        partial: count('PARTIAL'),
        missing: count('MISSING'),
        notApplicable: count('NOT_APPLICABLE'),
        unknown: count('UNKNOWN'),
        // Доля реализованных среди применимых — то, что имеет смысл показывать.
        coverage: (() => {
          const applicable = controls.filter(c => c.status !== 'NOT_APPLICABLE' && c.status !== 'UNKNOWN').length;
          if (applicable === 0) return null;
          return Math.round(((count('IMPLEMENTED') + count('PARTIAL') * 0.5) / applicable) * 100);
        })(),
      },
    };
  }

  async getScanArchitecture(userId: string, scanId: string) {
    const scan = await this.getScanById(userId, scanId);
    let summary: any = null;
    if (scan.scanResult?.summary) {
      try {
        summary = JSON.parse(scan.scanResult.summary);
      } catch {}
    }

    if (summary && summary.architectureNodes && summary.architectureNodes.length > 0) {
      return {
        nodes: summary.architectureNodes,
        edges: summary.architectureEdges || [],
        metadata: {
          filesCount: summary.filesCount,
          linesCount: summary.linesCount,
          languages: summary.languages,
          scannersUsed: summary.scannersUsed,
        }
      };
    }

    const workspacePath = this.repositoryService.getWorkspacePath(userId, scan.repositoryId, scanId);
    try {
      const arch = await this.architectureService.analyzeWorkspace(workspacePath);
      return {
        nodes: arch.nodes,
        edges: arch.edges,
        metadata: {
          filesCount: arch.filesCount,
          linesCount: arch.linesCount,
          languages: arch.languages,
          scannersUsed: arch.scannersUsed,
        }
      };
    } catch {
      return { nodes: [], edges: [], metadata: {} };
    }
  }

  async getScanFileTree(userId: string, scanId: string) {
    const scan = await this.getScanById(userId, scanId);
    let summary: any = null;
    if (scan.scanResult?.summary) {
      try {
        summary = JSON.parse(scan.scanResult.summary);
      } catch {}
    }

    if (summary && summary.fileTree && summary.fileTree.length > 0) {
      return {
        tree: summary.fileTree,
        filesCount: summary.filesCount,
        linesCount: summary.linesCount,
        languages: summary.languages,
        scanners: summary.scannersUsed,
      };
    }

    const workspacePath = this.repositoryService.getWorkspacePath(userId, scan.repositoryId, scanId);
    try {
      const arch = await this.architectureService.analyzeWorkspace(workspacePath);
      return {
        tree: arch.fileTree,
        filesCount: arch.filesCount,
        linesCount: arch.linesCount,
        languages: arch.languages,
        scanners: arch.scannersUsed,
      };
    } catch {
      return { tree: [], filesCount: 0, linesCount: 0, languages: [], scanners: [] };
    }
  }

  async getScanFileContent(userId: string, scanId: string, filePath: string) {
    const scan = await this.getScanById(userId, scanId);
    let workspacePath = this.repositoryService.getWorkspacePath(userId, scan.repositoryId, scanId);

    try {
      return await this.architectureService.readFileContent(workspacePath, filePath);
    } catch {
      return {
        path: filePath,
        content: `// Не удалось прочитать файл '${filePath}' из рабочей области сканирования.`,
        lineCount: 1,
      };
    }
  }

  async explainFinding(userId: string, scanId: string, findingId: string) {
    await this.getScanById(userId, scanId);
    const finding = await this.prisma.finding.findUnique({
      where: { id: findingId }
    });
    if (!finding) throw new NotFoundException('Finding not found');

    let snippet = finding.codeSnippet || '';
    if (!snippet && finding.filePath) {
      try {
        const fileContent = await this.getScanFileContent(userId, scanId, finding.filePath);
        if (fileContent && fileContent.content) {
          const lines = fileContent.content.split(/\r?\n/);
          const start = Math.max(0, (finding.startLine || 1) - 3);
          const end = Math.min(lines.length, (finding.endLine || finding.startLine || 1) + 4);
          snippet = lines.slice(start, end).join('\n');
        }
      } catch {}
    }

    return this.groqService.explainFinding(finding, snippet);
  }
}
