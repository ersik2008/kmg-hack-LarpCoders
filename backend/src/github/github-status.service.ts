import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { GithubService } from './github.service.js';
import { PrismaService } from '../prisma/index.js';

export type GateState = 'pending' | 'success' | 'failure' | 'error';

export interface GateReport {
  state: GateState;
  description: string;
  counts?: Record<string, number>;
  reasons?: string[];
  findings?: Array<{
    severity: string;
    title: string;
    filePath: string | null;
    startLine: number | null;
    scanner: string;
    ruleId: string | null;
  }>;
}

/**
 * Publishes the security gate back into GitHub.
 *
 * This is what makes the agent part of CI/CD rather than a separate dashboard:
 * the verdict lands on the commit as a status check, so GitHub branch
 * protection can require it and block a merge on its own.
 *
 * A commit status (not a Check Run) is used deliberately — it is available to
 * an OAuth token with the `repo` scope, which is what the app already holds;
 * Check Runs would require installing a separate GitHub App.
 */
@Injectable()
export class GithubStatusService {
  private readonly logger = new Logger(GithubStatusService.name);

  private static readonly CONTEXT = 'KMG AI / security-gate';

  constructor(
    private readonly githubService: GithubService,
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * GitHub calls fail intermittently on transient DNS/connection errors; a gate
   * verdict that never reaches the commit silently disables the whole check, so
   * these are worth retrying.
   */
  private async withRetry<T>(label: string, fn: () => Promise<T>, rethrow = false): Promise<T | null> {
    const transientCodes = ['EAI_AGAIN', 'ENOTFOUND', 'ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED'];
    const maxAttempts = 3;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await fn();
      } catch (err: any) {
        const code = err?.code || err?.cause?.code;
        const message = String(err?.message || '');
        // Octokit заворачивает сетевые ошибки, поэтому код смотрим и в тексте.
        const isTransient = transientCodes.includes(code) || transientCodes.some(c => message.includes(c));

        if (isTransient && attempt < maxAttempts) {
          const waitMs = 2000 * attempt;
          this.logger.warn(`${label}: network error, retry ${attempt}/${maxAttempts} in ${waitMs / 1000}s`);
          await new Promise(resolve => setTimeout(resolve, waitMs));
          continue;
        }
        this.logger.error(`${label} failed: ${err.message}`);
        // Вызывающему коду нужен статус GitHub (403/404), чтобы объяснить причину.
        if (rethrow) throw err;
        return null;
      }
    }
    return null;
  }

  private targetUrl(scanId: string): string {
    const frontend = this.configService.get<string>('FRONTEND_URL', 'http://localhost:5173');
    return `${frontend}/scans/${scanId}`;
  }

  /** Marks the commit as "checks running" as soon as a CI scan starts. */
  async publishPending(userId: string, fullName: string, commitSha: string, scanId: string) {
    await this.publishStatus(userId, fullName, commitSha, scanId, {
      state: 'pending',
      description: 'Проверка безопасности выполняется...',
    });
  }

  async publishStatus(
    userId: string,
    fullName: string,
    commitSha: string,
    scanId: string,
    report: GateReport,
  ): Promise<boolean> {
    const [owner, repo] = (fullName || '').split('/');
    if (!owner || !repo || !commitSha) {
      this.logger.warn(`Cannot publish status: incomplete target (${fullName} @ ${commitSha})`);
      return false;
    }

    const done = await this.withRetry(`Commit status -> ${fullName}`, async () => {
      const octokit = await this.githubService.getOctokitForUser(userId);
      await octokit.rest.repos.createCommitStatus({
        owner,
        repo,
        sha: commitSha,
        state: report.state,
        context: GithubStatusService.CONTEXT,
        // GitHub truncates the description at 140 characters.
        description: report.description.slice(0, 139),
        target_url: this.targetUrl(scanId),
      });
      return true;
    });

    if (done) {
      this.logger.log(`Published '${report.state}' status to ${fullName}@${commitSha.slice(0, 7)}`);
    }
    return Boolean(done);
  }

  /** Posts the detailed finding table as a PR comment. */
  async publishPullRequestComment(
    userId: string,
    fullName: string,
    prNumber: number,
    scanId: string,
    report: GateReport,
  ): Promise<boolean> {
    const [owner, repo] = (fullName || '').split('/');
    if (!owner || !repo || !prNumber) return false;

    const done = await this.withRetry(`PR comment -> ${fullName}#${prNumber}`, async () => {
      const octokit = await this.githubService.getOctokitForUser(userId);
      await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number: prNumber,
        body: this.renderComment(scanId, report),
      });
      return true;
    });

    if (done) this.logger.log(`Published scan comment to ${fullName}#${prNumber}`);
    return Boolean(done);
  }

  private renderComment(scanId: string, report: GateReport): string {
    const c = report.counts || {};
    const verdictLine =
      report.state === 'success'
        ? '✅ **Проверка пройдена** — критических проблем не найдено.'
        : report.state === 'failure'
          ? '🛑 **Слияние заблокировано** — найдены критические уязвимости.'
          : '⚠️ **Вердикт не вынесен** — сканирование не завершилось корректно. Отсутствие находок здесь НЕ означает, что код безопасен.';

    const rows = (report.findings || [])
      .slice(0, 15)
      .map(f => {
        const location = f.filePath ? `\`${f.filePath}${f.startLine ? `:${f.startLine}` : ''}\`` : '—';
        return `| ${f.severity} | ${location} | ${f.title.slice(0, 90)} | ${f.scanner} |`;
      })
      .join('\n');

    const table = rows
      ? `\n| Severity | Файл | Проблема | Сканер |\n|---|---|---|---|\n${rows}\n`
      : '\nНаходок нет.\n';

    const more =
      (report.findings?.length || 0) > 15
        ? `\n_Показано 15 из ${report.findings!.length} находок._\n`
        : '';

    const reasons = report.reasons?.length
      ? `\n**Причины вердикта:**\n${report.reasons.map(r => `- ${r}`).join('\n')}\n`
      : '';

    return [
      '## 🛡️ KMG AI — проверка безопасности',
      '',
      verdictLine,
      '',
      `**Найдено:** 🔴 CRITICAL ${c.CRITICAL || 0} · 🟠 HIGH ${c.HIGH || 0} · ` +
        `🟡 MEDIUM ${c.MEDIUM || 0} · 🔵 LOW ${c.LOW || 0}`,
      table,
      more,
      reasons,
      `[Полный отчёт и разбор AI →](${this.targetUrl(scanId)})`,
    ].join('\n');
  }

  /**
   * Uploads a SARIF report to GitHub Code Scanning.
   *
   * The findings then appear in the repository's own Security tab, annotated on
   * the exact lines, with GitHub handling history and dismissals.
   *
   * Requires the `security_events` OAuth scope (private repos) — an account
   * authorised before that scope was added will get a 403 until the user signs
   * in again, so the failure is reported rather than swallowed.
   */
  async uploadSarif(
    userId: string,
    fullName: string,
    commitSha: string,
    ref: string,
    encodedSarif: string,
  ): Promise<{ uploaded: boolean; error?: string; url?: string }> {
    const [owner, repo] = (fullName || '').split('/');
    if (!owner || !repo || !commitSha) {
      return { uploaded: false, error: 'Неполные данные для загрузки SARIF (репозиторий или commit SHA)' };
    }

    try {
      const data = await this.withRetry(`SARIF -> ${fullName}`, async () => {
        const octokit = await this.githubService.getOctokitForUser(userId);
        const response = await octokit.request('POST /repos/{owner}/{repo}/code-scanning/sarifs', {
          owner,
          repo,
          commit_sha: commitSha,
          // GitHub требует полный ref вида refs/heads/main
          ref: ref.startsWith('refs/') ? ref : `refs/heads/${ref}`,
          sarif: encodedSarif,
          tool_name: 'KMG AI Security Agent',
        });
        return response.data;
      }, true);

      if (!data) {
        return { uploaded: false, error: 'GitHub недоступен: не удалось выгрузить SARIF после повторов' };
      }

      this.logger.log(`SARIF uploaded to ${fullName}@${commitSha.slice(0, 7)} (id: ${data?.id})`);
      return { uploaded: true, url: data?.url };
    } catch (err: any) {
      const status = err?.status;
      let error = err?.message || 'unknown error';

      if (status === 403) {
        error =
          'GitHub отклонил загрузку: нет права security_events. ' +
          'Выйдите и войдите заново, чтобы выдать приложению этот доступ.';
      } else if (status === 404) {
        error = 'Code Scanning недоступен для этого репозитория (нужен GitHub Advanced Security для приватных репозиториев).';
      }

      this.logger.warn(`SARIF upload to ${fullName} failed: ${error}`);
      return { uploaded: false, error };
    }
  }

  /**
   * Picks the account whose GitHub token should act for a repository.
   * Preference: whoever scanned it last, otherwise any linked account.
   */
  async resolveActingUser(repositoryId: string): Promise<string | null> {
    const lastScan = await this.prisma.scan.findFirst({
      where: { repositoryId },
      orderBy: { createdAt: 'desc' },
      select: { userId: true },
    });

    if (lastScan?.userId) {
      const account = await this.prisma.gitHubAccount.findUnique({ where: { userId: lastScan.userId } });
      if (account?.accessTokenHash) return lastScan.userId;
    }

    const anyAccount = await this.prisma.gitHubAccount.findFirst({
      where: { accessTokenHash: { not: '' } },
      orderBy: { id: 'asc' },
    });

    return anyAccount?.userId ?? null;
  }
}
