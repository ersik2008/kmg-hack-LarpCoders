import {
  Controller, Post, Get, Req, Res, Query, UseGuards, Logger, BadRequestException, HttpCode,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { SkipThrottle } from '@nestjs/throttler';

import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { User } from '../generated/prisma/client.js';
import { CiService } from './ci.service.js';

/**
 * Точка входа для CI/CD.
 *
 * GitHub Actions упаковывает репозиторий в tar.gz, отправляет его сюда одним
 * POST-запросом и получает обратно готовый SARIF 2.1.0 — его остаётся передать
 * в `github/codeql-action/upload-sarif`. Ни webhook, ни публичный callback-URL,
 * ни заход в интерфейс KMG для этого не нужны.
 *
 * Вердикт дополнительно уезжает в заголовках ответа, чтобы workflow мог
 * уронить сборку, не разбирая SARIF.
 */
@Controller('ci')
export class CiController {
  private readonly logger = new Logger(CiController.name);

  constructor(private readonly ciService: CiService) {}

  /** Проверка доступности и токена — первый шаг в workflow. */
  @Get('ping')
  @UseGuards(JwtAuthGuard)
  ping(@Req() req: Request) {
    const user = req.user as User;
    return { ok: true, user: user.name || user.email, service: 'kmg-ci' };
  }

  /**
   * POST /api/ci/scan
   *
   * Тело: сырой tar.gz (Content-Type: application/gzip).
   * Ответ: SARIF 2.1.0 JSON.
   */
  @Post('scan')
  @UseGuards(JwtAuthGuard)
  @SkipThrottle()
  // Ответ — документ, а не созданный ресурс: CI-скрипты проверяют ровно 200.
  @HttpCode(200)
  async scan(
    @Req() req: Request,
    @Res() res: Response,
    @Query('repository') repository?: string,
    @Query('repositoryId') repositoryId?: string,
    @Query('sha') sha?: string,
    @Query('ref') ref?: string,
    @Query('pr') pr?: string,
    @Query('ai') ai?: string,
  ) {
    const user = req.user as User;

    // Сырое тело подставляет raw-парсер, настроенный в main.ts для этого пути.
    const archive = req.body as unknown as Buffer;
    if (!Buffer.isBuffer(archive)) {
      throw new BadRequestException(
        'Ожидается бинарный архив .tar.gz. Укажите заголовок Content-Type: application/gzip ' +
          'и отправляйте тело через --data-binary.',
      );
    }

    const repo = repository || (req.headers['x-kmg-repository'] as string);
    if (!repo) {
      throw new BadRequestException('Не указан репозиторий: параметр ?repository=owner/name');
    }

    const outcome = await this.ciService.scanArchive(user.id, {
      archive,
      repository: repo,
      githubRepoId: repositoryId ? Number(repositoryId) : undefined,
      commitSha: sha || (req.headers['x-kmg-sha'] as string) || undefined,
      ref: ref || (req.headers['x-kmg-ref'] as string) || undefined,
      prNumber: pr && /^\d+$/.test(pr) ? Number(pr) : undefined,
      aiMode: ai === 'off' ? 'off' : 'full',
    });

    // Заголовки позволяют workflow принять решение без парсинга SARIF.
    res.setHeader('X-KMG-Scan-Id', outcome.scanId);
    res.setHeader('X-KMG-Verdict', outcome.verdict);
    res.setHeader('X-KMG-Risk-Score', String(outcome.riskScore ?? ''));
    res.setHeader('X-KMG-Critical', String(outcome.counts.CRITICAL));
    res.setHeader('X-KMG-High', String(outcome.counts.HIGH));
    res.setHeader('X-KMG-Medium', String(outcome.counts.MEDIUM));
    res.setHeader('X-KMG-Low', String(outcome.counts.LOW));
    res.setHeader('X-KMG-Total', String(Object.values(outcome.counts).reduce((a, b) => a + b, 0)));
    res.setHeader('X-KMG-Files-Scanned', String(outcome.filesScanned));
    res.setHeader('X-KMG-Ai-Analysis', String(outcome.aiAnalysisSucceeded));
    // Код завершения по ТЗ п. 4.3.3 и перечень нарушенных требований (п. 4.3.5):
    // workflow печатает их в журнал, не открывая артефакт.
    res.setHeader('X-KMG-Exit-Code', String(outcome.exitCode));
    res.setHeader('X-KMG-Violated-Requirements', outcome.violatedRequirements.join(','));
    res.setHeader('X-KMG-Insufficient-Requirements', outcome.insufficientRequirements.join(','));
    res.setHeader('X-KMG-Decision-Basis', outcome.decisionBasis);
    res.setHeader('X-KMG-Started-At', outcome.startedAt);
    res.setHeader('X-KMG-Finished-At', outcome.finishedAt);
    res.setHeader('X-KMG-Duration-Seconds', String(outcome.durationSeconds));
    res.setHeader('Content-Type', 'application/json');

    return res.json(outcome.sarif);
  }

  /**
   * То же самое, но ответ — компактный JSON со сводкой вместо SARIF.
   * Пригодится, когда SARIF выгружать некуда (GitLab, Jenkins).
   */
  @Post('scan/summary')
  @UseGuards(JwtAuthGuard)
  @SkipThrottle()
  @HttpCode(200)
  async scanSummary(
    @Req() req: Request,
    @Query('repository') repository?: string,
    @Query('repositoryId') repositoryId?: string,
    @Query('sha') sha?: string,
    @Query('ref') ref?: string,
    @Query('pr') pr?: string,
    @Query('ai') ai?: string,
  ) {
    const user = req.user as User;
    const archive = req.body as unknown as Buffer;

    if (!Buffer.isBuffer(archive)) {
      throw new BadRequestException('Ожидается бинарный архив .tar.gz (Content-Type: application/gzip)');
    }

    const repo = repository || (req.headers['x-kmg-repository'] as string);
    if (!repo) {
      throw new BadRequestException('Не указан репозиторий: параметр ?repository=owner/name');
    }

    const outcome = await this.ciService.scanArchive(user.id, {
      archive,
      repository: repo,
      githubRepoId: repositoryId ? Number(repositoryId) : undefined,
      commitSha: sha || undefined,
      ref: ref || undefined,
      prNumber: pr && /^\d+$/.test(pr) ? Number(pr) : undefined,
      aiMode: ai === 'off' ? 'off' : 'full',
    });

    const { sarif, ...summary } = outcome;
    return {
      ...summary,
      findings: (sarif.runs?.[0]?.results || []).slice(0, 200).map((r: any) => ({
        ruleId: r.ruleId,
        level: r.level,
        message: r.message?.text,
        filePath: r.locations?.[0]?.physicalLocation?.artifactLocation?.uri,
        line: r.locations?.[0]?.physicalLocation?.region?.startLine,
      })),
    };
  }
}
