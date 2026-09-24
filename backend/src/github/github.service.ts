import {
  Injectable, Logger, UnauthorizedException, NotFoundException, ServiceUnavailableException,
} from '@nestjs/common';
import { Octokit } from '@octokit/rest';
import { PrismaService } from '../prisma/index.js';
import * as crypto from 'crypto';
import { ConfigService } from '@nestjs/config';
import { EventsService } from '../events/events.service.js';

const NEWLINE = String.fromCharCode(10);

/**
 * Как часто список репозиториев реально перечитывается из GitHub. Страница
 * открывается из базы мгновенно, а поход в GitHub идёт в фоне и не чаще этого
 * интервала — иначе каждый поллинг фронтенда упирался бы в сеть.
 */
const SYNC_INTERVAL_MS = 60_000;

@Injectable()
export class GithubService {
  private readonly logger = new Logger(GithubService.name);

  /** userId → время последней синхронизации с GitHub. */
  private readonly lastSyncAt = new Map<string, number>();
  /** userId → идущая синхронизация; защищает от параллельных походов в GitHub. */
  private readonly inFlightSync = new Map<string, Promise<void>>();

  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
    private events: EventsService,
  ) {}

  private get encryptionKey(): Buffer {
    const key = this.configService.get<string>('ENCRYPTION_KEY');
    if (!key || key.length !== 32) {
      throw new Error('ENCRYPTION_KEY must be exactly 32 characters long');
    }
    return Buffer.from(key);
  }

  private decrypt(text: string): string {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift()!, 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.encryptionKey, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  }

  /**
   * Octokit оборачивает сетевые ошибки в HttpError, и исходный код ошибки
   * («EAI_AGAIN» и т.п.) до `err.code` не доходит — поэтому определяем и по
   * тексту сообщения, иначе повтор никогда не срабатывает.
   */
  private static isTransient(err: any): boolean {
    const codes = ['EAI_AGAIN', 'ENOTFOUND', 'ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED', 'EPIPE'];
    const code = err?.code || err?.cause?.code || err?.cause?.cause?.code;
    if (codes.includes(code)) return true;
    if (err?.status === 502 || err?.status === 503 || err?.status === 504) return true;

    const message = String(err?.message || '');
    return codes.some(c => message.includes(c))
      || /socket hang up|network error|request to .* failed|timeout/i.test(message);
  }

  /**
   * Вызовы к GitHub периодически падают на временных сетевых/DNS-ошибках.
   * Без повтора это превращается в голый 500 на странице репозиториев.
   */
  private async withRetry<T>(label: string, fn: () => Promise<T>): Promise<T> {
    const maxAttempts = 3;
    let lastError: any;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await fn();
      } catch (err: any) {
        lastError = err;
        const isTransient = GithubService.isTransient(err);

        if (isTransient && attempt < maxAttempts) {
          const waitMs = 1500 * attempt;
          this.logger.warn(`${label}: временный сбой сети, повтор ${attempt}/${maxAttempts} через ${waitMs}мс`);
          await new Promise(resolve => setTimeout(resolve, waitMs));
          continue;
        }
        break;
      }
    }

    if (GithubService.isTransient(lastError)) {
      throw new ServiceUnavailableException(
        'GitHub сейчас недоступен (сетевая ошибка). Попробуйте обновить страницу через минуту.',
      );
    }
    if (lastError?.status === 401 || lastError?.status === 403) {
      throw new UnauthorizedException(
        'GitHub отклонил запрос: авторизация истекла или отозвана. Войдите через GitHub заново.',
      );
    }

    this.logger.error(`${label} failed: ${lastError?.message}`);
    throw lastError;
  }

  async getOctokitForUser(userId: string): Promise<Octokit> {
    const githubAccount = await this.prisma.gitHubAccount.findUnique({
      where: { userId },
    });

    if (!githubAccount) {
      throw new UnauthorizedException('User has no GitHub account linked');
    }

    if (!githubAccount.accessTokenHash) {
      throw new UnauthorizedException('GitHub authorization was revoked. Please sign in with GitHub again.');
    }

    const accessToken = this.decrypt(githubAccount.accessTokenHash);
    return new Octokit({ auth: accessToken });
  }

  /**
   * Список репозиториев для страницы. Отдаётся из базы сразу, без ожидания
   * GitHub: поход в GitHub — это сеть плюс запись сотни строк, и держать его
   * на пути отрисовки страницы нельзя. Актуализация идёт фоном, а фронтенд
   * узнаёт о ней событием repositories.synced.
   */
  async getUserRepositories(userId: string) {
    const cached = await this.readFromDb(userId);

    // Первый заход: в базе ещё пусто, показывать нечего — тогда ждём GitHub.
    if (cached.length === 0) {
      await this.syncFromGithub(userId);
      return this.readFromDb(userId);
    }

    this.scheduleSync(userId);
    return cached;
  }

  /**
   * Репозитории пользователя из базы. Таблица repositories общая для всех
   * пользователей, поэтому выборка идёт через связь user_repositories —
   * иначе в список попали бы чужие.
   */
  private async readFromDb(userId: string) {
    const repos = await this.prisma.repository.findMany({
      where: { users: { some: { userId } } },
      orderBy: { pushedAt: 'desc' },
    });

    if (repos.length === 0) return [];

    // Последний скан по каждому репозиторию — чтобы список сразу показывал
    // состояние безопасности, а не только метаданные GitHub.
    const lastScans = await this.prisma.scan.findMany({
      where: { userId, repositoryId: { in: repos.map(r => r.id) } },
      orderBy: { createdAt: 'desc' },
      include: { scanResult: { select: { totalFindings: true, criticalCount: true, highCount: true } } },
    });

    const scanByRepo = new Map<string, (typeof lastScans)[number]>();
    for (const scan of lastScans) {
      if (!scanByRepo.has(scan.repositoryId)) scanByRepo.set(scan.repositoryId, scan);
    }

    return repos.map(repo => {
      const scan = scanByRepo.get(repo.id);
      return {
        ...repo,
        lastScan: scan
          ? {
              id: scan.id,
              status: scan.status,
              policyResult: scan.policyResult,
              riskScore: scan.riskScore,
              completedAt: scan.completedAt,
              totalFindings: scan.scanResult?.totalFindings ?? 0,
              criticalCount: scan.scanResult?.criticalCount ?? 0,
              highCount: scan.scanResult?.highCount ?? 0,
            }
          : null,
      };
    });
  }

  /**
   * Запускает фоновую синхронизацию, если прошлая была давно. Ошибки здесь
   * намеренно не пробрасываются: страница уже отрисована данными из базы, и
   * недоступный GitHub не должен её ломать.
   */
  private scheduleSync(userId: string): void {
    const last = this.lastSyncAt.get(userId) ?? 0;
    if (Date.now() - last < SYNC_INTERVAL_MS) return;
    if (this.inFlightSync.has(userId)) return;

    const task = this.syncFromGithub(userId)
      .then(changed => {
        // Событие только когда данные действительно изменились: иначе фронтенд
        // перезапрашивал бы список в ответ на собственный же запрос.
        if (changed) this.events.emit({ type: 'repositories.synced', userId });
      })
      .catch(err => {
        this.logger.warn(`Фоновая синхронизация репозиториев не удалась: ${err.message}`);
      })
      .finally(() => {
        this.inFlightSync.delete(userId);
      });

    this.inFlightSync.set(userId, task);
  }

  /**
   * Тянет список из GitHub и обновляет базу одной транзакцией.
   * Возвращает true, если состав или метаданные репозиториев изменились.
   */
  private async syncFromGithub(userId: string): Promise<boolean> {
    const octokit = await this.getOctokitForUser(userId);

    const { data } = await this.withRetry('Список репозиториев', () =>
      octokit.rest.repos.listForAuthenticatedUser({ sort: 'updated', per_page: 100 }),
    );

    // Снимок «до»: по нему отличается реальное обновление от холостого прогона,
    // чтобы не рассылать событие на каждую фоновую синхронизацию.
    const before = await this.prisma.repository.findMany({
      where: { githubId: { in: data.map(r => r.id) } },
      select: { githubId: true, pushedAt: true, stars: true, openIssues: true, isPrivate: true },
    });
    const beforeByGithubId = new Map(before.map(r => [r.githubId, r]));

    const metadataChanged = data.some(repo => {
      const prev = beforeByGithubId.get(repo.id);
      if (!prev) return true;
      const pushedAt = repo.pushed_at ? new Date(repo.pushed_at).getTime() : null;
      return (
        (prev.pushedAt?.getTime() ?? null) !== pushedAt ||
        prev.stars !== (repo.stargazers_count ?? 0) ||
        prev.openIssues !== (repo.open_issues_count ?? 0) ||
        prev.isPrivate !== repo.private
      );
    });

    // Одна транзакция вместо сотни независимых запросов: раньше каждый
    // репозиторий стоил отдельного round-trip к базе.
    const saved = await this.prisma.$transaction(
      data.map(repo => {
        const fields = {
          name: repo.name,
          fullName: repo.full_name,
          owner: repo.owner.login,
          isPrivate: repo.private,
          defaultBranch: repo.default_branch,
          language: repo.language,
          description: repo.description,
          url: repo.html_url,
          pushedAt: repo.pushed_at ? new Date(repo.pushed_at) : null,
          stars: repo.stargazers_count ?? 0,
          openIssues: repo.open_issues_count ?? 0,
        };

        return this.prisma.repository.upsert({
          where: { githubId: repo.id },
          update: fields,
          create: { githubId: repo.id, ...fields },
        });
      }),
    );

    const repositoryIds = saved.map(r => r.id);

    const previous = await this.prisma.userRepository.findMany({
      where: { userId },
      select: { repositoryId: true },
    });
    const previousIds = new Set(previous.map(r => r.repositoryId));
    const membershipChanged =
      previousIds.size !== repositoryIds.length ||
      repositoryIds.some(id => !previousIds.has(id));

    // Доступ пользователя к репозиториям: то, что GitHub перестал отдавать,
    // должно пропасть и из списка, иначе там останутся отозванные репозитории.
    await this.prisma.$transaction([
      this.prisma.userRepository.deleteMany({
        where: { userId, repositoryId: { notIn: repositoryIds } },
      }),
      ...repositoryIds.map(repositoryId =>
        this.prisma.userRepository.upsert({
          where: { userId_repositoryId: { userId, repositoryId } },
          update: {},
          create: { userId, repositoryId },
        }),
      ),
    ]);

    this.lastSyncAt.set(userId, Date.now());
    return membershipChanged || metadataChanged;
  }

  /**
   * Кто последним пушил и какие пулл-реквесты открыты — по каждому репозиторию.
   *
   * Отдельным запросом, а не в общем списке: это 2 вызова GitHub API на
   * репозиторий, и держать их на пути отрисовки списка нельзя. Фронтенд
   * подгружает активность после того, как список уже показан.
   */
  async getRepositoriesActivity(userId: string, repositoryIds: string[]) {
    if (repositoryIds.length === 0) return {};

    const repos = await this.prisma.repository.findMany({
      where: { id: { in: repositoryIds.slice(0, 40) } },
    });

    const octokit = await this.getOctokitForUser(userId);
    const result: Record<string, any> = {};

    // Ограниченная параллельность: GitHub ограничивает частоту запросов.
    const CONCURRENCY = 6;
    for (let i = 0; i < repos.length; i += CONCURRENCY) {
      const batch = repos.slice(i, i + CONCURRENCY);

      await Promise.all(
        batch.map(async repo => {
          const [owner, name] = repo.fullName.split('/');
          const activity: any = { lastCommit: null, openPullRequests: [], openPullRequestCount: 0, error: null };

          try {
            const [commits, pulls] = await Promise.all([
              octokit.rest.repos.listCommits({ owner, repo: name, per_page: 1 }).catch(() => null),
              octokit.rest.pulls.list({ owner, repo: name, state: 'open', per_page: 5, sort: 'updated', direction: 'desc' }).catch(() => null),
            ]);

            const head = commits?.data?.[0];
            if (head) {
              activity.lastCommit = {
                sha: head.sha?.slice(0, 7),
                message: (head.commit?.message || '').split(NEWLINE)[0].slice(0, 120),
                // author может быть null для коммитов без связанного аккаунта GitHub
                authorLogin: head.author?.login || head.commit?.author?.name || 'unknown',
                authorAvatar: head.author?.avatar_url || null,
                date: head.commit?.author?.date || null,
              };
            }

            if (pulls?.data) {
              activity.openPullRequestCount = pulls.data.length;
              activity.openPullRequests = pulls.data.map(pr => ({
                number: pr.number,
                title: (pr.title || '').slice(0, 120),
                authorLogin: pr.user?.login || 'unknown',
                authorAvatar: pr.user?.avatar_url || null,
                updatedAt: pr.updated_at,
                url: pr.html_url,
              }));
            }
          } catch (err: any) {
            activity.error = err.message?.slice(0, 160) || 'GitHub API error';
          }

          result[repo.id] = activity;
        }),
      );
    }

    return result;
  }

  async getRepositoryById(userId: string, repoId: string) {
    const repo = await this.prisma.repository.findUnique({
      where: { id: repoId },
    });

    if (!repo) {
      throw new NotFoundException('Repository not found');
    }

    return repo;
  }
}
