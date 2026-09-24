import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/index.js';
import { ScanService } from '../scan/scan.service.js';
import { GithubStatusService } from '../github/github-status.service.js';

/**
 * GitHub webhook handling — the server-side half of the CI/CD integration.
 *
 * These handlers used to only log the event and answer "Scan will be triggered
 * via CI/CD pipeline" without ever starting one. They now run the real scan
 * pipeline and the verdict is published back onto the commit as a status
 * check, which is what lets GitHub branch protection block a merge.
 */
@Injectable()
export class CicdService {
  private readonly logger = new Logger(CicdService.name);

  constructor(
    private prisma: PrismaService,
    private scanService: ScanService,
    private githubStatus: GithubStatusService,
  ) {}

  private get watchedBranches(): string[] {
    const raw = process.env.CICD_BRANCHES || 'main,master,develop';
    return raw.split(',').map(b => b.trim()).filter(Boolean);
  }

  async handlePush(payload: any) {
    const repo = payload.repository;
    const branch = payload.ref?.replace('refs/heads/', '');
    const commitSha = payload.after;

    this.logger.log(`Push event: ${repo?.full_name} @ ${branch} (${commitSha})`);

    if (payload.deleted || !commitSha || /^0+$/.test(commitSha)) {
      return { status: 'skipped', reason: 'branch_deleted' };
    }

    const dbRepo = await this.prisma.repository.findFirst({
      where: { fullName: repo?.full_name },
    });

    if (!dbRepo) {
      this.logger.warn(`Repository ${repo?.full_name} is not connected to KMG, skipping`);
      return { status: 'skipped', reason: 'repository_not_connected' };
    }

    if (!this.watchedBranches.includes(branch)) {
      return { status: 'skipped', reason: 'branch_not_watched', branch };
    }

    const userId = await this.githubStatus.resolveActingUser(dbRepo.id);
    if (!userId) {
      this.logger.warn(`No GitHub account available to scan ${repo?.full_name}`);
      return { status: 'skipped', reason: 'no_linked_github_account' };
    }

    const { scanId } = await this.scanService.startScan(userId, dbRepo.id, {
      branch,
      trigger: 'push',
    });

    this.logger.log(`Auto-scan ${scanId} started for ${repo?.full_name}@${branch}`);

    return {
      status: 'scanning',
      scanId,
      repositoryId: dbRepo.id,
      branch,
      commitSha,
    };
  }

  async handlePullRequest(payload: any) {
    const action = payload.action;
    const pr = payload.pull_request;
    const repo = payload.repository;

    this.logger.log(`PR event: ${action} — ${repo?.full_name} #${pr?.number}`);

    if (!['opened', 'synchronize', 'reopened'].includes(action)) {
      return { status: 'skipped', reason: 'irrelevant_action', action };
    }

    const dbRepo = await this.prisma.repository.findFirst({
      where: { fullName: repo?.full_name },
    });

    if (!dbRepo) {
      return { status: 'skipped', reason: 'repository_not_connected' };
    }

    const userId = await this.githubStatus.resolveActingUser(dbRepo.id);
    if (!userId) {
      return { status: 'skipped', reason: 'no_linked_github_account' };
    }

    // Scan the PR head: that is the code a merge would actually introduce.
    const { scanId } = await this.scanService.startScan(userId, dbRepo.id, {
      branch: pr?.head?.ref,
      trigger: 'pull_request',
      prNumber: pr?.number,
    });

    this.logger.log(`PR scan ${scanId} started for ${repo?.full_name}#${pr?.number}`);

    return {
      status: 'scanning',
      scanId,
      repositoryId: dbRepo.id,
      prNumber: pr?.number,
      headSha: pr?.head?.sha,
    };
  }
}
