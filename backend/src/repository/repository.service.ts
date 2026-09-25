import { Injectable, NotFoundException, UnauthorizedException, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/index.js';
import { ConfigService } from '@nestjs/config';
import { GithubService } from '../github/github.service.js';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as os from 'os';
import { GitIgnoreMatcherTS } from '../common/utils/gitignore.util.js';

const execFileAsync = promisify(execFile);


export interface CloneResult {
  workspacePath: string;
  commitSha: string;
  fileCount: number;
  branch: string;
}

const IGNORED_DIRECTORIES = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  '.next',
  'coverage',
  '.cache',
  'vendor',
  '__pycache__',
  '.idea',
  '.vscode'
]);

@Injectable()
export class RepositoryService {
  private readonly logger = new Logger(RepositoryService.name);

  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
    private githubService: GithubService,
  ) {}

  /**
   * Единственная точка запуска git.
   *
   * Раньше здесь был `child_process.exec(строка)`, то есть запуск через
   * оболочку: имя репозитория и ветки из БД подставлялись в командную строку
   * (потенциальная инъекция), а OAuth-токен GitHub оказывался в URL внутри
   * строки команды — виден в списке процессов и в тексте исключений.
   *
   * Теперь: `execFile` с массивом аргументов (оболочки нет), значения
   * проверяются до запуска, токен передаётся заголовком через переменные
   * окружения процесса, а не аргументом командной строки.
   */
  async runCommand(
    args: string[],
    cwd: string,
    timeout = 90000,
    env: NodeJS.ProcessEnv = {},
  ): Promise<{ stdout: string; stderr: string }> {
    const { stdout, stderr } = await execFileAsync('git', args, {
      cwd,
      timeout,
      maxBuffer: 16 * 1024 * 1024,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', ...env },
    });
    return { stdout: String(stdout), stderr: String(stderr) };
  }

  /** `owner/name` — только допустимые в GitHub символы. */
  static isValidFullName(value: string): boolean {
    return /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(value) && !value.includes('..');
  }

  /** Имя ветки: без ведущего «-» (иначе git примет его за опцию), без «..» и метасимволов. */
  static isValidBranch(value: string): boolean {
    return /^[A-Za-z0-9][A-Za-z0-9._\/-]{0,199}$/.test(value) && !value.includes('..');
  }

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

  getWorkspacePath(userId: string, repoId: string, scanId?: string): string {
    const baseDir = this.configService.get<string>('WORKSPACES_ROOT') || path.join(os.tmpdir(), 'kmg_workspaces');
    if (scanId) {
      return path.join(baseDir, `scan-${scanId}`, 'repository');
    }
    return path.join(baseDir, userId, repoId);
  }

  getCiWorkspacePath(scanId: string): string {
    const baseDir = this.configService.get<string>('WORKSPACES_ROOT') || path.join(os.tmpdir(), 'kmg_workspaces');
    return path.join(baseDir, `ci-${scanId}`, 'repository');
  }

  /**
   * Возвращает реальный путь к рабочей области скана, пробуя доступные варианты:
   * • `scan-<scanId>/repository` — ручное сканирование через GitHub OAuth
   * • `ci-<scanId>/repository`   — архив из GitHub Actions
   * Если ни один не существует, возвращает стандартный `scan-` путь.
   */
  async resolveWorkspacePath(userId: string, repoId: string, scanId: string): Promise<string> {
    const scanPath = this.getWorkspacePath(userId, repoId, scanId);
    try {
      await import('fs/promises').then(fs => fs.access(scanPath));
      return scanPath;
    } catch {
      /* not found under scan- prefix, try ci- */
    }
    const ciPath = this.getCiWorkspacePath(scanId);
    try {
      await import('fs/promises').then(fs => fs.access(ciPath));
      return ciPath;
    } catch {
      /* neither exists — return the default so caller gets a meaningful error */
    }
    return scanPath;
  }

  async cloneRepository(userId: string, repoId: string, scanId?: string, branch?: string): Promise<string> {
    const res = await this.cloneRepositoryWithMeta(userId, repoId, scanId, branch);
    return res.workspacePath;
  }

  async cloneRepositoryWithMeta(
    userId: string,
    repoId: string,
    scanId?: string,
    requestedBranch?: string,
  ): Promise<CloneResult> {
    const repo = await this.prisma.repository.findUnique({
      where: { id: repoId },
    });

    if (!repo) {
      throw new NotFoundException(`Repository with ID '${repoId}' not found`);
    }

    const workspacePath = this.getWorkspacePath(userId, repoId, scanId);
    await this.cleanupWorkspace(userId, repoId, scanId);
    await fs.mkdir(workspacePath, { recursive: true });

    // Always a real clone of the selected GitHub repository.
    const targetBranch = requestedBranch || repo.defaultBranch || 'main';

    const githubAccount = await this.prisma.gitHubAccount.findUnique({
      where: { userId },
    });

    if (!githubAccount?.accessTokenHash) {
      throw new Error(
        'No valid GitHub authorization for this user (token missing or revoked by logout). Sign in with GitHub again.',
      );
    }

    let accessToken = '';
    if (githubAccount?.accessTokenHash) {
      try {
        accessToken = this.decrypt(githubAccount.accessTokenHash);
      } catch (decErr: any) {
        this.logger.warn(`Failed to decrypt GitHub access token: ${decErr.message}`);
      }
    }

    // Значения из БД и запроса проверяются до того, как попадут в аргументы git.
    if (!RepositoryService.isValidFullName(repo.fullName)) {
      throw new Error(`Недопустимое имя репозитория: '${String(repo.fullName).slice(0, 80)}'`);
    }
    if (!RepositoryService.isValidBranch(targetBranch)) {
      throw new Error(`Недопустимое имя ветки: '${String(targetBranch).slice(0, 80)}'`);
    }

    // URL без учётных данных. Токен уходит заголовком через окружение процесса
    // (GIT_CONFIG_*), поэтому его нет ни в командной строке, ни в тексте ошибок.
    const cloneUrl = `https://github.com/${repo.fullName}.git`;
    const authEnv: NodeJS.ProcessEnv = accessToken
      ? {
          GIT_CONFIG_COUNT: '1',
          GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader',
          GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${accessToken}`).toString('base64')}`,
        }
      : {};

    try {
      this.logger.log(`Cloning real GitHub repository ${repo.fullName} (branch: ${targetBranch}) to ${workspacePath}...`);

      try {
        await this.runCommand(
          ['clone', '--depth', '1', '--branch', targetBranch, '--', cloneUrl, '.'],
          workspacePath, 90000, authEnv,
        );
      } catch (branchErr: any) {
        this.logger.warn(`Branch '${targetBranch}' clone failed: ${this.scrub(branchErr.message, accessToken)}. Attempting default remote HEAD.`);
        await fs.rm(workspacePath, { recursive: true, force: true });
        await fs.mkdir(workspacePath, { recursive: true });
        await this.runCommand(['clone', '--depth', '1', '--', cloneUrl, '.'], workspacePath, 90000, authEnv);
      }

      // Verify commit SHA
      let commitSha = 'HEAD';
      try {
        const { stdout: shaOut } = await this.runCommand(['rev-parse', 'HEAD'], workspacePath);
        commitSha = shaOut.trim();
      } catch (shaErr: any) {
        this.logger.warn(`Could not resolve commit SHA via git rev-parse: ${shaErr.message}`);
      }

      // Count and validate source files
      const fileCount = await this.countSourceFiles(workspacePath);

      if (fileCount === 0) {
        throw new Error(`Repository ${repo.fullName} cloned successfully but workspace has no source files.`);
      }

      this.logger.log(`Successfully verified workspace for ${repo.fullName} (commit: ${commitSha.slice(0, 7)}, files: ${fileCount})`);

      return {
        workspacePath,
        commitSha,
        fileCount,
        branch: targetBranch,
      };
    } catch (error: unknown) {
      const err = error as Error;
      const safeMessage = this.scrub(err.message, accessToken);
      this.logger.error(`Real GitHub clone failed for ${repo.fullName}: ${safeMessage}`);
      await this.cleanupWorkspace(userId, repoId, scanId);
      throw new Error(`Failed to clone repository ${repo.fullName}: ${safeMessage}`);
    }
  }

  /** Токен не должен попадать ни в журнал, ни в текст исключения. */
  private scrub(message: string, token: string): string {
    let out = String(message ?? '');
    if (token) {
      out = out.split(token).join('***').split(Buffer.from(`x-access-token:${token}`).toString('base64')).join('***');
    }
    return out.replace(/(AUTHORIZATION:\s*basic\s+)[A-Za-z0-9+/=]+/gi, '$1***');
  }

  private async countSourceFiles(dir: string): Promise<number> {
    let count = 0;
    const matcher = await GitIgnoreMatcherTS.create(dir);

    const walk = async (currentDir: string) => {
      try {
        const entries = await fs.readdir(currentDir, { withFileTypes: true });
        for (const entry of entries) {
          const fullPath = path.join(currentDir, entry.name);
          const relPath = path.relative(dir, fullPath).replace(/\\/g, '/');

          if (matcher.isIgnored(relPath)) {
            continue;
          }

          if (entry.isDirectory()) {
            if (!IGNORED_DIRECTORIES.has(entry.name)) {
              await walk(fullPath);
            }
          } else if (entry.isFile()) {
            count++;
          }
        }
      } catch {}
    };
    await walk(dir);
    return count;
  }


  async cleanupWorkspace(userId: string, repoId: string, scanId?: string): Promise<void> {
    const workspacePath = this.getWorkspacePath(userId, repoId, scanId);
    try {
      const targetDir = scanId ? path.dirname(workspacePath) : workspacePath;
      await fs.rm(targetDir, { recursive: true, force: true });
    } catch (error: unknown) {
      this.logger.warn(`Failed to cleanup workspace ${workspacePath}: ${(error as Error).message}`);
    }
  }
}
