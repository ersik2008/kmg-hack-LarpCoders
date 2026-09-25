import * as fs from 'fs/promises';
import * as path from 'path';

interface GitIgnoreRule {
  baseDir: string;
  pattern: string;
  isNegation: boolean;
  regex: RegExp | null;
}

export class GitIgnoreMatcherTS {
  private rules: GitIgnoreRule[] = [];

  private constructor(private workspacePath: string) {}

  static async create(workspacePath: string): Promise<GitIgnoreMatcherTS> {
    const matcher = new GitIgnoreMatcherTS(path.resolve(workspacePath));
    await matcher.loadAllGitignores();
    return matcher;
  }

  private async loadAllGitignores(): Promise<void> {
    const ignoredDirs = new Set([
      '.git', 'node_modules', 'dist', 'build', '.next', 'coverage',
      '.cache', 'vendor', '__pycache__', '.idea', '.vscode', '.venv', 'venv',
    ]);

    const walk = async (currentDir: string) => {
      try {
        const entries = await fs.readdir(currentDir, { withFileTypes: true });

        const gitignoreEntry = entries.find(e => e.isFile() && e.name === '.gitignore');
        if (gitignoreEntry) {
          const gitignorePath = path.join(currentDir, '.gitignore');
          let relDir = path.relative(this.workspacePath, currentDir).replace(/\\/g, '/');
          if (relDir === '.') relDir = '';

          try {
            const content = await fs.readFile(gitignorePath, 'utf-8');
            const lines = content.split(/\r?\n/);
            for (const line of lines) {
              const trimmed = line.trim();
              if (!trimmed || trimmed.startsWith('#')) continue;
              this.addRule(relDir, trimmed);
            }
          } catch {}
        }

        for (const entry of entries) {
          if (entry.isDirectory() && !ignoredDirs.has(entry.name)) {
            await walk(path.join(currentDir, entry.name));
          }
        }
      } catch {}
    };

    await walk(this.workspacePath);
  }

  private addRule(baseDir: string, pattern: string): void {
    let isNegation = false;
    if (pattern.startsWith('!')) {
      isNegation = true;
      pattern = pattern.slice(1);
    }
    pattern = pattern.trim();
    if (!pattern) return;

    const regex = this.patternToRegex(pattern);
    this.rules.push({ baseDir, pattern, isNegation, regex });
  }

  private patternToRegex(pattern: string): RegExp | null {
    let isDirOnly = pattern.endsWith('/');
    if (isDirOnly) pattern = pattern.slice(0, -1);

    const anchored = pattern.startsWith('/');
    if (anchored) pattern = pattern.slice(1);

    let res = '';
    let i = 0;
    const n = pattern.length;

    while (i < n) {
      const c = pattern[i];
      if (c === '*') {
        if (i + 1 < n && pattern[i + 1] === '*') {
          if (i + 2 < n && pattern[i + 2] === '/') {
            res += '(?:.*/)?';
            i += 3;
          } else {
            res += '.*';
            i += 2;
          }
        } else {
          res += '[^/]*';
          i += 1;
        }
      } else if (c === '?') {
        res += '[^/]';
        i += 1;
      } else if ('.+^$()[]{}|\\'.includes(c)) {
        res += '\\' + c;
        i += 1;
      } else {
        res += c;
        i += 1;
      }
    }

    let regexStr: string;
    if (!anchored && !pattern.includes('/')) {
      regexStr = '(?:^|/)' + res + '(?:/.*|$)';
    } else {
      regexStr = '^' + res + '(?:/.*|$)';
    }

    try {
      return new RegExp(regexStr);
    } catch {
      return null;
    }
  }

  isIgnored(targetPath: string): boolean {
    if (!targetPath || targetPath === '.') return false;

    let relPath = path.isAbsolute(targetPath)
      ? path.relative(this.workspacePath, targetPath)
      : targetPath;

    relPath = relPath.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
    if (!relPath || relPath === '.') return false;

    let ignored = false;
    for (const rule of this.rules) {
      if (!rule.regex) continue;

      let checkPath = relPath;
      if (rule.baseDir) {
        if (!relPath.startsWith(rule.baseDir + '/') && relPath !== rule.baseDir) {
          continue;
        }
        checkPath = relPath.startsWith(rule.baseDir + '/')
          ? relPath.slice(rule.baseDir.length + 1)
          : relPath;
      }

      if (rule.regex.test(checkPath)) {
        ignored = !rule.isNegation;
      }
    }

    return ignored;
  }
}
