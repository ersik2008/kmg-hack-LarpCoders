import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface ScanFindingResult {
  scanner: string;
  ruleId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  filePath: string;
  startLine: number;
  endLine: number;
  codeSnippet: string;
  isFallback?: boolean;
}

interface SecretPattern {
  ruleId: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  pattern: RegExp;
  description: string;
  isSecret?: boolean;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    ruleId: 'generic-api-key',
    title: 'Hardcoded API Key / Token',
    severity: 'HIGH',
    pattern: /(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"`]([A-Za-z0-9_\-]{20,})['"`]/i,
    description: 'Found potential hardcoded API key or access token.',
    isSecret: true,
  },
  {
    ruleId: 'aws-access-key',
    title: 'Hardcoded AWS Access Key',
    severity: 'CRITICAL',
    pattern: /(?:AKIA[0-9A-Z]{16})/,
    description: 'AWS Access Key ID detected in code.',
    isSecret: true,
  },
  {
    ruleId: 'github-pat',
    title: 'Hardcoded GitHub Personal Access Token',
    severity: 'CRITICAL',
    pattern: /ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}/,
    description: 'Exposed GitHub token found in repository.',
    isSecret: true,
  },
  {
    ruleId: 'private-key',
    title: 'Private Key Detected',
    severity: 'CRITICAL',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    description: 'Cryptographic private key stored in plain text.',
    isSecret: true,
  },
  {
    ruleId: 'jwt-hardcoded-secret',
    title: 'Hardcoded JWT Secret',
    severity: 'HIGH',
    pattern: /jwt\.sign\(.*,\s*['"`]([A-Za-z0-9!@#$%^&*()_+\-=]{4,})['"`]\s*[,)]/i,
    description: 'JWT signing secret hardcoded in code.',
    isSecret: true,
  },
  {
    ruleId: 'database-connection-string',
    title: 'Exposed Database Credentials in URI',
    severity: 'CRITICAL',
    pattern: /(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[A-Za-z0-9_\-\.%]+:[A-Za-z0-9_\-\.%]+@[A-Za-z0-9_\-\.]+:[0-9]+\/[A-Za-z0-9_\-]+/i,
    description: 'Database connection URI with embedded password detected.',
    isSecret: true,
  },
  {
    ruleId: 'insecure-eval',
    title: 'Insecure Dynamic Code Execution (eval/Function)',
    severity: 'CRITICAL',
    pattern: /\beval\s*\(|\bnew\s+Function\s*\(/,
    description: 'Use of eval() or Function constructor allows Remote Code Execution (RCE).',
  },
  {
    ruleId: 'sql-injection-risk',
    title: 'Potential SQL Injection via Raw Concatenation',
    severity: 'HIGH',
    pattern: /(?:\$query|\.query|\.execute)\s*\(\s*[`'"].*SELECT.*FROM.*(\+|\$\{).*[`'"]/i,
    description: 'SQL query constructed via string concatenation or interpolation.',
  },
  {
    ruleId: 'command-injection-risk',
    title: 'Command Injection Risk (child_process.exec)',
    severity: 'HIGH',
    pattern: /\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{[^`]*`|[a-zA-Z0-9_]+\s*\+\s*)/,
    description: 'Shell command executed with untrusted input concatenation.',
  },
  {
    ruleId: 'hardcoded-password',
    title: 'Hardcoded Password Variable',
    severity: 'HIGH',
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"`](?!.*(env|process\.env|\$|[{}]))([A-Za-z0-9!@#$%^&*()_+\-=]{5,})['"`]/i,
    description: 'Hardcoded password string found in source code.',
    isSecret: true,
  },
  {
    ruleId: 'disable-cors-any-origin',
    title: 'Insecure Permissive CORS (*)',
    severity: 'MEDIUM',
    pattern: /origin:\s*['"`]\*['"`]|cors\(\s*\{\s*origin:\s*true\s*\}\s*\)/i,
    description: 'CORS configured to allow any origin without restrictions.',
  },
  {
    ruleId: 'ssrf-untrusted-fetch',
    title: 'Server-Side Request Forgery (SSRF) Risk',
    severity: 'HIGH',
    pattern: /(?:fetch|axios\.get|axios\.post|http\.get)\s*\(\s*(?:targetUrl|url|req\.query\.|req\.body\.)/i,
    description: 'Direct outbound HTTP request made to user-controlled URL without validation.',
  },
  {
    ruleId: 'reflected-xss',
    title: 'Potential Cross-Site Scripting (XSS)',
    severity: 'HIGH',
    pattern: /(?:res\.send|innerHTML)\s*\(\s*[`'"].*<.*(\$\{|req\.query|req\.body).*[`'"]/i,
    description: 'Unescaped user input directly rendered into HTML response.',
  },
  {
    ruleId: 'path-traversal',
    title: 'Path Traversal File Access',
    severity: 'HIGH',
    pattern: /(?:readFile|readFileSync|createReadStream)\s*\(\s*(?:path\.join\([^)]*req\.(?:query|params|body)|req\.(?:query|params|body))/i,
    description: 'User-controlled input passed directly into filesystem read API.',
  },
  {
    ruleId: 'weak-crypto-md5',
    title: 'Use of Weak Hash Function (MD5/SHA1)',
    severity: 'MEDIUM',
    pattern: /crypto\.createHash\(\s*['"`](?:md5|sha1)['"`]\s*\)/i,
    description: 'Legacy hash algorithm vulnerable to collision attacks used.',
  }
];

const IGNORED_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  '.next',
  '.idea',
  '.vscode',
  'vendor',
  '__pycache__',
  '.venv',
  'venv'
]);

const SCANNABLE_EXTS = new Set([
  '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
  '.py', '.java', '.go', '.rb', '.php', '.cs',
  '.json', '.yml', '.yaml', '.env', '.env.local',
  '.sql', '.sh', '.bash', '.config', '.toml'
]);

@Injectable()
export class BuiltinScannerService {
  private readonly logger = new Logger(BuiltinScannerService.name);

  async scanWorkspace(workspacePath: string): Promise<ScanFindingResult[]> {
    this.logger.log(`[FALLBACK SCANNER] Starting regex-based fallback security scan on ${workspacePath}`);
    const findings: ScanFindingResult[] = [];

    try {
      await this.scanDirectory(workspacePath, workspacePath, findings);
      this.logger.log(`[FALLBACK SCANNER] Scan finished. Findings detected: ${findings.length}`);
    } catch (err: any) {
      this.logger.error(`Error during fallback workspace scan: ${err.message}`);
    }

    return findings;
  }

  private async scanDirectory(basePath: string, currentDir: string, findings: ScanFindingResult[]): Promise<void> {
    const entries = await fs.readdir(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name)) {
          await this.scanDirectory(basePath, fullPath, findings);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SCANNABLE_EXTS.has(ext) || entry.name.startsWith('.env')) {
          await this.scanFile(basePath, fullPath, findings);
        }
      }
    }
  }

  private async scanFile(basePath: string, filePath: string, findings: ScanFindingResult[]): Promise<void> {
    try {
      const stat = await fs.stat(filePath);
      if (stat.size > 2 * 1024 * 1024) return;

      const content = await fs.readFile(filePath, 'utf-8');
      const lines = content.split(/\r?\n/);
      const relPath = path.relative(basePath, filePath).replace(/\\/g, '/');

      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const line = lines[lineIdx];

        for (const rule of SECRET_PATTERNS) {
          const match = rule.pattern.exec(line);
          if (match) {
            let snippet = lines.slice(Math.max(0, lineIdx - 1), Math.min(lines.length, lineIdx + 2)).join('\n');
            if (rule.isSecret) {
              snippet = '***REDACTED***';
            }

            findings.push({
              scanner: 'builtin_fallback',
              ruleId: `fallback-${rule.ruleId}`,
              severity: rule.severity,
              confidence: 'MEDIUM',
              title: `[Fallback] ${rule.title}`,
              description: `${rule.description} (Detected via built-in regex fallback analysis)`,
              filePath: relPath,
              startLine: lineIdx + 1,
              endLine: lineIdx + 1,
              codeSnippet: snippet.trim(),
              isFallback: true,
            });
            break;
          }
        }
      }
    } catch {
      // Ignore unreadable or binary files
    }
  }
}
