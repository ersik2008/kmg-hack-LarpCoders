import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { PrismaService } from '../prisma/index.js';

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

export interface RelationshipEvidence {
  filePath?: string;
  line?: number;
  symbol?: string;
  reason: string;
  confidence?: 'CONFIRMED' | 'POTENTIAL';
}

/**
 * Keeps a single tool result well inside the model's context budget.
 * Every agent turn resends the whole transcript, so large tool output does not
 * just cost one request — it is paid again on every following step. Raise this
 * only if the Groq account has a higher tokens-per-minute allowance.
 */
const AGENT_FINDINGS_LIMIT = Number(process.env.AGENT_FINDINGS_LIMIT || 8);

@Injectable()
export class AgentToolsService {
  private readonly logger = new Logger(AgentToolsService.name);

  constructor(private prisma: PrismaService) {}

  /**
   * Pure Node.js directory walker - 100% cross-platform, no shell find/grep needed
   */
  async getRepositoryStructure(workspacePath: string): Promise<string> {
    try {
      const files: string[] = [];
      await this.collectFiles(workspacePath, workspacePath, files, 0, 4);

      if (files.length === 0) {
        return "Repository is empty or only contains ignored directories (.git, node_modules).";
      }

      return `Total files found (${files.length}):\n` + files.slice(0, 40).join('\n') + (files.length > 40 ? `\n...and ${files.length - 40} more files` : '');
    } catch (e: unknown) {
      return `Error reading structure: ${(e as Error).message}`;
    }
  }

  private async collectFiles(basePath: string, currentDir: string, result: string[], depth: number, maxDepth: number) {
    if (depth > maxDepth || result.length >= 200) return;

    try {
      const entries = await fs.readdir(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          if (!IGNORED_DIRS.has(entry.name)) {
            await this.collectFiles(basePath, path.join(currentDir, entry.name), result, depth + 1, maxDepth);
          }
        } else if (entry.isFile()) {
          const relPath = path.relative(basePath, path.join(currentDir, entry.name)).replace(/\\/g, '/');
          result.push(relPath);
        }
      }
    } catch {
      // Ignore unreadable dirs
    }
  }

  /**
   * Safely read file content with bounds
   */
  async getFile(workspacePath: string, filePath: string): Promise<string> {
    try {
      const normalized = path.normalize(filePath).replace(/^(\.\.(\/|\\|$))+/, '');
      const fullPath = path.resolve(workspacePath, normalized);

      if (!fullPath.startsWith(path.resolve(workspacePath))) {
        return "Error: Access denied (path traversal prevented)";
      }

      const stat = await fs.stat(fullPath);
      if (stat.size > 1024 * 1024) {
        return "Error: File too large to read in full (> 1MB). Use get_file_range instead.";
      }

      const content = await fs.readFile(fullPath, 'utf8');
      return content.substring(0, 2500);
    } catch (e: unknown) {
      return `Error reading file ${filePath}: ${(e as Error).message}`;
    }
  }

  /**
   * Read specific lines from a file
   */
  async getFileRange(workspacePath: string, filePath: string, startLine: number, endLine: number): Promise<string> {
    try {
      const normalized = path.normalize(filePath).replace(/^(\.\.(\/|\\|$))+/, '');
      const fullPath = path.resolve(workspacePath, normalized);

      if (!fullPath.startsWith(path.resolve(workspacePath))) {
        return "Error: Access denied";
      }

      const content = await fs.readFile(fullPath, 'utf8');
      const lines = content.split(/\r?\n/);
      const start = Math.max(1, startLine) - 1;
      const end = Math.min(lines.length, endLine);

      const slice = lines.slice(start, end).map((l, i) => `${start + i + 1}: ${l}`).join('\n');
      return slice || "No lines in requested range";
    } catch (e: unknown) {
      return `Error reading range: ${(e as Error).message}`;
    }
  }

  /**
   * Pure Node.js text/code search across repository files
   */
  async searchCode(workspacePath: string, query: string): Promise<string> {
    if (!query || query.trim().length === 0) {
      return "Error: Empty search query";
    }

    try {
      const matches: string[] = [];
      const lowerQuery = query.toLowerCase();
      await this.searchInDirectory(workspacePath, workspacePath, lowerQuery, matches);

      if (matches.length === 0) {
        return `No matches found for query: "${query}"`;
      }

      return matches.slice(0, 15).join('\n');
    } catch (e: unknown) {
      return `Search failed: ${(e as Error).message}`;
    }
  }

  private async searchInDirectory(basePath: string, currentDir: string, query: string, matches: string[]) {
    if (matches.length >= 15) return;

    try {
      const entries = await fs.readdir(currentDir, { withFileTypes: true });

      for (const entry of entries) {
        if (matches.length >= 15) return;

        const fullPath = path.join(currentDir, entry.name);

        if (entry.isDirectory()) {
          if (!IGNORED_DIRS.has(entry.name)) {
            await this.searchInDirectory(basePath, fullPath, query, matches);
          }
        } else if (entry.isFile()) {
          const relPath = path.relative(basePath, fullPath).replace(/\\/g, '/');
          try {
            const stat = await fs.stat(fullPath);
            if (stat.size < 512 * 1024) {
              const content = await fs.readFile(fullPath, 'utf8');
              const lines = content.split(/\r?\n/);
              for (let i = 0; i < lines.length; i++) {
                if (lines[i].toLowerCase().includes(query)) {
                  matches.push(`${relPath}:${i + 1}: ${lines[i].trim().slice(0, 100)}`);
                  if (matches.length >= 15) return;
                }
              }
            }
          } catch {}
        }
      }
    } catch {}
  }

  /**
   * Find files matching pattern
   */
  async findFiles(workspacePath: string, pattern: string): Promise<string> {
    const files: string[] = [];
    await this.collectFiles(workspacePath, workspacePath, files, 0, 5);

    const regex = new RegExp(pattern.replace(/\*/g, '.*'), 'i');
    const matched = files.filter(f => regex.test(f));

    return matched.length > 0 ? matched.slice(0, 30).join('\n') : `No files matching pattern: ${pattern}`;
  }

  /**
   * Inspect dependencies and manifests
   */
  async getDependencies(workspacePath: string): Promise<string> {
    const depsInfo: string[] = [];

    // Check package.json
    try {
      const pkgPath = path.join(workspacePath, 'package.json');
      const pkgRaw = await fs.readFile(pkgPath, 'utf8');
      const pkg = JSON.parse(pkgRaw);
      depsInfo.push(`Node.js Dependencies:\n${JSON.stringify({ dependencies: pkg.dependencies, devDependencies: pkg.devDependencies }, null, 2)}`);
    } catch {}

    // Check requirements.txt
    try {
      const reqPath = path.join(workspacePath, 'requirements.txt');
      const reqs = await fs.readFile(reqPath, 'utf8');
      depsInfo.push(`Python Requirements:\n${reqs.slice(0, 1200)}`);
    } catch {}

    return depsInfo.length > 0 ? depsInfo.join('\n\n') : 'No standard dependency manifests found (package.json, requirements.txt).';
  }

  /**
   * Retrieve all findings recorded for this scan
   */
  /**
   * Findings handed to the LLM.
   *
   * A real repository easily produces hundreds of findings; dumping them all
   * blew past the model's token limit and the investigation never ran. The most
   * severe ones are sent, compactly, with the rest summarised by count.
   */
  async getFindings(scanId: string, limit = AGENT_FINDINGS_LIMIT): Promise<string> {
    const all = await this.prisma.finding.findMany({
      where: { scanId },
      select: {
        id: true,
        scanner: true,
        severity: true,
        confidence: true,
        title: true,
        description: true,
        filePath: true,
        startLine: true,
        codeSnippet: true
      }
    });

    const rank: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
    const sorted = [...all].sort((a, b) => (rank[b.severity] || 0) - (rank[a.severity] || 0));
    const shown = sorted.slice(0, limit);

    const counts = all.reduce<Record<string, number>>((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {});

    const compact = shown.map(f => ({
      id: f.id,
      scanner: f.scanner,
      severity: f.severity,
      confidence: f.confidence,
      title: (f.title || '').slice(0, 110),
      description: (f.description || '').slice(0, 180),
      filePath: f.filePath,
      startLine: f.startLine,
      codeSnippet: (f.codeSnippet || '').slice(0, 160),
    }));

    return JSON.stringify({
      totalFindings: all.length,
      countsBySeverity: counts,
      showing: compact.length,
      note: all.length > compact.length
        ? `Only the ${compact.length} most severe findings are listed. Use get_finding(finding_id) for details on any other.`
        : 'All findings are listed.',
      findings: compact,
    });
  }

  /**
   * Register relationship in the Security Graph with mandatory evidence
   */
  async buildRelationship(
    scanId: string,
    sourceLabel: string,
    targetLabel: string,
    type: string,
    evidence?: RelationshipEvidence
  ): Promise<string> {
    const confidence = evidence?.confidence || 'POTENTIAL';

    // Map labels to node types
    const deduceType = (label: string): string => {
      const l = label.toLowerCase();
      if (l.includes('req.') || l.includes('query') || l.includes('input') || l.includes('body')) return 'USER_INPUT';
      if (l.includes('db') || l.includes('query') || l.includes('exec') || l.includes('sink') || l.includes('eval')) return 'SINK';
      if (l.includes('valid') || l.includes('sanitiz') || l.includes('check')) return 'VALIDATION';
      return 'FILE';
    };

    const sourceNode = await this.ensureNode(scanId, sourceLabel, deduceType(sourceLabel), evidence?.filePath, evidence?.line);
    const targetNode = await this.ensureNode(scanId, targetLabel, deduceType(targetLabel), evidence?.filePath, evidence?.line);

    await this.prisma.graphEdge.create({
      data: {
        scanId,
        sourceId: sourceNode.id,
        targetId: targetNode.id,
        type: type as any,
        label: `${sourceLabel} -> ${targetLabel}`,
        confidence: confidence === 'CONFIRMED' ? 1.0 : 0.5,
        metadata: evidence ? JSON.stringify(evidence) : undefined
      }
    });

    return `Evidence-based relationship ${type} (${confidence}) created between ${sourceLabel} and ${targetLabel}. Evidence: ${evidence?.reason || 'Documented by AI investigation'}`;
  }

  /**
   * List all repository files (SPEC04 list_repository_files)
   */
  async listRepositoryFiles(workspacePath: string): Promise<string> {
    return this.getRepositoryStructure(workspacePath);
  }

  /**
   * Get finding by ID (SPEC04 get_finding)
   */
  async getFinding(findingId: string): Promise<string> {
    const finding = await this.prisma.finding.findUnique({
      where: { id: findingId }
    });
    return finding ? JSON.stringify(finding, null, 2) : `Finding with ID "${findingId}" not found.`;
  }

  /**
   * Get related findings sharing the same file or scanner (SPEC04 get_related_findings)
   */
  async getRelatedFindings(findingId: string): Promise<string> {
    const target = await this.prisma.finding.findUnique({ where: { id: findingId } });
    if (!target) return `Finding with ID "${findingId}" not found.`;

    const related = await this.prisma.finding.findMany({
      where: {
        scanId: target.scanId,
        filePath: target.filePath,
        id: { not: target.id }
      },
      take: 10
    });
    return JSON.stringify(related, null, 2);
  }

  /**
   * Inspect a specific function or class definition in a file (SPEC04 inspect_function)
   */
  async inspectFunction(workspacePath: string, filePath: string, symbol: string): Promise<string> {
    const fullContent = await this.getFile(workspacePath, filePath);
    if (fullContent.startsWith('Error:')) return fullContent;

    const lines = fullContent.split(/\r?\n/);
    const regex = new RegExp(`\\b(function|class|async\\s+function|const|let|def)\\s+${symbol}\\b|${symbol}\\s*\\(`, 'i');
    const matchIdx = lines.findIndex(line => regex.test(line));

    if (matchIdx === -1) {
      return `Symbol "${symbol}" not found in ${filePath}.`;
    }

    const start = Math.max(0, matchIdx - 2);
    const end = Math.min(lines.length, matchIdx + 45);
    return lines.slice(start, end).map((l, i) => `${start + i + 1}: ${l}`).join('\n');
  }

  /**
   * Get repository metadata (commit SHA, branch, total files) (SPEC04 get_repository_metadata)
   */
  async getRepositoryMetadata(workspacePath: string): Promise<string> {
    const files: string[] = [];
    await this.collectFiles(workspacePath, workspacePath, files, 0, 5);
    return JSON.stringify({
      workspacePath,
      totalFilesDiscovered: files.length,
      sampleFiles: files.slice(0, 15)
    }, null, 2);
  }

  /**
   * Get git diff (SPEC04 get_git_diff)
   */
  async getGitDiff(workspacePath: string): Promise<string> {
    try {
      const { exec } = await import('child_process');
      const { promisify } = await import('util');
      const execAsync = promisify(exec);
      const { stdout } = await execAsync('git diff HEAD~1', { cwd: workspacePath });
      return stdout.slice(0, 4000) || 'No git diff available (single shallow commit).';
    } catch {
      return 'Git diff not available for this workspace.';
    }
  }

  private async ensureNode(scanId: string, label: string, type: string, filePath?: string, line?: number) {
    let node = await this.prisma.graphNode.findFirst({
      where: { scanId, label }
    });
    if (!node) {
      node = await this.prisma.graphNode.create({
        data: {
          scanId,
          label,
          type: (['USER_INPUT', 'VALIDATION', 'SINK', 'FILE', 'DATABASE', 'FUNCTION'].includes(type) ? type : 'FILE') as any,
          filePath,
          line
        }
      });
    }
    return node;
  }
}
