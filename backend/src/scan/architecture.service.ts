import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface FileNode {
  name: string;
  path: string;
  type: 'file' | 'directory';
  children?: FileNode[];
  size?: number;
  lineCount?: number;
  hasFindings?: boolean;
  highestSeverity?: string;
}

export interface ArchitectureNode {
  id: string;
  label: string;
  type: 'MODULE' | 'CONTROLLER' | 'SERVICE' | 'MODEL' | 'DATABASE' | 'EXTERNAL_API' | 'CONFIG' | 'FILE';
  filePath: string;
  line?: number;
  description?: string;
  position?: { x: number; y: number };
}

export interface ArchitectureEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  type?: string;
  evidence?: string;
}

export interface ArchitectureAnalysisResult {
  nodes: ArchitectureNode[];
  edges: ArchitectureEdge[];
  fileTree: FileNode[];
  filesCount: number;
  linesCount: number;
  languages: string[];
  scannersUsed: string[];
}

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
  'venv',
  'target',
  'bin',
  'obj'
]);

const EXT_TO_LANG: Record<string, string> = {
  '.ts': 'TypeScript',
  '.tsx': 'TypeScript (React)',
  '.js': 'JavaScript',
  '.jsx': 'JavaScript (React)',
  '.py': 'Python',
  '.go': 'Go',
  '.java': 'Java',
  '.rb': 'Ruby',
  '.php': 'PHP',
  '.rs': 'Rust',
  '.cs': 'C#',
  '.cpp': 'C++',
  '.c': 'C',
  '.json': 'JSON',
  '.yml': 'YAML',
  '.yaml': 'YAML',
  '.sql': 'SQL',
  '.dockerfile': 'Docker',
  '.sh': 'Shell',
  '.bash': 'Shell'
};

@Injectable()
export class ArchitectureService {
  private readonly logger = new Logger(ArchitectureService.name);

  /**
   * Redact secrets from code or text (implements Section 13)
   */
  redactSecrets(content: string): string {
    if (!content) return '';
    return content
      .replace(/AKIA[0-9A-Z]{16}/g, 'AKIA****REDACTED****')
      .replace(/(aws_secret_access_key\s*[:=]\s*['"]?)[A-Za-z0-9/+=]{30,50}(['"]?)/gi, '$1****REDACTED_AWS_SECRET****$2')
      .replace(/(api[_-]?key\s*[:=]\s*['"]?)[a-zA-Z0-9_\-]{20,80}(['"]?)/gi, '$1****REDACTED_API_KEY****$2')
      .replace(/(secret\s*[:=]\s*['"]?)[a-zA-Z0-9_\-]{16,80}(['"]?)/gi, '$1****REDACTED_SECRET****$2')
      .replace(/(token\s*[:=]\s*['"]?)[a-zA-Z0-9_\-\.]{20,120}(['"]?)/gi, '$1****REDACTED_TOKEN****$2')
      .replace(/(password\s*[:=]\s*['"]?)[^'"\s]{6,40}(['"]?)/gi, '$1****REDACTED_PASSWORD****$2')
      .replace(/ghp_[A-Za-z0-9]{36}/g, 'ghp_****REDACTED_GITHUB_TOKEN****')
      .replace(/-----BEGIN [A-Z\s]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z\s]+ PRIVATE KEY-----/g, '-----BEGIN PRIVATE KEY-----\n****REDACTED_PRIVATE_KEY****\n-----END PRIVATE KEY-----');
  }

  /**
   * Analyze the full project workspace to produce:
   * 1. Architecture Graph (Graph A) - ALWAYS created
   * 2. Hierarchical File Tree
   * 3. Metadata (lines, files, languages)
   */
  async analyzeWorkspace(workspacePath: string): Promise<ArchitectureAnalysisResult> {
    const rawFiles: { relPath: string; fullPath: string; ext: string; size: number }[] = [];
    const languagesSet = new Set<string>();
    let linesCount = 0;

    // 1. Recursive file collection
    await this.walkDir(workspacePath, workspacePath, rawFiles);

    // 2. Build Tree & Count Lines
    for (const file of rawFiles) {
      const lang = EXT_TO_LANG[file.ext.toLowerCase()];
      if (lang) languagesSet.add(lang);

      if (file.size < 500 * 1024) {
        try {
          const content = await fs.readFile(file.fullPath, 'utf8');
          const lines = content.split(/\r?\n/).length;
          linesCount += lines;
        } catch {}
      }
    }

    const fileTree = this.buildTreeHierarchy(rawFiles);
    const languages = Array.from(languagesSet);

    // 3. Extract Architecture Graph A
    const { nodes, edges } = await this.extractArchitectureGraph(workspacePath, rawFiles);

    return {
      nodes,
      edges,
      fileTree,
      filesCount: rawFiles.length,
      linesCount,
      languages: languages.length > 0 ? languages : ['Generic Code'],
      scannersUsed: ['Semgrep (SAST)', 'Gitleaks (Secrets)', 'Trivy (Dependencies)', 'Architecture Analyzer', 'Qwen AI Agent']
    };
  }

  /**
   * Safely read a file from the workspace
   */
  async readFileContent(workspacePath: string, relativePath: string): Promise<{ path: string; content: string; lineCount: number }> {
    const normalized = path.normalize(relativePath).replace(/^(\.\.(\/|\\|$))+/, '');
    const fullPath = path.resolve(workspacePath, normalized);

    if (!fullPath.startsWith(path.resolve(workspacePath))) {
      throw new Error('Access denied: path traversal prevented');
    }

    const stat = await fs.stat(fullPath);
    if (stat.size > 2 * 1024 * 1024) {
      return {
        path: normalized,
        content: '// File exceeds 2MB limit for viewer.',
        lineCount: 1
      };
    }

    const rawContent = await fs.readFile(fullPath, 'utf8');
    const content = this.redactSecrets(rawContent);
    const lineCount = content.split(/\r?\n/).length;

    return {
      path: normalized.replace(/\\/g, '/'),
      content,
      lineCount
    };
  }

  private async walkDir(basePath: string, currentDir: string, list: { relPath: string; fullPath: string; ext: string; size: number }[]) {
    if (list.length >= 800) return; // Cap to reasonable size for performance

    try {
      const entries = await fs.readdir(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          if (!IGNORED_DIRS.has(entry.name)) {
            await this.walkDir(basePath, path.join(currentDir, entry.name), list);
          }
        } else if (entry.isFile()) {
          const fullPath = path.join(currentDir, entry.name);
          try {
            const stat = await fs.stat(fullPath);
            const relPath = path.relative(basePath, fullPath).replace(/\\/g, '/');
            const ext = path.extname(entry.name).toLowerCase();
            list.push({ relPath, fullPath, ext, size: stat.size });
          } catch {}
        }
      }
    } catch {}
  }

  private buildTreeHierarchy(files: { relPath: string; size: number }[]): FileNode[] {
    const root: { [key: string]: any } = {};

    for (const file of files) {
      const parts = file.relPath.split('/');
      let current = root;

      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        const isFile = i === parts.length - 1;

        if (!current[part]) {
          current[part] = {
            __data: {
              name: part,
              path: parts.slice(0, i + 1).join('/'),
              type: isFile ? 'file' : 'directory',
              size: isFile ? file.size : undefined,
              children: isFile ? undefined : {}
            }
          };
        }
        if (!isFile) {
          current = current[part].__data.children;
        }
      }
    }

    const toArray = (obj: any): FileNode[] => {
      const result: FileNode[] = [];
      const keys = Object.keys(obj).sort((a, b) => {
        const aIsDir = obj[a].__data.type === 'directory';
        const bIsDir = obj[b].__data.type === 'directory';
        if (aIsDir && !bIsDir) return -1;
        if (!aIsDir && bIsDir) return 1;
        return a.localeCompare(b);
      });

      for (const key of keys) {
        const item = obj[key].__data;
        if (item.type === 'directory' && item.children) {
          result.push({
            name: item.name,
            path: item.path,
            type: 'directory',
            children: toArray(item.children)
          });
        } else {
          result.push({
            name: item.name,
            path: item.path,
            type: 'file',
            size: item.size
          });
        }
      }
      return result;
    };

    return toArray(root);
  }

  /**
   * Parse real file code to extract modules, controllers, services, database models, and their calls
   */
  private async extractArchitectureGraph(workspacePath: string, files: { relPath: string; fullPath: string; ext: string; size: number }[]): Promise<{ nodes: ArchitectureNode[]; edges: ArchitectureEdge[] }> {
    const nodesMap = new Map<string, ArchitectureNode>();
    const edges: ArchitectureEdge[] = [];

    // Filter relevant code files
    const codeFiles = files.filter(f => 
      ['.ts', '.js', '.jsx', '.tsx', '.py', '.go', '.java', '.json', '.yml', '.yaml'].includes(f.ext) &&
      !f.relPath.includes('.spec.') && !f.relPath.includes('.test.')
    );

    let dbDetected = false;
    let externalApiDetected = false;

    for (const f of codeFiles) {
      if (f.size > 250 * 1024) continue; // Skip huge files

      let content = '';
      try {
        content = await fs.readFile(f.fullPath, 'utf8');
      } catch {
        continue;
      }

      const lowerPath = f.relPath.toLowerCase();
      const baseName = path.basename(f.relPath);

      // Determine node type
      let type: ArchitectureNode['type'] = 'FILE';
      let label = baseName;

      if (lowerPath.includes('controller') || /@Controller|express\(\)|@router|router\.get/i.test(content)) {
        type = 'CONTROLLER';
        const ctrlMatch = content.match(/class\s+([A-Za-z0-9_]+Controller)/);
        label = ctrlMatch ? ctrlMatch[1] : baseName.replace(/\.[^.]+$/, '');
      } else if (lowerPath.includes('service') || /@Injectable|def\s+[a-z0-9_]+_service/i.test(content)) {
        type = 'SERVICE';
        const srvMatch = content.match(/class\s+([A-Za-z0-9_]+Service)/);
        label = srvMatch ? srvMatch[1] : baseName.replace(/\.[^.]+$/, '');
      } else if (lowerPath.includes('module') || /@Module/i.test(content)) {
        type = 'MODULE';
        const modMatch = content.match(/class\s+([A-Za-z0-9_]+Module)/);
        label = modMatch ? modMatch[1] : baseName.replace(/\.[^.]+$/, '');
      } else if (lowerPath.includes('model') || lowerPath.includes('entity') || lowerPath.includes('schema') || /@Entity|schema\.prisma/i.test(content)) {
        type = 'MODEL';
        label = baseName.replace(/\.[^.]+$/, '');
      } else if (baseName === 'Dockerfile' || baseName.includes('docker-compose') || baseName === 'package.json' || baseName.startsWith('.env')) {
        type = 'CONFIG';
        label = baseName;
      }

      // Check for Database interactions
      if (/prisma|typeorm|mongoose|sequelize|pg|postgres|mysql2|sqlite|redis|psycopg2|sqlalchemy/i.test(content)) {
        dbDetected = true;
      }

      // Check for External API calls
      if (/fetch\(|axios\.|httpService|requests\.get|requests\.post|got\(/i.test(content)) {
        externalApiDetected = true;
      }

      const nodeId = f.relPath;
      nodesMap.set(nodeId, {
        id: nodeId,
        label,
        type,
        filePath: f.relPath,
        line: 1,
        description: `${type}: ${f.relPath}`
      });

      // Extract relationships (Imports & Calls)
      const importMatches = content.matchAll(/(?:import\s+(?:\{([^}]+)\}|\*\s+as\s+([A-Za-z0-9_]+)|([A-Za-z0-9_]+))\s+from\s+['"]([^'"]+)['"]|require\(['"]([^'"]+)['"]\))/g);
      for (const match of importMatches) {
        const importTarget = match[4] || match[5];
        if (importTarget && importTarget.startsWith('.')) {
          // Resolve relative path
          const resolvedDir = path.dirname(f.relPath);
          const candidateBase = path.normalize(path.join(resolvedDir, importTarget)).replace(/\\/g, '/');

          // Match against known code files
          const targetFile = codeFiles.find(cf => 
            cf.relPath.startsWith(candidateBase) ||
            cf.relPath === candidateBase + '.ts' ||
            cf.relPath === candidateBase + '.js' ||
            cf.relPath === candidateBase + '/index.ts'
          );

          if (targetFile && targetFile.relPath !== f.relPath) {
            edges.push({
              id: `edge-${f.relPath}-${targetFile.relPath}`,
              source: f.relPath,
              target: targetFile.relPath,
              label: 'IMPORTS',
              type: 'IMPORTS',
              evidence: match[0]
            });
          }
        }
      }
    }

    // Add Database Node if detected
    if (dbDetected) {
      const dbNodeId = 'database-service';
      nodesMap.set(dbNodeId, {
        id: dbNodeId,
        label: 'Database (SQL/NoSQL/ORM)',
        type: 'DATABASE',
        filePath: 'Database Storage',
        description: 'Хранилище данных и транзакций'
      });

      // Connect Services to DB
      for (const [id, node] of nodesMap.entries()) {
        if (node.type === 'SERVICE' || node.type === 'MODEL') {
          edges.push({
            id: `edge-${id}-db`,
            source: id,
            target: dbNodeId,
            label: 'CONNECTS_TO',
            type: 'CONNECTS_TO',
            evidence: 'Database access detected in service logic'
          });
        }
      }
    }

    // Add External API Node if detected
    if (externalApiDetected) {
      const apiNodeId = 'external-api';
      nodesMap.set(apiNodeId, {
        id: apiNodeId,
        label: 'External Services & APIs',
        type: 'EXTERNAL_API',
        filePath: 'HTTP Client',
        description: 'Внешние интеграции и вызовы'
      });

      for (const [id, node] of nodesMap.entries()) {
        if (node.type === 'SERVICE' || node.type === 'CONTROLLER') {
          edges.push({
            id: `edge-${id}-ext`,
            source: id,
            target: apiNodeId,
            label: 'CALLS',
            type: 'CALLS',
            evidence: 'Outbound HTTP requests'
          });
          break; // Link to one representative
        }
      }
    }

    // Fallback if no specific controllers/services were found (e.g. small or script repo)
    if (nodesMap.size === 0 && files.length > 0) {
      const sampleFiles = files.slice(0, 10);
      for (const f of sampleFiles) {
        nodesMap.set(f.relPath, {
          id: f.relPath,
          label: path.basename(f.relPath),
          type: 'FILE',
          filePath: f.relPath,
          description: f.relPath
        });
      }
    }

    // Compute coordinate positions for ReactFlow (Layered Layout)
    const allNodesList = Array.from(nodesMap.values());
    const controllers = allNodesList.filter(n => n.type === 'CONTROLLER');
    const services = allNodesList.filter(n => n.type === 'SERVICE');
    const models = allNodesList.filter(n => n.type === 'MODEL');
    const databases = allNodesList.filter(n => n.type === 'DATABASE');
    const externals = allNodesList.filter(n => n.type === 'EXTERNAL_API');
    const others = allNodesList.filter(n => !['CONTROLLER', 'SERVICE', 'MODEL', 'DATABASE', 'EXTERNAL_API'].includes(n.type));

    const setPositions = (list: ArchitectureNode[], x: number) => {
      list.forEach((n, idx) => {
        n.position = { x, y: 50 + idx * 100 };
      });
    };

    setPositions(controllers, 60);
    setPositions(services, 360);
    setPositions([...models, ...databases, ...externals], 660);
    setPositions(others, 960);

    return {
      nodes: allNodesList,
      edges
    };
  }
}
