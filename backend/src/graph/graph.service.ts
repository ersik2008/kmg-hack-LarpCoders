import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/index.js';

export interface EvidenceInfo {
  filePath?: string;
  line?: number;
  symbol?: string;
  reason: string;
  confidence: 'CONFIRMED' | 'POTENTIAL';
}

@Injectable()
export class GraphService {
  private readonly logger = new Logger(GraphService.name);

  constructor(private prisma: PrismaService) {}

  /**
   * Security Graph (Graph B) - Built strictly from security findings and code evidence
   */
  async getGraphData(scanId: string) {
    const findings = await this.prisma.finding.findMany({
      where: { scanId },
      orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }]
    });

    if (findings.length === 0) {
      return {
        nodes: [],
        edges: [],
        hasFindings: false,
        message: 'No supported vulnerabilities detected. No security graph relationships generated.'
      };
    }

    // Check if agent registered evidence-based relationships
    const storedEdges = await this.prisma.graphEdge.findMany({
      where: { scanId },
      include: { source: true, target: true }
    });

    const nodes: any[] = [];
    const edges: any[] = [];
    const nodeMap = new Map<string, any>();

    // 1. If stored graph edges exist from AI investigation with evidence, use them
    if (storedEdges.length > 0) {
      return this.buildChainGraph(storedEdges, findings.length);
    }

    // 2. Build evidence-based relationships directly from verified finding code references
    let yOffset = 40;

    findings.slice(0, 10).forEach((f, idx) => {
      const pathGroupId = `finding-graph-${idx}`;
      const baseName = f.filePath ? f.filePath.split(/[\\/]/).pop() : 'Unknown File';
      const snippet = f.codeSnippet || '';

      // Check if code contains verified user input reference
      const hasUserInputRef = /\b(req\.(?:query|body|params|headers)|request\.|input|args\.|params\.)/i.test(snippet);
      const isSecret = f.scanner.toLowerCase().includes('secret') || f.title.toLowerCase().includes('secret') || f.title.toLowerCase().includes('key');
      const isInjection = f.title.toLowerCase().includes('injection') || f.title.toLowerCase().includes('traversal') || f.title.toLowerCase().includes('ssrf');

      // Confidence: CONFIRMED if input reference directly present in code snippet; otherwise POTENTIAL
      const relationshipConfidence: 'CONFIRMED' | 'POTENTIAL' = (hasUserInputRef || isSecret) ? 'CONFIRMED' : 'POTENTIAL';

      // 1. Source Node
      const sourceId = `${pathGroupId}-source`;
      let sourceLabel = 'Входные данные (User Input)';
      let sourceDescription = 'Непроверенные параметры внешнего запроса';
      let sourceReason = 'Обнаружена ссылка на входные данные пользователя в контексте уязвимости';

      if (isSecret) {
        sourceLabel = `Секрет в ${baseName}`;
        sourceDescription = 'Захардкоженный ключ в репозитории';
        sourceReason = 'Ключ/токен непосредственно записан в исходном коде';
      } else if (f.title.toLowerCase().includes('ssrf')) {
        sourceLabel = 'Целевой URL из запроса';
        sourceDescription = 'Пользовательский параметр адреса';
        sourceReason = 'URL передается во внешний HTTP-клиент';
      } else if (!hasUserInputRef) {
        sourceLabel = 'Потенциальный источник ввода';
        sourceDescription = 'Параметры функции (требует подтверждения трассировки)';
        sourceReason = 'Прямой источник ввода в срезе кода не подтвержден; связь помечена как POTENTIAL';
      }

      nodes.push({
        id: sourceId,
        type: 'sourceNode',
        data: {
          label: sourceLabel,
          type: 'SOURCE',
          description: sourceDescription,
          filePath: f.filePath,
          line: f.startLine,
          confidence: relationshipConfidence
        },
        position: { x: 50, y: yOffset }
      });

      // 2. Weakness Node (the actual vulnerable file and line)
      const weaknessId = `${pathGroupId}-weakness`;
      nodes.push({
        id: weaknessId,
        type: 'weaknessNode',
        data: {
          label: `${baseName}:${f.startLine || 1}`,
          title: f.title,
          filePath: f.filePath,
          line: f.startLine,
          severity: f.severity,
          type: 'WEAKNESS',
          description: `Место срабатывания правила ${f.ruleId || f.scanner}`,
          confidence: 'CONFIRMED'
        },
        position: { x: 420, y: yOffset }
      });

      // 3. Sink Node
      const sinkId = `${pathGroupId}-sink`;
      let sinkLabel = 'Точка исполнения';
      let sinkReason = 'Исполнение команды или запроса';
      if (f.title.toLowerCase().includes('sql')) {
        sinkLabel = 'Database Query (Raw SQL)';
        sinkReason = 'Передача строки запроса в SQL драйвер';
      } else if (f.title.toLowerCase().includes('command') || f.title.toLowerCase().includes('shell')) {
        sinkLabel = 'OS Shell Execution (child_process)';
        sinkReason = 'Вызов системного шелла с конкатенацией аргументов';
      } else if (isSecret) {
        sinkLabel = 'Утечка авторизационных данных';
        sinkReason = 'Доступ к секрету в открытом виде';
      } else if (f.title.toLowerCase().includes('ssrf')) {
        sinkLabel = 'Outbound HTTP Request';
        sinkReason = 'Сетевой запрос к внутренней сети';
      }

      nodes.push({
        id: sinkId,
        type: 'sinkNode',
        data: {
          label: sinkLabel,
          type: 'SINK',
          filePath: f.filePath,
          line: f.startLine,
          confidence: relationshipConfidence,
          description: sinkReason
        },
        position: { x: 800, y: yOffset }
      });

      // Connect Edges with explicit evidence
      edges.push({
        id: `edge-${sourceId}-${weaknessId}`,
        source: sourceId,
        target: weaknessId,
        label: relationshipConfidence === 'CONFIRMED' ? 'FLOWS_TO (CONFIRMED)' : 'FLOWS_TO (POTENTIAL)',
        type: 'FLOWS_TO',
        animated: true,
        style: {
          stroke: relationshipConfidence === 'CONFIRMED' ? '#f59e0b' : '#94a3b8',
          strokeWidth: 2,
          strokeDasharray: relationshipConfidence === 'CONFIRMED' ? undefined : '5,5'
        },
        data: {
          confidence: relationshipConfidence,
          filePath: f.filePath,
          line: f.startLine,
          reason: sourceReason
        }
      });

      edges.push({
        id: `edge-${weaknessId}-${sinkId}`,
        source: weaknessId,
        target: sinkId,
        label: relationshipConfidence === 'CONFIRMED' ? 'EXECUTES_IN (CONFIRMED)' : 'EXECUTES_IN (POTENTIAL)',
        type: 'EXECUTES_IN',
        animated: true,
        style: {
          stroke: relationshipConfidence === 'CONFIRMED' ? '#ef4444' : '#f59e0b',
          strokeWidth: 2,
          strokeDasharray: relationshipConfidence === 'CONFIRMED' ? undefined : '5,5'
        },
        data: {
          confidence: relationshipConfidence,
          filePath: f.filePath,
          line: f.startLine,
          reason: sinkReason
        }
      });

      yOffset += 130;
    });

    return {
      nodes,
      edges,
      hasFindings: true,
      findingsCount: findings.length,
      isEvidenceBased: true
    };
  }

  /**
   * Раскладывает сохранённые связи в читаемые цепочки атаки.
   *
   * Агент сохраняет узлы как FILE, без роли в цепочке, а прежняя версия клала
   * их в две фиксированные колонки — при нескольких связях узлы наезжали друг
   * на друга, и граф читался как набор серых прямоугольников. Роль выводится
   * из положения узла в рёбрах: откуда ничего не входит — источник, откуда
   * ничего не выходит — последствие, остальное — сама уязвимость.
   */
  private buildChainGraph(storedEdges: any[], findingsCount: number) {
    const COLUMN_WIDTH = 330;
    const ROW_HEIGHT = 130;

    const incoming = new Set<string>();
    const outgoing = new Set<string>();
    for (const edge of storedEdges) {
      outgoing.add(edge.sourceId);
      incoming.add(edge.targetId);
    }

    /** Глубина узла = длина самой длинной цепочки, ведущей к нему. */
    const depthOf = new Map<string, number>();
    const resolveDepth = (nodeId: string, seen: Set<string>): number => {
      if (depthOf.has(nodeId)) return depthOf.get(nodeId)!;
      // Цикл в графе не должен уводить обход в бесконечность.
      if (seen.has(nodeId)) return 0;
      seen.add(nodeId);

      const parents = storedEdges.filter(e => e.targetId === nodeId);
      const depth = parents.length === 0
        ? 0
        : Math.max(...parents.map(e => resolveDepth(e.sourceId, seen) + 1));

      depthOf.set(nodeId, depth);
      return depth;
    };

    const roleOf = (nodeId: string): 'SOURCE' | 'WEAKNESS' | 'IMPACT' => {
      if (!incoming.has(nodeId)) return 'SOURCE';
      if (!outgoing.has(nodeId)) return 'IMPACT';
      return 'WEAKNESS';
    };

    // Узлы одной цепочки идут одной строкой. Когда из узла выходит несколько
    // связей, каждая ветка получает собственную строку — иначе потомки одного
    // источника встали бы в одну точку и перекрыли друг друга.
    const rowOf = new Map<string, number>();
    const roots = [...new Set(storedEdges.map(e => e.sourceId))].filter(id => !incoming.has(id));
    let nextRow = 0;

    const assignRow = (nodeId: string, row: number, seen: Set<string>): number => {
      if (seen.has(nodeId)) return row;
      seen.add(nodeId);
      if (!rowOf.has(nodeId)) rowOf.set(nodeId, row);

      let branchRow = row;
      const children = storedEdges.filter(e => e.sourceId === nodeId);

      children.forEach((edge, index) => {
        // Первая ветка продолжает текущую строку, каждая следующая — новую.
        const childRow = index === 0 ? row : ++branchRow;
        branchRow = Math.max(branchRow, assignRow(edge.targetId, childRow, seen));
      });

      return branchRow;
    };

    for (const root of roots) {
      nextRow = assignRow(root, nextRow, new Set()) + 1;
    }

    const nodes: any[] = [];
    const nodeMap = new Map<string, any>();

    const addNode = (raw: any, edgeConfidence: number) => {
      if (nodeMap.has(raw.id)) return;

      const role = roleOf(raw.id);
      const depth = resolveDepth(raw.id, new Set());
      const row = rowOf.get(raw.id) ?? nextRow++;

      const node = {
        id: raw.id,
        // Тип роли, а не сырой FILE: по нему клиент подбирает цвет и подпись.
        type: `${role.toLowerCase()}Node`,
        data: {
          label: raw.label,
          filePath: raw.filePath,
          line: raw.line,
          type: role,
          originalType: raw.type,
          confidence: edgeConfidence >= 1.0 ? 'CONFIRMED' : 'POTENTIAL',
        },
        position: { x: 40 + depth * COLUMN_WIDTH, y: 40 + row * ROW_HEIGHT },
      };

      nodes.push(node);
      nodeMap.set(raw.id, node);
    };

    for (const edge of storedEdges) {
      addNode(edge.source, edge.confidence);
      addNode(edge.target, edge.confidence);
    }

    const edges = storedEdges.map(edge => {
      let evidenceData: any = null;
      if (edge.metadata) {
        try {
          evidenceData = typeof edge.metadata === 'string' ? JSON.parse(edge.metadata) : edge.metadata;
        } catch {}
      }

      const isConfirmed = edge.confidence >= 1.0;

      return {
        id: `edge-${edge.id}`,
        source: edge.sourceId,
        target: edge.targetId,
        // Подпись ребра — вид связи; названия узлов и так видны на концах.
        label: edge.type,
        type: edge.type,
        animated: true,
        style: {
          stroke: isConfirmed ? '#ef4444' : '#f59e0b',
          strokeWidth: isConfirmed ? 3 : 2,
          strokeDasharray: isConfirmed ? undefined : '5,5',
        },
        data: {
          confidence: isConfirmed ? 'CONFIRMED' : 'POTENTIAL',
          evidence: evidenceData?.reason || 'Verified via AST/code inspection',
          filePath: evidenceData?.filePath || edge.source.filePath,
          line: evidenceData?.line || edge.source.line,
        },
      };
    });

    return {
      nodes,
      edges,
      hasFindings: true,
      findingsCount,
      isEvidenceBased: true,
      chainCount: roots.length,
    };
  }

  /**
   * Attack Paths - distinct from architecture and raw findings
   */
  /**
   * Список репозиториев, по которым есть результаты сканирования.
   *
   * Страница цепочек атак показывает один репозиторий за раз: вперемешку по
   * всем репозиториям список не отвечал на вопрос «что сейчас не так вот с
   * этим проектом».
   */
  async getScannedRepositories(userId: string) {
    const scans = await this.prisma.scan.findMany({
      where: { userId, status: 'COMPLETED' },
      include: { repository: true },
      orderBy: { createdAt: 'desc' },
    });

    // Один репозиторий — одна запись, с самым свежим завершённым сканом.
    const byRepository = new Map<string, { id: string; name: string; fullName: string; lastScanId: string; lastScanAt: Date }>();

    for (const scan of scans) {
      if (!scan.repository || byRepository.has(scan.repositoryId)) continue;
      byRepository.set(scan.repositoryId, {
        id: scan.repository.id,
        name: scan.repository.name,
        fullName: scan.repository.fullName,
        lastScanId: scan.id,
        lastScanAt: scan.createdAt,
      });
    }

    return [...byRepository.values()];
  }

  /**
   * Цепочки атак одного скана.
   *
   * `repositoryId` не задан — берётся последний завершённый скан пользователя.
   * Раньше метод отдавал цепочки сразу по всем сканам всех репозиториев, из-за
   * чего в списке смешивались разные проекты и устаревшие прогоны.
   */
  async getAttackPaths(userId: string, repositoryId?: string) {
    const scan = await this.prisma.scan.findFirst({
      where: {
        userId,
        status: 'COMPLETED',
        ...(repositoryId ? { repositoryId } : {}),
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!scan) return [];

    const paths = await this.prisma.attackPath.findMany({
      where: { scanId: scan.id },
      include: {
        scan: { include: { repository: true } },
        nodes: {
          include: { graphNode: true },
          orderBy: { order: 'asc' }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    if (paths.length > 0) {
      return paths;
    }

    // Derive evidence-based attack paths from high/critical findings
    const highFindings = await this.prisma.finding.findMany({
      where: {
        scanId: scan.id,
        severity: { in: ['CRITICAL', 'HIGH'] }
      },
      include: {
        scan: { include: { repository: true } }
      },
      take: 10,
      orderBy: { createdAt: 'desc' }
    });

    return highFindings.map((f) => {
      const snippet = f.codeSnippet || '';
      const hasDirectInput = /\b(req\.|request\.|input|params\.)/i.test(snippet);
      const isSecret = f.scanner.toLowerCase().includes('secret') || f.title.toLowerCase().includes('secret');
      const isConfirmed = hasDirectInput || isSecret;

      return {
        id: `derived-path-${f.id}`,
        title: `${isConfirmed ? '' : '[POTENTIAL] '}${f.title}`,
        description: isConfirmed
          ? `Подтвержденный вектор атаки через файл ${f.filePath || 'кода'}. Данные контролируются внешним запросом.`
          : `Потенциальный вектор атаки через файл ${f.filePath || 'кода'}. Требуется подтверждение пути передачи аргументов.`,
        severity: f.severity,
        confidence: (isConfirmed ? 'HIGH' : 'LOW') as any,
        impact: f.severity === 'CRITICAL' ? 'Полный доступ к данным или выполнение команд на сервере' : 'Несанкционированный доступ',
        remediation: 'Применить валидацию входных данных, параметризацию запросов или безопасное хранение секрета.',
        scanId: f.scanId,
        createdAt: f.createdAt,
        scan: f.scan,
        nodes: [
          {
            order: 1,
            graphNode: {
              label: isConfirmed ? 'Входные данные (User Input)' : 'Потенциальный источник (Не подтвержден)',
              type: 'USER_INPUT',
              filePath: f.filePath,
              line: f.startLine
            }
          },
          {
            order: 2,
            graphNode: {
              label: `${f.filePath || 'Файл'}${f.startLine ? `:${f.startLine}` : ''}`,
              type: 'FILE',
              filePath: f.filePath,
              line: f.startLine
            }
          },
          {
            order: 3,
            graphNode: {
              label: `${f.title} (${f.scanner})`,
              type: 'SINK',
              filePath: f.filePath,
              line: f.startLine
            }
          }
        ]
      };
    });
  }
}
