import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useParams, useSearchParams, Link } from 'react-router-dom';
import SecurityControlsPanel from '../components/SecurityControlsPanel';
import MarkdownView from '../components/MarkdownView';
import { useScanEvents } from '../hooks/useScanEvents';
import { ReactFlow, MiniMap, Controls, Background, useNodesState, useEdgesState, MarkerType } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  ArrowLeft,
  CheckCircle,
  ShieldAlert,
  Clock,
  RefreshCw,
  FileCode,
  Check,
  Folder,
  FolderOpen,
  File,
  Code,
  Layers,
  GitBranch,
  GitCommit,
  AlertTriangle,
  Search,
  ChevronDown,
  Sparkles,
  ShieldCheck,
  Crosshair,
} from 'lucide-react';

/** Сколько находок показывать до нажатия «Подробнее». */
const FINDINGS_PAGE_SIZE = 30;

/** Шагов в индикаторе пайплайна (последний, «Завершено», не показывается). */
const PIPELINE_STEP_COUNT = 5;

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

/**
 * Палитра узлов графа атак. Ключ — роль узла в цепочке, которую присылает
 * бэкенд; раньше клиент знал только часть ролей, и всё остальное рисовалось
 * одинаковыми серыми прямоугольниками.
 */
const GRAPH_ROLES: Record<string, { bg: string; border: string; color: string; icon: string; caption: string }> = {
  SOURCE:   { bg: 'rgba(59, 130, 246, 0.16)',  border: '#3b82f6', color: '#bfdbfe', icon: '→',  caption: 'Источник' },
  WEAKNESS: { bg: 'rgba(239, 68, 68, 0.16)',   border: '#ef4444', color: '#fecaca', icon: '⚠',  caption: 'Уязвимость' },
  SINK:     { bg: 'rgba(249, 115, 22, 0.16)',  border: '#f97316', color: '#fed7aa', icon: '◎',  caption: 'Исполнение' },
  IMPACT:   { bg: 'rgba(168, 85, 247, 0.16)',  border: '#a855f7', color: '#e9d5ff', icon: '✸',  caption: 'Последствие' },
  FILE:     { bg: 'rgba(100, 116, 139, 0.16)', border: '#64748b', color: '#e2e8f0', icon: '◆',  caption: 'Узел' },
};

const graphRole = (raw?: string) => GRAPH_ROLES[String(raw || '').toUpperCase()] || GRAPH_ROLES.FILE;

/**
 * Слои архитектуры. Порядок задаёт колонку на графе: поток идёт слева направо,
 * от точек входа к хранилищам и внешним сервисам, — так граф из 50+ узлов
 * читается как схема, а не как лента прямоугольников.
 */
const ARCH_TYPES: Record<string, { bg: string; border: string; color: string; icon: string; label: string; layer: number }> = {
  CONTROLLER:   { bg: 'rgba(168, 85, 247, 0.16)', border: '#a855f7', color: '#e9d5ff', icon: '⚡', label: 'Контроллеры', layer: 0 },
  SERVICE:      { bg: 'rgba(59, 130, 246, 0.16)', border: '#3b82f6', color: '#bfdbfe', icon: '⚙', label: 'Сервисы',     layer: 1 },
  MODEL:        { bg: 'rgba(236, 72, 153, 0.16)', border: '#ec4899', color: '#fbcfe8', icon: '▤', label: 'Модели',      layer: 2 },
  DATABASE:     { bg: 'rgba(16, 185, 129, 0.16)', border: '#10b981', color: '#a7f3d0', icon: '▣', label: 'Базы данных', layer: 3 },
  EXTERNAL_API: { bg: 'rgba(245, 158, 11, 0.16)', border: '#f59e0b', color: '#fde68a', icon: '☁', label: 'Внешние API', layer: 3 },
  CONFIG:       { bg: 'rgba(148, 163, 184, 0.14)', border: '#64748b', color: '#e2e8f0', icon: '⚙', label: 'Конфигурация', layer: 2 },
  FILE:         { bg: 'rgba(71, 85, 105, 0.16)',  border: '#475569', color: '#cbd5e1', icon: '◆', label: 'Файлы',       layer: 2 },
};

const archType = (raw?: string) => ARCH_TYPES[String(raw || '').toUpperCase()] || ARCH_TYPES.FILE;

/** Как показывается вердикт AI по конкретной находке. */
const VERDICT_META: Record<string, { label: string; bg: string; border: string; color: string }> = {
  TRUE_POSITIVE:  { label: 'Подтверждено AI', bg: 'rgba(239, 68, 68, 0.13)',  border: 'rgba(239, 68, 68, 0.35)',  color: '#fca5a5' },
  FALSE_POSITIVE: { label: 'Ложное срабатывание', bg: 'rgba(16, 185, 129, 0.13)', border: 'rgba(16, 185, 129, 0.32)', color: '#6ee7b7' },
  UNCERTAIN:      { label: 'Требует проверки', bg: 'rgba(245, 158, 11, 0.13)', border: 'rgba(245, 158, 11, 0.32)', color: '#fcd34d' },
};

interface FindingItem {
  id: string;
  scanner: string;
  ruleId?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: string;
  title: string;
  description?: string;
  filePath?: string;
  startLine?: number;
  endLine?: number;
  codeSnippet?: string;
}

interface FileTreeNode {
  name: string;
  path: string;
  type: 'file' | 'directory';
  children?: FileTreeNode[];
  size?: number;
}

interface ScanData {
  id: string;
  status: string;
  branch?: string;
  commitSha?: string;
  riskScore?: number | null;
  policyResult?: string | null;
  createdAt: string;
  completedAt?: string | null;
  errorMessage?: string | null;
  repository?: {
    name: string;
    fullName?: string;
    defaultBranch?: string;
  };
  findings?: FindingItem[];
  aiAnalyses?: Array<{
    id: string;
    type: string;
    response: string;
    model: string;
    /** Заполнен у разбора конкретной находки (type = finding_triage). */
    findingId?: string | null;
    metadata?: {
      verdict?: string;
      confidence?: string;
      reason?: string;
      exploitation?: string;
      recommendation?: string;
    } | null;
  }>;
  scanResult?: {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    summary?: string;
  };
}

const ScanDetails = () => {
  const { id } = useParams();
  // ?file=<путь>&line=<строка> — вход с других страниц сразу к нужному месту.
  const [searchParams] = useSearchParams();

  const [scan, setScan] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<FindingItem | null>(null);

  // Фильтрация таблицы находок и постраничное раскрытие по «Подробнее».
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [findingQuery, setFindingQuery] = useState('');
  const [visibleCount, setVisibleCount] = useState(FINDINGS_PAGE_SIZE);

  // File Tree & Code Viewer state
  const [fileTree, setFileTree] = useState<FileTreeNode[]>([]);
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set(['src', 'app', 'backend']));
  const [activeFilePath, setActiveFilePath] = useState<string>('');
  const [activeFileContent, setActiveFileContent] = useState<string>('');
  const [activeFileLineCount, setActiveFileLineCount] = useState<number>(0);
  const [targetHighlightLine, setTargetHighlightLine] = useState<number | null>(null);
  const [fileLoading, setFileLoading] = useState<boolean>(false);

  // Architecture Graph (Graph A) state
  const [archNodes, setArchNodes, onArchNodesChange] = useNodesState<any>([]);
  const [archEdges, setArchEdges, onArchEdgesChange] = useEdgesState<any>([]);
  const [archFilter, setArchFilter] = useState<string>('ALL');

  // Security Attack Graph (Graph B) state
  const [secNodes, setSecNodes, onSecNodesChange] = useNodesState<any>([]);
  const [secEdges, setSecEdges, onSecEdgesChange] = useEdgesState<any>([]);
  const [secChainCount, setSecChainCount] = useState(0);

  // Metadata metrics & SPEC04 summary
  const [summaryData, setSummaryData] = useState<any>(null);
  const [metadata, setMetadata] = useState<{
    filesCount: number;
    linesCount: number;
    languages: string[];
    scannersUsed: string[];
  }>({
    filesCount: 0,
    linesCount: 0,
    languages: ['TypeScript / JavaScript'],
    scannersUsed: ['Semgrep', 'Gitleaks', 'Trivy', 'Built-in SAST', 'AI Agent']
  });

  // AI Groq Explanation state
  const [aiExplanations, setAiExplanations] = useState<Record<string, any>>({});
  const [explainingId, setExplainingId] = useState<string | null>(null);

  const codeViewerRef = useRef<HTMLDivElement>(null);

  const fetchFindingExplanation = async (findingId: string) => {
    if (aiExplanations[findingId] || explainingId === findingId) return;
    setExplainingId(findingId);
    try {
      const token = localStorage.getItem('kmg_token');
      const res = await fetch(`http://localhost:3000/api/scans/${id}/findings/${findingId}/explain`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setAiExplanations(prev => ({ ...prev, [findingId]: data }));
      }
    } catch {}
    setExplainingId(null);
  };

  const retryScan = async () => {
    const repoId = (scan as any)?.repositoryId;
    if (!repoId) return;
    try {
      const token = localStorage.getItem('kmg_token');
      const res = await fetch(`http://localhost:3000/api/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ repositoryId: repoId })
      });
      if (res.ok) {
        const newScan = await res.json();
        window.location.href = `/scans/${newScan.scanId}`;
      }
    } catch {}
  };

  // Fetch scan file tree
  const fetchFileTree = useCallback(async () => {
    if (!id) return;
    try {
      const token = localStorage.getItem('kmg_token');
      const res = await fetch(`http://localhost:3000/api/scans/${id}/tree`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        if (data.tree && data.tree.length > 0) {
          setFileTree(data.tree);
        }
        if (data.filesCount != null) {
          setMetadata(prev => ({
            ...prev,
            filesCount: data.filesCount || prev.filesCount,
            linesCount: data.linesCount || prev.linesCount,
            languages: (data.languages && data.languages.length > 0) ? data.languages : prev.languages,
            scannersUsed: (data.scanners && data.scanners.length > 0) ? data.scanners : prev.scannersUsed
          }));
        }
      }
    } catch {}
  }, [id]);

  // Fetch file content
  const openFile = useCallback(async (filePath: string, highlightLine: number | null = null) => {
    if (!id || !filePath) return;
    setActiveFilePath(filePath);
    setTargetHighlightLine(highlightLine);
    setFileLoading(true);

    try {
      const token = localStorage.getItem('kmg_token');
      const res = await fetch(`http://localhost:3000/api/scans/${id}/file?path=${encodeURIComponent(filePath)}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setActiveFileContent(data.content || '');
        setActiveFileLineCount(data.lineCount || 0);

        // Прокрутка к строке с повторами: единственная попытка через 100мс
        // промахивалась, когда React ещё не отрисовал строки файла.
        if (highlightLine) {
          let attempts = 0;
          const scrollToLine = () => {
            const lineEl = document.getElementById(`code-line-${highlightLine}`);
            if (lineEl) {
              lineEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
              return;
            }
            if (++attempts < 20) setTimeout(scrollToLine, 100);
          };
          setTimeout(scrollToLine, 60);
        }
      } else {
        setActiveFileContent('// Не удалось загрузить содержимое файла');
      }
    } catch (err: any) {
      setActiveFileContent(`// Ошибка: ${err.message}`);
    } finally {
      setFileLoading(false);
    }
  }, [id]);

  // Fetch Architecture Graph (Graph A - Always exists)
  const fetchArchitectureGraph = useCallback(async () => {
    if (!id) return;
    try {
      const token = localStorage.getItem('kmg_token');
      const res = await fetch(`http://localhost:3000/api/scans/${id}/architecture`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        const rawNodes = data.nodes || [];
        const rawEdges = data.edges || [];

        // Раскладка по слоям: узлы одного типа образуют колонку, и схема
        // читается слева направо — от точек входа к данным и внешним сервисам.
        const layerCounters: Record<number, number> = {};

        const formattedNodes = rawNodes.map((n: any) => {
          const meta = archType(n.type);
          const row = layerCounters[meta.layer] = (layerCounters[meta.layer] ?? 0) + 1;

          return {
            id: n.id,
            position: { x: 60 + meta.layer * 330, y: 40 + (row - 1) * 92 },
            data: {
              label: (
                <div style={{ display: 'flex', alignItems: 'center', gap: '7px', textAlign: 'left' }}>
                  <span style={{ fontSize: '13px', opacity: 0.9 }}>{meta.icon}</span>
                  <div style={{ overflow: 'hidden' }}>
                    <div style={{ fontSize: '11.5px', fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {n.label}
                    </div>
                    <div style={{ fontSize: '8.5px', opacity: 0.65, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      {n.type}
                    </div>
                  </div>
                </div>
              ),
              rawNode: n,
              archType: n.type,
            },
            style: {
              background: meta.bg,
              border: `1px solid ${meta.border}`,
              color: meta.color,
              borderRadius: '9px',
              padding: '8px 11px',
              width: 220,
              cursor: 'pointer',
              boxShadow: '0 4px 10px -4px rgba(0, 0, 0, 0.5)',
            },
          };
        });

        const formattedEdges = rawEdges.map((e: any) => ({
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label || '',
          animated: true,
          markerEnd: { type: MarkerType.ArrowClosed },
          style: { stroke: 'var(--primary)', strokeWidth: 1.5 },
        }));

        setArchNodes(formattedNodes);
        setArchEdges(formattedEdges);
      }
    } catch {}
  }, [id, setArchNodes, setArchEdges]);

  // Fetch Security / Attack Graph (Graph B - Only with findings)
  const fetchSecurityGraph = useCallback(async () => {
    if (!id) return;
    try {
      const token = localStorage.getItem('kmg_token');
      const res = await fetch(`http://localhost:3000/api/graph/${id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        const rawNodes = data.nodes || [];
        const rawEdges = data.edges || [];

        const formattedNodes = rawNodes.map((node: any, index: number) => {
          // Роль узла в цепочке атаки: по ней подбирается цвет и подпись.
          const role = graphRole(node.data?.type || node.type?.replace(/Node$/, ''));
          const isPotential = node.data?.confidence === 'POTENTIAL';

          return {
            id: node.id,
            position: node.position || { x: (index % 4) * 300 + 50, y: Math.floor(index / 4) * 130 + 50 },
            data: {
              label: (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', textAlign: 'left' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '9px', opacity: 0.85, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    <span>{role.icon}</span>
                    <span>{role.caption}</span>
                    {isPotential && <span style={{ opacity: 0.75 }}>· вероятн.</span>}
                  </div>
                  <div style={{ fontSize: '11.5px', fontWeight: 600, lineHeight: 1.3 }}>
                    {node.data?.label || node.id}
                  </div>
                  {node.data?.filePath && (
                    <div style={{ fontSize: '9px', opacity: 0.7, fontFamily: 'ui-monospace, monospace' }}>
                      {String(node.data.filePath).split(/[\/]/).pop()}
                      {node.data?.line ? `:${node.data.line}` : ''}
                    </div>
                  )}
                </div>
              ),
              rawNode: node.data,
            },
            style: {
              background: role.bg,
              border: `1px solid ${role.border}`,
              borderStyle: isPotential ? 'dashed' : 'solid',
              color: role.color,
              borderRadius: '10px',
              padding: '9px 12px',
              width: 230,
              cursor: 'pointer',
              boxShadow: '0 4px 12px -4px rgba(0, 0, 0, 0.5)',
            },
          };
        });

        const formattedEdges = rawEdges.map((edge: any) => ({
          id: edge.id,
          source: edge.source,
          target: edge.target,
          label: edge.label || '',
          animated: true,
          markerEnd: { type: MarkerType.ArrowClosed },
          style: edge.style || { stroke: '#ef4444', strokeWidth: 1.5 },
        }));

        setSecNodes(formattedNodes);
        setSecEdges(formattedEdges);
        // Число независимых цепочек считает бэкенд; на старых сканах его нет.
        setSecChainCount(
          data.chainCount ?? formattedNodes.filter((n: any) => n.data?.rawNode?.type === 'SOURCE').length,
        );
      }
    } catch {}
  }, [id, setSecNodes, setSecEdges]);

  // Main Scan data fetch
  const fetchScanData = useCallback(async () => {
    if (!id) return;
    try {
      const token = localStorage.getItem('kmg_token');
      const res = await fetch(`http://localhost:3000/api/scans/${id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (!res.ok) {
        throw new Error('Сканирование не найдено или нет доступа');
      }

      const data: ScanData = await res.json();
      setScan(data);

      if (data.scanResult?.summary) {
        try {
          const parsed = JSON.parse(data.scanResult.summary);
          setSummaryData(parsed);
          setMetadata({
            filesCount: parsed.filesCount || 0,
            linesCount: parsed.linesCount || 0,
            languages: parsed.languages || ['TypeScript / JavaScript'],
            scannersUsed: parsed.scannersUsed || ['Semgrep', 'Gitleaks', 'Trivy', 'Built-in SAST', 'AI Agent']
          });
          if (parsed.fileTree && parsed.fileTree.length > 0) {
            setFileTree(parsed.fileTree);
          }
        } catch {}
      }

      // Файл из ссылки имеет приоритет: переход с другой страницы должен
      // попадать ровно в указанное место, а не в первую попавшуюся находку.
      const requestedFile = searchParams.get('file');
      const requestedLine = Number(searchParams.get('line')) || null;

      if (requestedFile && !activeFilePath) {
        openFile(requestedFile, requestedLine);
      } else if (data.findings && data.findings.length > 0 && !activeFilePath) {
        const firstWithFile = data.findings.find(f => f.filePath);
        if (firstWithFile && firstWithFile.filePath) {
          openFile(firstWithFile.filePath, firstWithFile.startLine || null);
        }
      }

      // Fetch file tree and both graphs
      fetchFileTree();
      fetchArchitectureGraph();
      fetchSecurityGraph();

    } catch (err: any) {
      setError(err.message || 'Ошибка загрузки данных');
    } finally {
      setLoading(false);
    }
  }, [id, activeFilePath, openFile, fetchFileTree, fetchArchitectureGraph, fetchSecurityGraph, searchParams]);

  // Живые обновления по SSE: этапы скана приходят событием, а не по таймеру.
  useScanEvents(event => {
    if (event.scanId !== id) return;
    if (event.type === 'scan.progress' || event.type === 'scan.completed') {
      fetchScanData();
    }
  });

  // Страховочный опрос — на случай разрыва SSE. Реже, чем раньше: основной
  // канал обновлений теперь событийный.
  useEffect(() => {
    fetchScanData();
    const isRunning = scan?.status && !['COMPLETED', 'FAILED'].includes(scan.status);
    let interval: any = null;

    if (isRunning || loading) {
      interval = setInterval(() => {
        fetchScanData();
      }, 10000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [fetchScanData, scan?.status, loading]);

  // Toggle tree directory
  const toggleFolder = (folderPath: string) => {
    setExpandedFolders(prev => {
      const next = new Set(prev);
      if (next.has(folderPath)) {
        next.delete(folderPath);
      } else {
        next.add(folderPath);
      }
      return next;
    });
  };

  // Find if a file in tree has findings
  /**
   * Находки после фильтра и поиска, отсортированные по критичности:
   * самое опасное должно попадать в первую видимую страницу.
   */
  const filteredFindings = useMemo(() => {
    const list = scan?.findings || [];
    const q = findingQuery.toLowerCase().trim();

    return list
      .filter(f => severityFilter === 'ALL' || f.severity === severityFilter)
      .filter(f => {
        if (!q) return true;
        return (
          f.title?.toLowerCase().includes(q) ||
          f.filePath?.toLowerCase().includes(q) ||
          f.ruleId?.toLowerCase().includes(q) ||
          f.scanner?.toLowerCase().includes(q) ||
          f.description?.toLowerCase().includes(q)
        );
      })
      .slice()
      .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  }, [scan?.findings, severityFilter, findingQuery]);

  const visibleFindings = useMemo(
    () => filteredFindings.slice(0, visibleCount),
    [filteredFindings, visibleCount],
  );

  // Смена фильтра начинает список заново, иначе «Подробнее» помнил бы
  // раскрытие от предыдущей выборки.
  useEffect(() => {
    setVisibleCount(FINDINGS_PAGE_SIZE);
  }, [severityFilter, findingQuery]);

  const archTypeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const node of archNodes as any[]) {
      const key = String(node.data?.archType || 'FILE').toUpperCase();
      counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
  }, [archNodes]);

  /** Фильтр по типу компонента; связи остаются только между видимыми узлами. */
  const visibleArchNodes = useMemo(() => {
    if (archFilter === 'ALL') return archNodes;
    return (archNodes as any[]).filter(n => String(n.data?.archType).toUpperCase() === archFilter);
  }, [archNodes, archFilter]);

  const visibleArchEdges = useMemo(() => {
    if (archFilter === 'ALL') return archEdges;
    const ids = new Set(visibleArchNodes.map((n: any) => n.id));
    return (archEdges as any[]).filter(e => ids.has(e.source) && ids.has(e.target));
  }, [archEdges, archFilter, visibleArchNodes]);

  const fileFindingsMap = useMemo(() => {
    const map = new Map<string, FindingItem[]>();
    (scan?.findings || []).forEach(f => {
      if (f.filePath) {
        const norm = f.filePath.replace(/\\/g, '/');
        const list = map.get(norm) || [];
        list.push(f);
        map.set(norm, list);
      }
    });
    return map;
  }, [scan?.findings]);

  // Render Tree recursively
  const renderTree = (nodes: FileTreeNode[]) => {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
        {nodes.map(node => {
          const isDir = node.type === 'directory';
          const isExpanded = expandedFolders.has(node.path);
          const normPath = node.path.replace(/\\/g, '/');
          const hasVulnerabilities = fileFindingsMap.has(normPath);
          const isSelected = activeFilePath === normPath;

          if (isDir) {
            return (
              <div key={node.path}>
                <div
                  onClick={() => toggleFolder(node.path)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '4px 8px',
                    cursor: 'pointer',
                    borderRadius: '4px',
                    fontSize: '12px',
                    color: 'var(--text-muted)',
                    background: 'transparent',
                    userSelect: 'none'
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255,255,255,0.05)')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                >
                  {isExpanded ? <FolderOpen size={14} color="#38bdf8" /> : <Folder size={14} color="#38bdf8" />}
                  <span style={{ fontWeight: 500, color: 'white' }}>{node.name}</span>
                </div>
                {isExpanded && node.children && (
                  <div style={{ paddingLeft: '14px', borderLeft: '1px solid rgba(255,255,255,0.07)', marginLeft: '6px' }}>
                    {renderTree(node.children)}
                  </div>
                )}
              </div>
            );
          }

          return (
            <div
              key={node.path}
              onClick={() => openFile(node.path)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '6px',
                padding: '4px 8px',
                cursor: 'pointer',
                borderRadius: '4px',
                fontSize: '12px',
                background: isSelected ? 'rgba(99, 102, 241, 0.2)' : 'transparent',
                color: isSelected ? '#a5b4fc' : '#94a3b8',
                userSelect: 'none'
              }}
              onMouseEnter={(e) => {
                if (!isSelected) e.currentTarget.style.background = 'rgba(255,255,255,0.04)';
              }}
              onMouseLeave={(e) => {
                if (!isSelected) e.currentTarget.style.background = 'transparent';
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                <File size={13} color="#94a3b8" />
                <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{node.name}</span>
              </div>
              {hasVulnerabilities && (
                <span
                  style={{
                    width: '7px',
                    height: '7px',
                    borderRadius: '50%',
                    background: 'var(--danger)',
                    display: 'inline-block'
                  }}
                  title="Файл содержит уязвимости"
                />
              )}
            </div>
          );
        })}
      </div>
    );
  };

  const steps = [
    { key: 'CLONING', label: 'Клонирование' },
    { key: 'SCANNING', label: 'SAST & Secrets' },
    { key: 'ANALYZING', label: 'AI Анализ' },
    { key: 'GRAPHING', label: 'Построение графов' },
    { key: 'RISK_CALCULATING', label: 'Оценка риска' },
    { key: 'COMPLETED', label: 'Завершено' },
  ];

  const currentStepIndex = useMemo(() => {
    if (!scan?.status) return 0;
    if (scan.status === 'PENDING' || scan.status === 'CLONING') return 0;
    if (scan.status === 'SCANNING') return 1;
    if (scan.status === 'ANALYZING') return 2;
    if (scan.status === 'GRAPHING') return 3;
    if (scan.status === 'RISK_CALCULATING') return 4;
    if (scan.status === 'COMPLETED') return 5;
    return -1;
  }, [scan?.status]);

  if (loading && !scan) {
    return (
      <div style={{ padding: '4rem', textAlign: 'center', color: 'var(--text-muted)' }}>
        <Clock size={32} style={{ margin: '0 auto 1rem auto', animation: 'spin 2s linear infinite' }} />
        <div>Загрузка Security IDE и результатов сканирования...</div>
      </div>
    );
  }

  if (error && !scan) {
    return (
      <div className="card" style={{ border: '1px solid var(--danger)', color: 'var(--danger)', margin: '2rem' }}>
        <h3>Ошибка: {error}</h3>
        <Link to="/repositories" className="btn btn-outline" style={{ marginTop: '1rem', display: 'inline-block' }}>
          Вернуться к репозиториям
        </Link>
      </div>
    );
  }

  const isCompleted = scan?.status === 'COMPLETED';
  const isFailed = scan?.status === 'FAILED';
  const isIncomplete = Boolean(
    summaryData?.isIncomplete ||
    (isCompleted && metadata.filesCount <= 2) ||
    scan?.errorMessage?.toLowerCase().includes('incomplete')
  );
  const riskScore = isIncomplete ? 'N/A' : (scan?.riskScore != null ? scan.riskScore.toFixed(1) : '-');
  const policy = isIncomplete ? 'INCOMPLETE' : scan?.policyResult;
  const findings = scan?.findings || [];
  // Итоговое заключение — последний анализ; отдельно считаем, сколько находок
  // прошло поштучный разбор, чтобы показать охват проверки.
  const aiList = scan?.aiAnalyses || [];
  // Итоговый отчёт — это запись типа finding_analysis. Раньше бралась просто
  // последняя запись, и в блок сводки попадал разбор одной находки.
  const summaryAnalysis = [...aiList].reverse().find(a => a.type === 'finding_analysis') || null;
  const latestAiAnalysis = summaryAnalysis?.response || null;
  const latestAiModel = summaryAnalysis?.model || null;
  const aiTriageCount = aiList.filter(a => a.type === 'finding_triage').length;

  /** Вердикт AI по каждой находке — показывается прямо в её строке таблицы. */
  const verdictByFinding = new Map<string, NonNullable<ScanData['aiAnalyses']>[number]>();
  for (const analysis of aiList) {
    if (analysis.type === 'finding_triage' && analysis.findingId) {
      verdictByFinding.set(analysis.findingId, analysis);
    }
  }

  const criticalCount = scan?.scanResult?.criticalCount ?? findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = scan?.scanResult?.highCount ?? findings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = scan?.scanResult?.mediumCount ?? findings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = scan?.scanResult?.lowCount ?? findings.filter(f => f.severity === 'LOW').length;
  const infoCount = scan?.scanResult?.infoCount ?? findings.filter(f => f.severity === 'INFO').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', paddingBottom: '3rem' }}>
      
      {/* 1. TOP HEADER & METRICS BAR */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <Link to="/dashboard" style={{ color: 'var(--text-muted)', textDecoration: 'none', display: 'flex', alignItems: 'center' }}>
              <ArrowLeft size={22} />
            </Link>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <h1 style={{ margin: 0, fontSize: '1.5rem' }}>
                  {scan?.repository?.name || id}
                </h1>
                {scan?.branch && (
                  <span className="badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', background: 'rgba(255,255,255,0.08)' }}>
                    <GitBranch size={12} /> {scan.branch}
                  </span>
                )}
                {scan?.commitSha && (
                  <span className="badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', background: 'rgba(255,255,255,0.08)' }}>
                    <GitCommit size={12} /> {scan.commitSha.slice(0, 7)}
                  </span>
                )}
              </div>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', margin: '0.25rem 0 0 0', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                {isCompleted ? (
                  <>
                    <CheckCircle size={15} color={isIncomplete ? 'var(--warning)' : 'var(--accent)'} />
                    {isIncomplete ? 'Завершено с предупреждением (Incomplete)' : `Завершено ${scan?.completedAt ? new Date(scan.completedAt).toLocaleTimeString() : ''}`}
                  </>
                ) : isFailed ? (
                  <>
                    <ShieldAlert size={15} color="var(--danger)" />
                    Ошибка сканирования: {scan?.errorMessage || 'Pipeline failure'}
                  </>
                ) : (
                  <>
                    <Clock size={15} color="var(--primary)" />
                    Статус: {scan?.status || 'В процессе...'}
                  </>
                )}
              </p>
            </div>
          </div>

          {/* Вердикт, риск и действия — одна линия карточек равной высоты. */}
          <div className="scan-header-actions">
            {policy && (
              <div className="scan-stat">
                <span className="scan-stat-label">Policy Gate</span>
                <span className={`badge ${policy === 'PASS' ? 'badge-accent' : policy === 'BLOCK' ? 'badge-critical' : 'badge-warning'}`}>
                  {policy}
                </span>
              </div>
            )}

            <div className="scan-stat">
              <span className="scan-stat-label">Оценка риска</span>
              <span
                className="scan-stat-risk"
                style={{
                  color: isIncomplete
                    ? 'var(--text-muted)'
                    : Number(riskScore) > 7 ? 'var(--danger)' : Number(riskScore) > 4 ? 'var(--warning)' : 'var(--accent)',
                }}
              >
                <ShieldAlert size={16} />
                {riskScore}{isIncomplete ? '' : ' / 10'}
              </span>
            </div>

            <button onClick={fetchScanData} className="btn btn-outline scan-refresh-btn" title="Обновить данные скана">
              <RefreshCw size={15} />
            </button>
          </div>
        </div>

        {/* SPEC04 Section 2 & 25: Critical Rule - Incomplete Scan Warning Banner */}
        {isIncomplete && (
          <div className="card" style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.4)', padding: '1rem 1.25rem', display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <AlertTriangle size={24} color="#f87171" style={{ flexShrink: 0 }} />
            <div style={{ flex: 1, minWidth: '260px' }}>
              <h4 style={{ margin: 0, color: '#f87171', fontSize: '0.95rem' }}>
                ⚠ Scan Incomplete / Сканирование не завершено
              </h4>
              <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.8rem', color: '#cbd5e1' }}>
                {summaryData?.incompleteReason || scan?.errorMessage || 'Обнаружено 2 или менее файлов. Содержимое репозитория неполное. Вердикт безопасности недоступен.'}
              </p>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button onClick={retryScan} className="btn btn-primary" style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                Повторить Scan
              </button>
              <Link to="/repositories" className="btn btn-outline" style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}>
                Детали репозитория
              </Link>
            </div>
          </div>
        )}

        {/* Scan Details & Metrics Ribbon with Dynamic Scanner Statuses */}
        <div className="card scan-ribbon">
          {/* Метрики как отдельные ячейки: подпись над значением читается
              быстрее, чем строка «Статус: X  Файлов: Y» в одну линию. */}
          <div className="scan-metrics">
            <div className="scan-metric">
              <span className="scan-metric-label">Статус</span>
              <strong
                className="scan-metric-value"
                style={{ color: summaryData?.stage === 'PARTIAL' ? 'var(--warning)' : isCompleted ? 'var(--accent)' : '#38bdf8' }}
              >
                {summaryData?.stage || scan?.status || 'RUNNING'}
              </strong>
            </div>
            <div className="scan-metric">
              <span className="scan-metric-label">Файлов проверено</span>
              <strong className="scan-metric-value">{metadata.filesCount.toLocaleString('ru-RU')}</strong>
            </div>
            <div className="scan-metric">
              <span className="scan-metric-label">Строк кода</span>
              <strong className="scan-metric-value">{metadata.linesCount.toLocaleString('ru-RU')}</strong>
            </div>
            <div className="scan-metric scan-metric-wide">
              <span className="scan-metric-label">Языки</span>
              <strong className="scan-metric-value scan-metric-langs" title={metadata.languages.join(', ')}>
                {metadata.languages.join(', ')}
              </strong>
            </div>

            {/* Счётчики критичности прижаты вправо и отделены от метрик. */}
            <div className="scan-severities">
              {[
                { label: 'CRIT', value: criticalCount, cls: 'badge-critical', title: 'Критические' },
                { label: 'HIGH', value: highCount, cls: 'badge-high', title: 'Высокие' },
                { label: 'MED', value: mediumCount, cls: 'badge-medium', title: 'Средние' },
                { label: 'LOW', value: lowCount, cls: 'badge-low', title: 'Низкие' },
                ...(infoCount > 0 ? [{ label: 'INFO', value: infoCount, cls: 'badge-info', title: 'Информационные' }] : []),
              ].map(item => (
                <span
                  key={item.label}
                  className={`scan-sev ${item.cls}${item.value === 0 ? ' is-empty' : ''}`}
                  title={item.title}
                >
                  <span className="scan-sev-value">{item.value}</span>
                  <span className="scan-sev-label">{item.label}</span>
                </span>
              ))}
            </div>
          </div>

          {/* Детекторы: единый рендер вместо трёх скопированных блоков. */}
          <div className="scan-detectors">
            <span className="scan-detectors-title">Детекторы безопасности</span>

            <div className="scan-detectors-list">
              {[
                { key: 'semgrep', label: 'Semgrep', kind: 'SAST' },
                { key: 'gitleaks', label: 'Gitleaks', kind: 'Secrets' },
                { key: 'trivy', label: 'Trivy', kind: 'Deps' },
              ].map(det => {
                const s = summaryData?.scanners?.[det.key];
                const isOk = s?.status === 'COMPLETED';
                const isFail = s?.status === 'FAILED' || s?.status === 'INVALID';
                const state = isFail ? 'is-fail' : isOk ? 'is-ok' : 'is-pending';

                return (
                  <span key={det.key} className={`scan-detector ${state}`} title={s?.error || undefined}>
                    <span className="scan-detector-mark">{isFail ? '✕' : isOk ? '✓' : '⟳'}</span>
                    <span className="scan-detector-name">{det.label}</span>
                    <span className="scan-detector-kind">{det.kind}</span>
                    {s?.findingsCount > 0 && <span className="scan-detector-count">{s.findingsCount}</span>}
                  </span>
                );
              })}

              {summaryData?.scanners?.builtin_fallback && (
                <span className="scan-detector is-warn">
                  <span className="scan-detector-mark">⚠</span>
                  <span className="scan-detector-name">Fallback SAST</span>
                  <span className="scan-detector-count">{summaryData.scanners.builtin_fallback.findingsCount}</span>
                </span>
              )}

              <span className="scan-detector is-ai">
                <span className="scan-detector-mark">✦</span>
                <span className="scan-detector-name">Qwen AI Agent</span>
              </span>
            </div>
          </div>

          {/* Specific scanner errors if any failed */}
          {summaryData?.policyReasons && summaryData.policyReasons.some((r: string) => r.includes('failed') || r.includes('missing')) && (
            <div className="scan-detectors-error">
              <AlertTriangle size={14} style={{ flexShrink: 0 }} />
              <span>{summaryData.policyReasons.filter((r: string) => r.includes('failed') || r.includes('missing')).join(' | ')}</span>
            </div>
          )}
        </div>
      </div>

      {/* Progress steps (if still scanning) */}
      {!isCompleted && !isFailed && (
        <div className="card" style={{ padding: '1.15rem 1.5rem 1.35rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.1rem' }}>
            <RefreshCw size={15} color="var(--primary)" className="scan-spin" />
            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--primary)' }}>
              Прогресс пайплайна безопасности
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
              шаг {Math.min(currentStepIndex + 1, PIPELINE_STEP_COUNT)} из {PIPELINE_STEP_COUNT}
            </span>
          </div>

          <div className="pipeline">
            {/* Рельс и заполненная часть лежат за кружками: без них шаги
                висели в пустоте и не читались как последовательность. */}
            <div className="pipeline-rail" />
            <div
              className="pipeline-rail-fill"
              style={{
                width: `${(Math.max(0, Math.min(currentStepIndex, PIPELINE_STEP_COUNT - 1)) / (PIPELINE_STEP_COUNT - 1)) * 100}%`,
              }}
            />

            {steps.slice(0, PIPELINE_STEP_COUNT).map((step, idx) => {
              const isPassed = currentStepIndex > idx;
              const isCurrent = currentStepIndex === idx;

              return (
                <div key={step.key} className="pipeline-step">
                  <div
                    className={`pipeline-dot${isPassed ? ' is-done' : ''}${isCurrent ? ' is-current' : ''}`}
                  >
                    {isPassed ? <Check size={14} strokeWidth={3} /> : idx + 1}
                  </div>
                  <span className={`pipeline-label${isCurrent ? ' is-current' : ''}${isPassed ? ' is-done' : ''}`}>
                    {step.label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 2. SECURITY IDE: PROJECT EXPLORER + CODE VIEWER (Sections 15, 19, 20) */}
      <div className="card" style={{ padding: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden', border: '1px solid #334155' }}>
        {/* IDE Top Bar */}
        <div style={{ padding: '0.6rem 1rem', background: '#090d16', borderBottom: '1px solid #1e293b', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '0.85rem', fontWeight: 600 }}>
            <Code size={16} color="var(--primary)" />
            <span>Security IDE: Проводник репозитория и просмотр исходного кода</span>
          </div>
          {activeFilePath && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              <span style={{ color: '#38bdf8' }}>{activeFilePath}</span>
              {activeFileLineCount > 0 && <span>({activeFileLineCount} строк)</span>}
            </div>
          )}
        </div>

        {/* IDE Split View */}
        <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', minHeight: '440px', background: '#050811' }}>
          {/* Left: VS Code style File Explorer */}
          <div style={{ borderRight: '1px solid #1e293b', padding: '0.75rem', overflowY: 'auto', maxHeight: '520px', background: '#0b0f19' }}>
            <div style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.5rem', letterSpacing: '0.5px' }}>
              Файлы проекта ({metadata.filesCount})
            </div>
            {fileTree.length === 0 ? (
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', padding: '1rem 0' }}>
                Индексация структуры репозитория...
              </div>
            ) : (
              renderTree(fileTree)
            )}
          </div>

          {/* Right: Code Viewer */}
          <div ref={codeViewerRef} style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#030712' }}>
            {/* Active file tabs */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.4rem 1rem', background: '#0b0f19', borderBottom: '1px solid #1e293b', fontSize: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <FileCode size={14} color="#60a5fa" />
                <span style={{ color: 'white', fontWeight: 500 }}>{activeFilePath || 'Выберите файл для инспекции'}</span>
              </div>
              {targetHighlightLine && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#f87171', fontSize: '0.75rem' }}>
                  <AlertTriangle size={13} />
                  <span>Уязвимость в строке {targetHighlightLine}</span>
                </div>
              )}
            </div>

            {/* Code lines container */}
            <div style={{ flex: 1, overflowY: 'auto', overflowX: 'auto', maxHeight: '480px', padding: '0.75rem 0', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace', fontSize: '0.8rem', lineHeight: '1.5' }}>
              {fileLoading ? (
                <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Загрузка кода из изолированного окружения...
                </div>
              ) : !activeFileContent ? (
                <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.75rem' }}>
                  <Code size={32} style={{ opacity: 0.3 }} />
                  <div>Выберите файл в проводнике слева или кликните по уязвимости в таблице</div>
                </div>
              ) : (
                activeFileContent.split(/\r?\n/).map((line, idx) => {
                  const lineNum = idx + 1;
                  const isHighlighted = targetHighlightLine === lineNum;

                  return (
                    <div
                      key={idx}
                      id={`code-line-${lineNum}`}
                      style={{
                        display: 'flex',
                        padding: '1px 0',
                        background: isHighlighted ? 'rgba(239, 68, 68, 0.25)' : 'transparent',
                        borderLeft: isHighlighted ? '3px solid #ef4444' : '3px solid transparent',
                      }}
                    >
                      <span
                        style={{
                          width: '45px',
                          textAlign: 'right',
                          paddingRight: '1rem',
                          color: isHighlighted ? '#fca5a5' : '#475569',
                          userSelect: 'none',
                          fontWeight: isHighlighted ? 700 : 400
                        }}
                      >
                        {lineNum}
                      </span>
                      <span style={{ color: isHighlighted ? '#ffffff' : '#cbd5e1', whiteSpace: 'pre', flex: 1, paddingRight: '1rem' }}>
                        {line || ' '}
                      </span>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </div>

      {/* 3. РЕЗУЛЬТАТЫ ПРОВЕРОК БЕЗОПАСНОСТИ */}
      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding: '1.1rem 1.5rem', borderBottom: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
              <FileCode size={18} color="var(--primary)" />
              <h3 style={{ margin: 0, fontSize: '1.05rem' }}>Результаты проверок безопасности</h3>
              <span className="badge" style={{ background: 'var(--bg-dark)', border: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                {findings.length}
              </span>
            </div>

            {findings.length > 0 && (
              <div style={{ position: 'relative', minWidth: '240px', flex: '0 1 320px' }}>
                <Search size={15} style={{ position: 'absolute', left: '0.7rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input
                  value={findingQuery}
                  onChange={e => setFindingQuery(e.target.value)}
                  placeholder="Поиск по названию, файлу или правилу..."
                  style={{
                    width: '100%', padding: '0.5rem 0.75rem 0.5rem 2.1rem',
                    background: 'var(--bg-dark)', border: '1px solid var(--border-color)',
                    borderRadius: 'var(--radius-sm)', color: 'white', outline: 'none', fontSize: '0.8rem',
                  }}
                />
              </div>
            )}
          </div>

          {/* Фильтр по критичности: счётчики сразу показывают, где смотреть. */}
          {findings.length > 0 && (
            <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
              {[
                { key: 'ALL', label: 'Все', count: findings.length, color: '#94a3b8' },
                { key: 'CRITICAL', label: 'Critical', count: criticalCount, color: '#f87171' },
                { key: 'HIGH', label: 'High', count: highCount, color: '#fb923c' },
                { key: 'MEDIUM', label: 'Medium', count: mediumCount, color: '#fbbf24' },
                { key: 'LOW', label: 'Low', count: lowCount, color: '#60a5fa' },
                ...(infoCount > 0 ? [{ key: 'INFO', label: 'Info', count: infoCount, color: '#94a3b8' }] : []),
              ].map(chip => {
                const active = severityFilter === chip.key;
                const empty = chip.count === 0 && chip.key !== 'ALL';
                return (
                  <button
                    key={chip.key}
                    onClick={() => setSeverityFilter(chip.key)}
                    disabled={empty}
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
                      padding: '0.32rem 0.7rem', borderRadius: '999px',
                      fontSize: '0.75rem', fontWeight: 600, cursor: empty ? 'default' : 'pointer',
                      background: active ? `${chip.color}22` : 'var(--bg-dark)',
                      border: `1px solid ${active ? chip.color : 'var(--border-color)'}`,
                      color: empty ? '#475569' : active ? chip.color : 'var(--text-muted)',
                      opacity: empty ? 0.5 : 1,
                      transition: 'all 0.15s ease',
                    }}
                  >
                    {chip.label}
                    <span style={{ fontSize: '0.7rem', opacity: 0.85 }}>{chip.count}</span>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {findings.length === 0 ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            {isCompleted ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
                <CheckCircle size={30} color="var(--accent)" />
                <div style={{ fontWeight: 600, color: 'white', fontSize: '1.05rem' }}>
                  No supported vulnerabilities detected
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  ✓ Semgrep completed &bull; ✓ Gitleaks completed &bull; ✓ Trivy completed
                </div>
                <div style={{ fontSize: '0.75rem', color: '#64748b', maxWidth: '420px', margin: '0 auto' }}>
                  Проверки безопасности не выявили поддерживаемых уязвимостей в проанализированном репозитории.
                </div>
              </div>
            ) : (
              'Ожидание результатов сканирования...'
            )}
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-color)', background: 'var(--bg-dark)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '0.75rem 1.25rem' }}>Уязвимость</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Критичность</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Файл / Строка</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Сканер</th>
                  <th style={{ padding: '0.75rem 1.25rem', textAlign: 'right' }}>Действия</th>
                </tr>
              </thead>
              <tbody>
                {visibleFindings.map((f) => {
                  const isExpanded = selectedFinding?.id === f.id;
                  const aiExplanation = aiExplanations[f.id];
                  const isExplaining = explainingId === f.id;
                  const triage = verdictByFinding.get(f.id);
                  const verdictMeta = triage?.metadata?.verdict ? VERDICT_META[triage.metadata.verdict] : null;

                  return (
                    <React.Fragment key={f.id}>
                      <tr
                        style={{
                          borderBottom: '1px solid var(--border-color)',
                          cursor: 'pointer',
                          background: isExpanded ? 'rgba(99, 102, 241, 0.08)' : 'transparent',
                        }}
                        onClick={() => setSelectedFinding(isExpanded ? null : f)}
                      >
                        <td style={{ padding: '0.9rem 1.25rem', fontWeight: 600, color: 'white' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                            <span>{f.title}</span>
                            {/* Вердикт AI виден сразу в списке: он определяет, стоит ли
                                вообще открывать находку. */}
                            {verdictMeta && (
                              <span
                                title={triage?.metadata?.reason || undefined}
                                style={{
                                  display: 'inline-flex', alignItems: 'center', gap: '4px',
                                  padding: '0.1rem 0.45rem', borderRadius: '999px',
                                  fontSize: '0.65rem', fontWeight: 600, letterSpacing: '0.02em',
                                  background: verdictMeta.bg,
                                  border: `1px solid ${verdictMeta.border}`,
                                  color: verdictMeta.color,
                                }}
                              >
                                <Sparkles size={10} /> {verdictMeta.label}
                              </span>
                            )}
                          </div>
                          {f.description && (
                            <div style={{ fontSize: '0.75rem', fontWeight: 400, color: 'var(--text-muted)', marginTop: '2px' }}>
                              {f.description.slice(0, 100)}{f.description.length > 100 ? '...' : ''}
                            </div>
                          )}
                        </td>
                        <td style={{ padding: '0.9rem 1rem' }}>
                          <span className={`badge badge-${f.severity.toLowerCase()}`}>
                            {f.severity}
                          </span>
                        </td>
                        <td style={{ padding: '0.9rem 1rem', color: '#93c5fd', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                          {f.filePath || 'N/A'}{f.startLine ? `:${f.startLine}` : ''}
                        </td>
                        <td style={{ padding: '0.9rem 1rem' }}>
                          <span className="badge" style={{ background: 'var(--bg-dark)', border: '1px solid var(--border-color)' }}>
                            {f.scanner}
                          </span>
                        </td>
                        <td style={{ padding: '0.9rem 1.25rem', textAlign: 'right' }}>
                          <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end' }}>
                            {f.filePath && (
                              <button
                                className="btn btn-outline"
                                style={{ fontSize: '0.7rem', padding: '0.25rem 0.5rem', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  openFile(f.filePath!, f.startLine || 1);
                                }}
                                title="Перейти к строке в редакторе"
                              >
                                <Code size={12} /> Код
                              </button>
                            )}
                            <button className="btn btn-outline" style={{ fontSize: '0.7rem', padding: '0.25rem 0.5rem' }}>
                              {isExpanded ? 'Скрыть' : 'Детали'}
                            </button>
                          </div>
                        </td>
                      </tr>

                      {/* Expanded Deep Security View (SPEC04 Sections 15, 16, 17, 18, 19) */}
                      {isExpanded && (
                        <tr style={{ background: '#070c18', borderBottom: '1px solid var(--border-color)' }}>
                          <td colSpan={5} style={{ padding: '1.25rem 1.5rem' }}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                              
                              {/* Metadata chips */}
                              <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap', fontSize: '0.75rem' }}>
                                <span>Правило: <code>{f.ruleId || 'security-rule'}</code></span>
                                <span>Уверенность: <code style={{ color: 'var(--accent)' }}>{f.confidence}</code></span>
                                <span>Сканер: <code>{f.scanner}</code></span>
                              </div>

                              {/* Разбор, сделанный агентом во время скана: он уже есть,
                                  и запускать анализ заново ради него не требуется. */}
                              {triage?.metadata && (
                                <div
                                  style={{
                                    border: `1px solid ${verdictMeta?.border || 'var(--border-color)'}`,
                                    background: 'rgba(2, 6, 23, 0.5)',
                                    borderRadius: '8px',
                                    padding: '0.9rem 1rem',
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: '0.7rem',
                                  }}
                                >
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                                    <Sparkles size={14} color="#a5b4fc" />
                                    <strong style={{ fontSize: '0.82rem', color: 'white' }}>Вердикт AI-агента</strong>
                                    {verdictMeta && (
                                      <span
                                        style={{
                                          padding: '0.1rem 0.5rem', borderRadius: '999px', fontSize: '0.68rem',
                                          fontWeight: 600, background: verdictMeta.bg,
                                          border: `1px solid ${verdictMeta.border}`, color: verdictMeta.color,
                                        }}
                                      >
                                        {verdictMeta.label}
                                      </span>
                                    )}
                                    {triage.metadata.confidence && (
                                      <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                                        уверенность: {triage.metadata.confidence}
                                      </span>
                                    )}
                                  </div>

                                  {triage.metadata.reason && (
                                    <div>
                                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '2px' }}>Почему возникает</div>
                                      <div style={{ fontSize: '0.82rem', color: '#e2e8f0' }}>{triage.metadata.reason}</div>
                                    </div>
                                  )}

                                  {triage.metadata.exploitation && (
                                    <div>
                                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '2px' }}>Как эксплуатируется</div>
                                      <div style={{ fontSize: '0.82rem', color: '#e2e8f0' }}>{triage.metadata.exploitation}</div>
                                    </div>
                                  )}

                                  {triage.metadata.recommendation && (
                                    <div>
                                      <div style={{ fontSize: '0.72rem', color: '#86efac', fontWeight: 600, marginBottom: '2px' }}>Что сделать</div>
                                      <div style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>{triage.metadata.recommendation}</div>
                                    </div>
                                  )}
                                </div>
                              )}

                              {/* Consequence — only when the analysis actually produced one. */}
                              {aiExplanation?.consequence && (
                                <div style={{ padding: '0.75rem 1rem', background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.25)', borderRadius: '6px' }}>
                                  <div style={{ fontWeight: 600, color: '#fca5a5', fontSize: '0.8rem', marginBottom: '4px' }}>
                                    ⚠️ Потенциальное последствие (Possible Consequence):
                                  </div>
                                  <div style={{ fontSize: '0.8rem', color: 'var(--text-main)' }}>
                                    {aiExplanation.consequence}
                                  </div>
                                </div>
                              )}

                              {/* Code Snippet with line number (Section 15) */}
                              {f.codeSnippet && (
                                <div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                                    <strong style={{ color: 'white', fontSize: '0.8rem' }}>Фрагмент уязвимого кода (Evidence):</strong>
                                    {f.filePath && (
                                      <button
                                        className="btn btn-outline"
                                        style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem' }}
                                        onClick={() => openFile(f.filePath!, f.startLine || 1)}
                                      >
                                        Открыть {f.filePath}:{f.startLine}
                                      </button>
                                    )}
                                  </div>
                                  <pre style={{
                                    background: '#040711',
                                    padding: '0.75rem 1rem',
                                    borderRadius: '6px',
                                    overflowX: 'auto',
                                    fontSize: '0.78rem',
                                    color: '#38bdf8',
                                    border: '1px solid #1e293b',
                                    lineHeight: '1.4'
                                  }}>
                                    {f.codeSnippet}
                                  </pre>
                                </div>
                              )}

                              {/* SPEC04 Sections 18 & 19: AI Investigation & Concrete Before/After Fix */}
                              <div className="card" style={{ padding: '1rem', background: '#090e1a', border: '1px solid #1e293b' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                    <span style={{ color: 'var(--primary)' }}>✦</span>
                                    <strong style={{ fontSize: '0.85rem', color: 'white' }}>AI Расследование и Рекомендация (Qwen AI)</strong>
                                  </div>
                                  {!aiExplanation && (
                                    <button
                                      className="btn btn-primary"
                                      style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}
                                      disabled={isExplaining}
                                      onClick={() => fetchFindingExplanation(f.id)}
                                    >
                                      {isExplaining ? 'Анализ нейросетью...' : '✦ Запустить глубокий AI разбор'}
                                    </button>
                                  )}
                                </div>

                                {aiExplanation ? (
                                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                                    <div>
                                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '2px' }}>Почему возникает проблема:</div>
                                      <div style={{ fontSize: '0.82rem', color: '#e2e8f0' }}>{aiExplanation.reason}</div>
                                    </div>

                                    {aiExplanation.relatedFiles && aiExplanation.relatedFiles.length > 0 && (
                                      <div>
                                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '4px' }}>Связанные файлы:</div>
                                        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                                          {aiExplanation.relatedFiles.map((rf: string) => (
                                            <button
                                              key={rf}
                                              className="badge"
                                              style={{ background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.3)', cursor: 'pointer' }}
                                              onClick={() => openFile(rf)}
                                            >
                                              {rf}
                                            </button>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {aiExplanation.unavailableReason && (
                                      <div style={{
                                        fontSize: '0.78rem', color: '#fcd34d',
                                        background: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.3)',
                                        borderRadius: '4px', padding: '0.5rem 0.75rem',
                                      }}>
                                        {aiExplanation.unavailableReason}
                                      </div>
                                    )}

                                    {aiExplanation.recommendedFix && (
                                      <div>
                                        <div style={{ fontSize: '0.75rem', color: '#86efac', fontWeight: 600, marginBottom: '2px' }}>
                                          Рекомендованное исправление (Recommended Fix):
                                        </div>
                                        <div style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>{aiExplanation.recommendedFix}</div>
                                      </div>
                                    )}

                                    {/* Before / After — rendered only when the model returned a real fix. */}
                                    {aiExplanation.afterCode && (
                                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '0.75rem', marginTop: '0.25rem' }}>
                                      <div>
                                        <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#f87171', marginBottom: '3px' }}>
                                          Before (Уязвимый код):
                                        </div>
                                        <pre style={{ background: '#030712', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '4px', padding: '0.6rem', fontSize: '0.75rem', color: '#fca5a5', overflowX: 'auto', margin: 0 }}>
                                          {aiExplanation.beforeCode}
                                        </pre>
                                      </div>
                                      <div>
                                        <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#4ade80', marginBottom: '3px' }}>
                                          After (Исправленный код):
                                        </div>
                                        <pre style={{ background: '#030712', border: '1px solid rgba(34, 197, 94, 0.3)', borderRadius: '4px', padding: '0.6rem', fontSize: '0.75rem', color: '#86efac', overflowX: 'auto', margin: 0 }}>
                                          {aiExplanation.afterCode}
                                        </pre>
                                      </div>
                                    </div>
                                    )}

                                    <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.25rem' }}>
                                      {f.filePath && (
                                        <button
                                          className="btn btn-outline"
                                          style={{ fontSize: '0.72rem', padding: '0.3rem 0.6rem' }}
                                          onClick={() => openFile(f.filePath!, f.startLine || 1)}
                                        >
                                          Открыть код в редакторе
                                        </button>
                                      )}
                                    </div>
                                  </div>
                                ) : (
                                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                                    {f.title.toLowerCase().includes('sql')
                                      ? 'Используйте параметризованные запросы (prepared statements) или ORM вместо динамической конкатенации строк SQL.'
                                      : f.title.toLowerCase().includes('command')
                                      ? 'Избегайте вызовов shell/exec с непроверенными входными данными. Используйте функции с фиксированным списком аргументов.'
                                      : 'Нажмите «Запустить глубокий AI разбор» для генерации детального отчета с примерами Before / After кода от Qwen.'}
                                  </div>
                                )}
                              </div>

                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>

            {/* Список ограничен, чтобы страница оставалась обозримой; остальное — по кнопке. */}
            {filteredFindings.length > visibleFindings.length && (
              <div style={{ padding: '1.1rem 1.5rem', borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'center' }}>
                <button
                  className="btn btn-outline"
                  onClick={() => setVisibleCount(c => c + FINDINGS_PAGE_SIZE)}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem' }}
                >
                  <ChevronDown size={15} />
                  Подробнее — показать ещё {Math.min(FINDINGS_PAGE_SIZE, filteredFindings.length - visibleFindings.length)}
                  <span style={{ color: 'var(--text-muted)' }}>
                    (показано {visibleFindings.length} из {filteredFindings.length})
                  </span>
                </button>
              </div>
            )}

            {filteredFindings.length === 0 && (
              <div style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                По выбранному фильтру уязвимости не найдены
              </div>
            )}
          </div>
        )}
      </div>

      {/* 4. GRAPH B: ГРАФ ВЕКТОРОВ АТАК */}
      <div className="card" style={{ padding: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ padding: '1rem 1.35rem', borderBottom: '1px solid var(--border-color)', background: 'linear-gradient(180deg, rgba(239, 68, 68, 0.06), transparent)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', flexWrap: 'wrap' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
                <Crosshair size={18} color="var(--danger)" />
                <h3 style={{ margin: 0, fontSize: '1.05rem' }}>Граф векторов атак и безопасности</h3>
                <span className="badge badge-critical" style={{ fontSize: '0.68rem' }}>Graph B</span>
              </div>
              <p style={{ margin: '0.3rem 0 0 0', fontSize: '0.78rem', color: 'var(--text-muted)', maxWidth: '68ch' }}>
                Цепочка эксплуатации: откуда приходят данные, где срабатывает уязвимость и к чему это приводит.
                Клик по узлу открывает соответствующий файл в редакторе выше.
              </p>
            </div>

            {secNodes.length > 0 && (
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                <GraphStat value={secChainCount} label="цепочек атак" tone="#f87171" />
                <GraphStat value={secNodes.length} label="узлов" />
                <GraphStat value={secEdges.length} label="связей" />
              </div>
            )}
          </div>

          {/* Легенда ролей: без неё цвета узлов ничего не сообщают. */}
          {secNodes.length > 0 && (
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.85rem', alignItems: 'center' }}>
              {['SOURCE', 'WEAKNESS', 'SINK', 'IMPACT'].map(key => {
                const role = GRAPH_ROLES[key];
                const present = secNodes.some((n: any) => n.data?.rawNode?.type === key);
                if (!present) return null;
                return (
                  <span
                    key={key}
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
                      fontSize: '0.72rem', padding: '0.22rem 0.6rem', borderRadius: '999px',
                      background: role.bg, border: `1px solid ${role.border}`, color: role.color,
                    }}
                  >
                    <span>{role.icon}</span> {role.caption}
                  </span>
                );
              })}
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: '0.25rem' }}>
                сплошная линия — подтверждено, пунктир — вероятно
              </span>
            </div>
          )}
        </div>

        <div style={{ height: '520px', background: '#070b14' }}>
          {secNodes.length === 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', gap: '0.75rem' }}>
              {isCompleted ? (
                <>
                  <ShieldCheck size={34} color="var(--accent)" />
                  <div style={{ fontWeight: 600, color: 'white', fontSize: '1rem' }}>
                    Векторы атак не обнаружены
                  </div>
                  <div style={{ fontSize: '0.8rem', maxWidth: '480px', textAlign: 'center' }}>
                    Связей между входными данными и уязвимыми участками кода не найдено.
                  </div>
                </>
              ) : (
                'Формирование графа векторов атак на основе находок...'
              )}
            </div>
          ) : (
            <ReactFlow
              nodes={secNodes}
              edges={secEdges}
              onNodesChange={onSecNodesChange}
              onEdgesChange={onSecEdgesChange}
              onNodeClick={(_, node) => {
                const raw: any = node.data?.rawNode;
                if (raw?.filePath) openFile(raw.filePath, raw.line || 1);
              }}
              minZoom={0.2}
              fitView
              fitViewOptions={{ padding: 0.18 }}
              proOptions={{ hideAttribution: true }}
            >
              <Controls />
              <MiniMap nodeStrokeColor="#475569" nodeColor="#1e293b" maskColor="rgba(0,0,0,0.65)" pannable zoomable />
              <Background color="#1e293b" gap={18} />
            </ReactFlow>
          )}
        </div>
      </div>

      {/* 5. ЗАКЛЮЧЕНИЕ AI-АГЕНТА */}
      {latestAiAnalysis && (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div
            style={{
              padding: '1rem 1.35rem',
              borderBottom: '1px solid var(--border-color)',
              background: 'linear-gradient(180deg, rgba(99, 102, 241, 0.09), transparent)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: '1rem',
              flexWrap: 'wrap',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <div
                style={{
                  width: '32px', height: '32px', borderRadius: '9px',
                  background: 'rgba(99, 102, 241, 0.16)', border: '1px solid rgba(99, 102, 241, 0.4)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                }}
              >
                <Sparkles size={16} color="#a5b4fc" />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.05rem' }}>AI Security Agent: заключение расследования</h3>
                <p style={{ margin: '0.15rem 0 0 0', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Сводка по результатам всех проверок и приоритет исправлений
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', flexWrap: 'wrap' }}>
              {aiTriageCount > 0 && (
                <span className="badge" style={{ background: 'var(--bg-dark)', border: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                  проверено находок: {aiTriageCount}
                </span>
              )}
              {latestAiModel && (
                <span className="badge" style={{ background: 'rgba(99, 102, 241, 0.12)', border: '1px solid rgba(99, 102, 241, 0.3)', color: '#a5b4fc', fontSize: '0.7rem' }}>
                  {latestAiModel}
                </span>
              )}
            </div>
          </div>

          <div style={{ padding: '1.35rem' }}>
            <MarkdownView>{latestAiAnalysis}</MarkdownView>
          </div>
        </div>
      )}

      {/* 6. ФУНКЦИИ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ */}
      <SecurityControlsPanel scanId={id} scanStatus={scan?.status} onOpenFile={openFile} />

      {/* 7. GRAPH A: АРХИТЕКТУРНЫЙ ГРАФ ПРОЕКТА (в самом низу страницы) */}
      <div className="card" style={{ padding: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ padding: '1rem 1.35rem', borderBottom: '1px solid var(--border-color)', background: 'linear-gradient(180deg, rgba(168, 85, 247, 0.07), transparent)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', flexWrap: 'wrap' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
                <Layers size={18} color="#a855f7" />
                <h3 style={{ margin: 0, fontSize: '1.05rem' }}>Архитектурный граф проекта</h3>
                <span className="badge" style={{ background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', fontSize: '0.68rem' }}>
                  Graph A
                </span>
              </div>
              <p style={{ margin: '0.3rem 0 0 0', fontSize: '0.78rem', color: 'var(--text-muted)', maxWidth: '68ch' }}>
                Структура проекта по слоям: точки входа, бизнес-логика, модели и внешние зависимости.
                Клик по узлу открывает исходный файл в редакторе выше.
              </p>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <GraphStat value={archNodes.length} label="компонентов" tone="#c084fc" />
              <GraphStat value={archEdges.length} label="связей" />
            </div>
          </div>

          {/* Легенда слоёв и быстрый фильтр: 50+ узлов иначе не разобрать. */}
          {archNodes.length > 0 && (
            <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginTop: '0.85rem' }}>
              <button
                onClick={() => setArchFilter('ALL')}
                style={{
                  fontSize: '0.72rem', padding: '0.25rem 0.65rem', borderRadius: '999px', cursor: 'pointer',
                  background: archFilter === 'ALL' ? 'rgba(148, 163, 184, 0.2)' : 'var(--bg-dark)',
                  border: `1px solid ${archFilter === 'ALL' ? '#94a3b8' : 'var(--border-color)'}`,
                  color: archFilter === 'ALL' ? '#e2e8f0' : 'var(--text-muted)',
                }}
              >
                Все · {archNodes.length}
              </button>

              {Object.entries(ARCH_TYPES)
                .filter(([key]) => archTypeCounts[key] > 0)
                .sort((a, b) => a[1].layer - b[1].layer)
                .map(([key, meta]) => {
                  const active = archFilter === key;
                  return (
                    <button
                      key={key}
                      onClick={() => setArchFilter(active ? 'ALL' : key)}
                      style={{
                        display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
                        fontSize: '0.72rem', padding: '0.25rem 0.65rem', borderRadius: '999px', cursor: 'pointer',
                        background: active ? meta.bg : 'var(--bg-dark)',
                        border: `1px solid ${active ? meta.border : 'var(--border-color)'}`,
                        color: active ? meta.color : 'var(--text-muted)',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <span>{meta.icon}</span> {meta.label} · {archTypeCounts[key]}
                    </button>
                  );
                })}
            </div>
          )}
        </div>

        <div style={{ height: '560px', background: '#070b14' }}>
          {archNodes.length === 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              Извлечение компонентов и архитектуры репозитория...
            </div>
          ) : (
            <ReactFlow
              nodes={visibleArchNodes}
              edges={visibleArchEdges}
              onNodesChange={onArchNodesChange}
              onEdgesChange={onArchEdgesChange}
              onNodeClick={(_, node) => {
                const rawNode: any = node.data?.rawNode;
                if (rawNode?.filePath) openFile(rawNode.filePath, rawNode.line || 1);
              }}
              minZoom={0.15}
              fitView
              fitViewOptions={{ padding: 0.15 }}
              proOptions={{ hideAttribution: true }}
            >
              <Controls />
              <MiniMap nodeStrokeColor="#475569" nodeColor="#1e293b" maskColor="rgba(0,0,0,0.65)" pannable zoomable />
              <Background color="#1e293b" gap={18} />
            </ReactFlow>
          )}
        </div>
      </div>

    </div>
  );
};

/** Компактный счётчик в шапке графа. */
const GraphStat = ({ value, label, tone }: { value: number; label: string; tone?: string }) => (
  <div
    style={{
      padding: '0.35rem 0.75rem',
      borderRadius: 'var(--radius-sm)',
      background: 'var(--bg-dark)',
      border: '1px solid var(--border-color)',
      textAlign: 'center',
      minWidth: '72px',
    }}
  >
    <div style={{ fontSize: '1rem', fontWeight: 700, color: tone || 'white', lineHeight: 1.2 }}>{value}</div>
    <div style={{ fontSize: '0.63rem', color: 'var(--text-muted)' }}>{label}</div>
  </div>
);

export default ScanDetails;
