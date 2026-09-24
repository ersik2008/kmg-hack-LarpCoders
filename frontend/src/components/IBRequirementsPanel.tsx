import { useEffect, useState } from "react";
import { ShieldCheck, ShieldAlert, AlertTriangle, MinusCircle, ChevronDown, ChevronUp, FileCode } from "lucide-react";

type RequirementStatus = "PASS" | "VIOLATION" | "INSUFFICIENT_EVIDENCE" | "NOT_APPLICABLE";

interface RequirementEvidence {
  filePath: string;
  line: number;
  snippet: string;
  note: string;
  kind: "SUPPORTS" | "VIOLATES" | "CONTEXT";
}

interface RequirementViolation {
  filePath: string | null;
  lineStart: number | null;
  lineEnd: number | null;
  symbol: string | null;
  evidence: string;
  explanation: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  recommendation: string;
}

interface RequirementResult {
  requirementId: string;
  title: string;
  requirementText: string;
  status: RequirementStatus;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  summary: string;
  evidence: RequirementEvidence[];
  violations: RequirementViolation[];
  insufficientReason: string | null;
}

const STATUS_META = {
  PASS: { label: "Выполнено", color: "#4ade80", bg: "rgba(34,197,94,0.10)", border: "rgba(34,197,94,0.3)" },
  VIOLATION: { label: "Нарушение", color: "#f87171", bg: "rgba(239,68,68,0.12)", border: "rgba(239,68,68,0.3)" },
  INSUFFICIENT_EVIDENCE: { label: "Недостаточно данных", color: "#fcd34d", bg: "rgba(245,158,11,0.10)", border: "rgba(245,158,11,0.3)" },
  NOT_APPLICABLE: { label: "Неприменимо", color: "#94a3b8", bg: "rgba(148,163,184,0.10)", border: "rgba(148,163,184,0.25)" },
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#f87171", HIGH: "#fb923c", MEDIUM: "#fbbf24", LOW: "#60a5fa",
};

const IBRequirementsPanel = ({
  scanId, scanStatus, onOpenFile,
}: {
  scanId?: string;
  scanStatus?: string;
  onOpenFile?: (filePath: string, line?: number) => void;
}) => {
  const [requirements, setRequirements] = useState<RequirementResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    const load = async () => {
      try {
        const token = localStorage.getItem("kmg_token");
        const res = await fetch(`http://localhost:3000/api/scans/${scanId}/requirements`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (!cancelled) {
          const list = Array.isArray(data) ? data : (data.results || []);
          setRequirements(list);
        }
      } catch { if (!cancelled) setRequirements([]); }
      finally { if (!cancelled) setLoading(false); }
    };
    load();
    return () => { cancelled = true; };
  }, [scanId, scanStatus]);

  if (loading) {
    return (
      <div className="card" style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
        Загрузка требований ИБ...
      </div>
    );
  }

  if (requirements.length === 0) {
    return (
      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding: "1rem 1.5rem", borderBottom: "1px solid var(--border-color)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <ShieldCheck size={18} color="var(--primary)" />
            <h3 style={{ margin: 0, fontSize: "1.05rem" }}>Требования информационной безопасности (ТЗ п.&nbsp;4.5)</h3>
          </div>
          <p style={{ margin: "0.25rem 0 0", fontSize: "0.8rem", color: "var(--text-muted)" }}>
            Соответствие проекта обязательным требованиям ИБ-01&nbsp;—&nbsp;ИБ-08
          </p>
        </div>
        <div style={{ padding: "1.25rem 1.5rem", color: "var(--text-muted)", fontSize: "0.85rem", lineHeight: 1.5 }}>
          Для данного сканирования результаты проверки требований ИБ еще не сформированы или скан был выполнен до их подключения.
          Запустите новое сканирование репозитория, чтобы автоматически проверить соблюдение всех 8 обязательных требований ИБ.
        </div>
      </div>
    );
  }

  const passCount = requirements.filter(r => r.status === "PASS").length;
  const violationCount = requirements.filter(r => r.status === "VIOLATION").length;
  const insufficientCount = requirements.filter(r => r.status === "INSUFFICIENT_EVIDENCE").length;
  const notApplicableCount = requirements.filter(r => r.status === "NOT_APPLICABLE").length;
  const total = requirements.length;

  return (
    <div className="card" style={{ padding: 0 }}>
      <div style={{ padding: "1rem 1.5rem", borderBottom: "1px solid var(--border-color)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <ShieldCheck size={18} color="var(--primary)" />
              <h3 style={{ margin: 0, fontSize: "1.05rem" }}>Требования информационной безопасности (ТЗ п.&nbsp;4.5)</h3>
            </div>
            <p style={{ margin: "0.25rem 0 0", fontSize: "0.8rem", color: "var(--text-muted)" }}>
              Соответствие проекта обязательным требованиям ИБ-01&nbsp;—&nbsp;ИБ-08
            </p>
          </div>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Выполнено</div>
            <div style={{ fontSize: "1.5rem", fontWeight: 700, color: passCount === total ? "var(--accent)" : violationCount > 0 ? "var(--danger)" : "var(--warning)" }}>
              {passCount}/{total}
            </div>
          </div>
        </div>

        <div style={{ marginTop: "0.85rem", height: "6px", borderRadius: "999px", background: "var(--bg-dark)", overflow: "hidden", display: "flex" }}>
          <div style={{ width: `${total ? (passCount / total) * 100 : 0}%`, background: "#22c55e" }} />
          <div style={{ width: `${total ? (violationCount / total) * 100 : 0}%`, background: "#ef4444" }} />
          <div style={{ width: `${total ? (insufficientCount / total) * 100 : 0}%`, background: "#f59e0b" }} />
        </div>

        <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.75rem", flexWrap: "wrap" }}>
          {passCount > 0 && <span style={{ fontSize: "0.72rem", padding: "0.22rem 0.55rem", borderRadius: "999px", background: "rgba(34,197,94,0.1)", color: "#4ade80", border: "1px solid rgba(34,197,94,0.3)" }}>Выполнено: {passCount}</span>}
          {violationCount > 0 && <span style={{ fontSize: "0.72rem", padding: "0.22rem 0.55rem", borderRadius: "999px", background: "rgba(239,68,68,0.1)", color: "#f87171", border: "1px solid rgba(239,68,68,0.3)" }}>Нарушения: {violationCount}</span>}
          {insufficientCount > 0 && <span style={{ fontSize: "0.72rem", padding: "0.22rem 0.55rem", borderRadius: "999px", background: "rgba(245,158,11,0.1)", color: "#fcd34d", border: "1px solid rgba(245,158,11,0.3)" }}>Недостаточно данных: {insufficientCount}</span>}
          {notApplicableCount > 0 && <span style={{ fontSize: "0.72rem", padding: "0.22rem 0.55rem", borderRadius: "999px", background: "rgba(148,163,184,0.1)", color: "#94a3b8", border: "1px solid rgba(148,163,184,0.25)" }}>Неприменимо: {notApplicableCount}</span>}
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column" }}>
        {requirements.map(req => {
          const meta = STATUS_META[req.status] || STATUS_META.INSUFFICIENT_EVIDENCE;
          const isOpen = expanded === req.requirementId;
          const hasViolations = req.violations && req.violations.length > 0;
          const hasEvidence = req.evidence && req.evidence.length > 0;

          return (
            <div key={req.requirementId} style={{ borderBottom: "1px solid var(--border-color)" }}>
              <button
                onClick={() => setExpanded(isOpen ? null : req.requirementId)}
                style={{ width: "100%", background: isOpen ? "rgba(99,102,241,0.04)" : "transparent", border: "none", cursor: "pointer", padding: "0.85rem 1.5rem", display: "flex", alignItems: "center", gap: "0.85rem", textAlign: "left", color: "inherit" }}
              >
                <span style={{ flexShrink: 0, display: "inline-flex", alignItems: "center", gap: "4px", minWidth: "136px", fontSize: "0.7rem", fontWeight: 700, padding: "0.22rem 0.5rem", borderRadius: "5px", background: meta.bg, color: meta.color, border: `1px solid ${meta.border}` }}>
                  {req.status === "PASS" ? <ShieldCheck size={12} /> : req.status === "VIOLATION" ? <ShieldAlert size={12} /> : req.status === "INSUFFICIENT_EVIDENCE" ? <AlertTriangle size={12} /> : <MinusCircle size={12} />}
                  {meta.label}
                </span>
                <span style={{ flexShrink: 0, fontSize: "0.78rem", fontWeight: 700, color: "var(--primary)", minWidth: "52px" }}>{req.requirementId}</span>
                <span style={{ flex: 1, fontSize: "0.88rem", fontWeight: 500 }}>{req.title}</span>
                {hasViolations && <span style={{ fontSize: "0.68rem", color: "#f87171", background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.25)", borderRadius: "4px", padding: "0.15rem 0.4rem", flexShrink: 0 }}>{req.violations.length} нар.</span>}
                {hasEvidence && !hasViolations && <span style={{ fontSize: "0.68rem", color: "var(--text-muted)", flexShrink: 0 }}>{req.evidence.length} подтв.</span>}
                <span style={{ color: "var(--text-muted)", flexShrink: 0 }}>{isOpen ? <ChevronUp size={15} /> : <ChevronDown size={15} />}</span>
              </button>

              {isOpen && (
                <div style={{ padding: "0 1.5rem 1.25rem 1.5rem", display: "flex", flexDirection: "column", gap: "0.9rem" }}>
                  <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", lineHeight: 1.5, padding: "0.55rem 0.8rem", background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-color)", borderRadius: "6px" }}>
                    <strong style={{ color: "#94a3b8" }}>Формулировка:</strong> {req.requirementText}
                  </div>

                  {req.summary && <div style={{ fontSize: "0.84rem", color: "#e2e8f0", lineHeight: 1.55 }}>{req.summary}</div>}

                  {req.insufficientReason && (
                    <div style={{ fontSize: "0.8rem", color: "#fcd34d", padding: "0.5rem 0.75rem", background: "rgba(245,158,11,0.07)", border: "1px solid rgba(245,158,11,0.25)", borderRadius: "5px" }}>
                      <strong>Причина:</strong> {req.insufficientReason}
                    </div>
                  )}

                  {hasViolations && (
                    <div>
                      <div style={{ fontSize: "0.73rem", fontWeight: 700, color: "#f87171", marginBottom: "0.5rem", display: "flex", alignItems: "center", gap: "0.35rem" }}>
                        <ShieldAlert size={13} /> Нарушения ({req.violations.length}):
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
                        {req.violations.map((v, i) => (
                          <div key={i} style={{ background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: "6px", padding: "0.7rem 0.85rem", display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", flexWrap: "wrap" }}>
                              <span style={{ fontSize: "0.65rem", padding: "0.1rem 0.4rem", borderRadius: "4px", background: `${SEVERITY_COLORS[v.severity]}22`, color: SEVERITY_COLORS[v.severity], border: `1px solid ${SEVERITY_COLORS[v.severity]}44`, fontWeight: 700 }}>{v.severity}</span>
                              {v.filePath && (
                                onOpenFile ? (
                                  <button onClick={() => onOpenFile(v.filePath!, v.lineStart ?? undefined)} style={{ background: "none", border: "none", padding: 0, cursor: "pointer", color: "#38bdf8", fontSize: "0.72rem", fontFamily: "monospace", textDecoration: "underline", textDecorationStyle: "dotted", textUnderlineOffset: "2px", display: "inline-flex", alignItems: "center", gap: "3px" }}>
                                    <FileCode size={11} />{v.filePath}{v.lineStart ? `:${v.lineStart}` : ""}
                                  </button>
                                ) : (
                                  <code style={{ fontSize: "0.72rem", color: "#38bdf8" }}>{v.filePath}{v.lineStart ? `:${v.lineStart}` : ""}</code>
                                )
                              )}
                              {v.symbol && <code style={{ fontSize: "0.68rem", color: "#94a3b8" }}>{v.symbol}</code>}
                            </div>
                            <div style={{ fontSize: "0.8rem", color: "#fca5a5" }}>{v.explanation}</div>
                            {v.evidence && (
                              <pre style={{ margin: 0, fontSize: "0.72rem", color: "#94a3b8", background: "#030712", borderRadius: "4px", padding: "0.45rem 0.6rem", overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all", border: "1px solid #1e293b" }}>{v.evidence}</pre>
                            )}
                            {v.recommendation && (
                              <div style={{ fontSize: "0.78rem", color: "#86efac" }}><strong style={{ color: "#4ade80" }}>Что сделать:</strong> {v.recommendation}</div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {hasEvidence && (
                    <div>
                      <div style={{ fontSize: "0.73rem", color: "var(--text-muted)", marginBottom: "0.4rem" }}>Подтверждение из кода:</div>
                      <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                        {req.evidence.slice(0, 4).map((ev, i) => (
                          <div key={i} style={{ background: "#030712", border: "1px solid var(--border-color)", borderRadius: "5px", padding: "0.45rem 0.65rem", fontSize: "0.72rem" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", marginBottom: "3px", flexWrap: "wrap" }}>
                              <span style={{ fontSize: "0.63rem", padding: "0.1rem 0.35rem", borderRadius: "3px", fontWeight: 600, background: ev.kind === "VIOLATES" ? "rgba(239,68,68,0.12)" : ev.kind === "SUPPORTS" ? "rgba(34,197,94,0.1)" : "rgba(148,163,184,0.1)", color: ev.kind === "VIOLATES" ? "#f87171" : ev.kind === "SUPPORTS" ? "#4ade80" : "#94a3b8" }}>
                                {ev.kind === "VIOLATES" ? "Нарушает" : ev.kind === "SUPPORTS" ? "Подтверждает" : "Контекст"}
                              </span>
                              {ev.filePath && (onOpenFile ? (
                                <button onClick={() => onOpenFile(ev.filePath, ev.line)} style={{ background: "none", border: "none", padding: 0, cursor: "pointer", color: "#38bdf8", fontSize: "0.7rem", fontFamily: "monospace", textDecoration: "underline", textDecorationStyle: "dotted", textUnderlineOffset: "2px" }}>
                                  {ev.filePath}{ev.line ? `:${ev.line}` : ""}
                                </button>
                              ) : <code style={{ color: "#38bdf8", fontSize: "0.7rem" }}>{ev.filePath}{ev.line ? `:${ev.line}` : ""}</code>)}
                            </div>
                            {ev.snippet && <pre style={{ margin: 0, color: "#64748b", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{ev.snippet.slice(0, 200)}{ev.snippet.length > 200 ? "…" : ""}</pre>}
                            {ev.note && <div style={{ color: "var(--text-muted)", marginTop: "2px", fontStyle: "italic" }}>{ev.note}</div>}
                          </div>
                        ))}
                        {req.evidence.length > 4 && <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", paddingLeft: "0.4rem" }}>+ ещё {req.evidence.length - 4} доказательств</div>}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default IBRequirementsPanel;
