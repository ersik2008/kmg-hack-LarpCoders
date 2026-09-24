import { useState } from 'react';
import { Download, ShieldCheck, Loader2, ExternalLink } from 'lucide-react';

/**
 * Выгрузка отчёта в SARIF — формате, который понимают все инструменты анализа
 * кода, и который GitHub принимает в Code Scanning.
 *
 * Две кнопки решают разные задачи: скачать файл (для внешних систем и для
 * приложения к отчёту) и опубликовать находки во вкладку Security репозитория,
 * где GitHub сам разметит их по строкам и будет вести их историю.
 */

interface UploadResult {
  uploaded: boolean;
  error?: string;
  repository?: string;
  commitSha?: string;
  securityTabUrl?: string;
}

const SarifExport = ({ scanId, disabled }: { scanId?: string; disabled?: boolean }) => {
  const [downloading, setDownloading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<UploadResult | null>(null);

  const token = () => localStorage.getItem('kmg_token') || '';

  const download = async () => {
    if (!scanId) return;
    setDownloading(true);
    try {
      const res = await fetch(`http://localhost:3000/api/scans/${scanId}/sarif`, {
        headers: { Authorization: `Bearer ${token()}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `kmg-scan-${scanId}.sarif`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setResult({ uploaded: false, error: `Не удалось скачать SARIF: ${err.message}` });
    } finally {
      setDownloading(false);
    }
  };

  const upload = async () => {
    if (!scanId) return;
    setUploading(true);
    setResult(null);
    try {
      const res = await fetch(`http://localhost:3000/api/scans/${scanId}/sarif/upload`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token()}` },
      });
      setResult(await res.json());
    } catch (err: any) {
      setResult({ uploaded: false, error: err.message });
    } finally {
      setUploading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', alignItems: 'flex-end' }}>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button
          onClick={download}
          disabled={disabled || downloading}
          className="btn btn-outline scan-refresh-btn"
          title="Скачать отчёт в формате SARIF 2.1.0"
          style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
        >
          {downloading ? <Loader2 size={14} /> : <Download size={14} />} SARIF
        </button>

        <button
          onClick={upload}
          disabled={disabled || uploading}
          className="btn btn-outline scan-refresh-btn"
          title="Опубликовать находки во вкладке Security репозитория GitHub"
          style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
        >
          {uploading ? <Loader2 size={14} /> : <ShieldCheck size={14} />}
          {uploading ? 'Выгрузка...' : 'В GitHub Security'}
        </button>
      </div>

      {result && (
        <div
          style={{
            fontSize: '0.72rem',
            maxWidth: '320px',
            textAlign: 'right',
            padding: '0.45rem 0.7rem',
            borderRadius: '6px',
            background: result.uploaded ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
            border: `1px solid ${result.uploaded ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
            color: result.uploaded ? '#86efac' : '#fca5a5',
          }}
        >
          {result.uploaded ? (
            <span>
              Находки опубликованы в GitHub.{' '}
              {result.securityTabUrl && (
                <a
                  href={result.securityTabUrl}
                  target="_blank"
                  rel="noreferrer"
                  style={{ color: '#86efac', display: 'inline-flex', alignItems: 'center', gap: '3px' }}
                >
                  Открыть <ExternalLink size={11} />
                </a>
              )}
            </span>
          ) : (
            result.error
          )}
        </div>
      )}
    </div>
  );
};

export default SarifExport;
