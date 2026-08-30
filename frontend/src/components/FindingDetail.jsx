import { useState } from 'react';
import { X, Copy, CheckCircle2 } from 'lucide-react';
import { apiClient } from '../api/client';

export default function FindingDetail({ finding, scanId, onClose, onRemediation }) {
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleGenerateFix = async () => {
    setLoading(true);
    try {
      const remediation = await apiClient.getRemediation(
        scanId, finding.rule_id, finding.device_hostname
      );
      onRemediation(remediation);
    } catch (err) {
      alert('Failed to generate fix: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    const text = finding.evidence_lines?.join('\n') || '';
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer" onClick={e => e.stopPropagation()}>
        <div className="drawer-header">
          <div className="drawer-title-group">
            <span className={`badge ${finding.severity}`}>{finding.severity}</span>
            <div className="drawer-title">{finding.title}</div>
            <div className="drawer-meta">
              <span>{finding.rule_id}</span>
              <span className="dot-separator" />
              <span>{finding.device_hostname}</span>
              <span className="dot-separator" />
              <span>{finding.vendor}</span>
            </div>
          </div>
          <button className="btn-ghost" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="drawer-content">
          <div>
            <div className="drawer-section-title">Description</div>
            <div className="drawer-text">{finding.description}</div>
          </div>

          <div>
            <div className="drawer-section-title">Security Impact</div>
            <div className="drawer-text">{finding.security_impact}</div>
          </div>

          {finding.evidence_lines && finding.evidence_lines.length > 0 && (
            <div>
              <div className="drawer-section-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                <span>Configuration Evidence</span>
                <button className="btn-ghost" style={{ padding: 0, fontSize: '0.6875rem' }} onClick={handleCopy}>
                  {copied ? <CheckCircle2 size={12} style={{ marginRight: 4 }}/> : <Copy size={12} style={{ marginRight: 4 }}/>}
                  {copied ? 'COPIED' : 'COPY'}
                </button>
              </div>
              <div className="config-block">
                <div className="config-header">
                  <span>snippet</span>
                </div>
                <div className="config-body">
                  {finding.evidence_lines.map((line, i) => {
                    const lineNum = finding.line_numbers?.[i] || (i + 1);
                    return (
                      <div key={i} className="config-line highlight">
                        <span className="line-num">{lineNum}</span>
                        <span>{line}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {finding.compliance && finding.compliance.length > 0 && (
            <div>
              <div className="drawer-section-title">Compliance</div>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                {finding.compliance.map((c, i) => (
                  <span key={i} className="badge neutral">
                    {c.framework} {c.control_id}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div>
            <div className="drawer-section-title">Recommendation</div>
            <div className="drawer-text">{finding.recommendation}</div>
          </div>
        </div>

        <div className="drawer-footer">
          <button
            className="btn-primary"
            onClick={handleGenerateFix}
            disabled={loading}
            style={{ width: '100%', justifyContent: 'center' }}
          >
            {loading ? 'Generating Fix...' : 'Generate Remediation'}
          </button>
        </div>
      </div>
    </div>
  );
}
