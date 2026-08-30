import { useState } from 'react';
import { X, Copy, CheckCircle2, ShieldCheck } from 'lucide-react';
import { apiClient } from '../api/client';

export default function RemediationView({ remediation, scanId, onClose, onVerified }) {
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleVerify = async () => {
    setLoading(true);
    try {
      const result = await apiClient.verifyFix(scanId, remediation.remediation_commands);
      onVerified(result);
    } catch (err) {
      alert('Verification failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(remediation.remediation_commands);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer" style={{ maxWidth: '800px' }} onClick={e => e.stopPropagation()}>
        <div className="drawer-header">
          <div className="drawer-title-group">
            <span className="badge" style={{ backgroundColor: 'var(--success-bg)', color: 'var(--success)', border: '1px solid var(--success)' }}>
              Remediation
            </span>
            <div className="drawer-title">{remediation.title}</div>
            <div className="drawer-meta">
              <span>{remediation.rule_id}</span>
              <span className="dot-separator" />
              <span>{remediation.device_hostname}</span>
              <span className="dot-separator" />
              <span>{remediation.vendor}</span>
            </div>
          </div>
          <button className="btn-ghost" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="drawer-content">
          <div className="remediation-grid">
            <div>
              <div className="drawer-section-title">Original Configuration</div>
              <div className="config-block">
                <div className="config-header">
                  <span>current</span>
                </div>
                <div className="config-body">
                  {remediation.original_lines.map((line, i) => (
                    <div key={i} className="config-line highlight">
                      <span className="line-num">{i + 1}</span>
                      <span>{line}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div>
              <div className="drawer-section-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                <span>Proposed Fix</span>
                <button className="btn-ghost" style={{ padding: 0, fontSize: '0.6875rem' }} onClick={handleCopy}>
                  {copied ? <CheckCircle2 size={12} style={{ marginRight: 4 }}/> : <Copy size={12} style={{ marginRight: 4 }}/>}
                  {copied ? 'COPIED' : 'COPY'}
                </button>
              </div>
              <div className="config-block">
                <div className="config-header">
                  <span style={{ color: 'var(--success)' }}>remediation commands</span>
                </div>
                <div className="config-body">
                  {remediation.remediation_commands.split('\n').map((line, i) => (
                    <div key={i} className="config-line fix-highlight">
                      <span className="line-num">{i + 1}</span>
                      <span>{line}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div>
            <div className="drawer-section-title">Why This Fix</div>
            <div className="drawer-text">{remediation.explanation}</div>
          </div>
        </div>

        <div className="drawer-footer" style={{ display: 'flex', gap: '1rem' }}>
          <button
            className="btn-secondary"
            onClick={handleCopy}
            style={{ flex: 1, justifyContent: 'center' }}
          >
            <Copy size={14} />
            Copy Fix
          </button>
          <button
            className="btn-primary"
            onClick={handleVerify}
            disabled={loading}
            style={{ flex: 1, justifyContent: 'center', backgroundColor: 'var(--text-primary)', color: 'var(--bg-dark)' }}
          >
            {loading ? 'Verifying...' : (
              <>
                <ShieldCheck size={14} />
                Verify Fix
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
