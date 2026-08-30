import { useState } from 'react';
import { X, CheckCircle, FileText, Code } from 'lucide-react';
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
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-group">
            <span className="badge" style={{
              backgroundColor: 'var(--success-bg)',
              color: 'var(--success)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
            }}>remediation</span>
            <h2>{remediation.title}</h2>
            <div className="finding-meta">
              {remediation.rule_id}
              <span className="dot-separator" />
              {remediation.device_hostname}
              <span className="dot-separator" />
              {remediation.vendor}
            </div>
          </div>
          <button className="close-btn" onClick={onClose}>
            <X size={20} />
          </button>
        </div>

        <div className="modal-body">
          <div className="section">
            <h3>Original Configuration</h3>
            <div className="code-container">
              <div className="code-header">
                <FileText size={12} style={{ display: 'inline', marginRight: '4px' }}/>
                current config
              </div>
              <div className="code-block">
                {remediation.original_lines.map((line, i) => (
                  <div key={i} className="code-line highlight">
                    <span className="line-number">{i + 1}</span>
                    {line}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="section">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '0.75rem' }}>
              <h3 style={{ margin: 0 }}>Proposed Fix</h3>
              <button 
                onClick={handleCopy}
                style={{ fontSize: '0.75rem', color: 'var(--accent)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
              >
                {copied ? <CheckCircle size={12} /> : <Code size={12} />}
                {copied ? 'Copied' : 'Copy Fix'}
              </button>
            </div>
            <div className="code-container">
              <div className="code-header" style={{ borderBottomColor: 'rgba(16, 185, 129, 0.3)' }}>
                <Code size={12} style={{ display: 'inline', marginRight: '4px' }}/>
                remediation commands
              </div>
              <div className="code-block fix">
                {remediation.remediation_commands.split('\n').map((line, i) => (
                  <div key={i} className="code-line highlight">
                    <span className="line-number">{i + 1}</span>
                    {line}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="section">
            <h3>Explanation</h3>
            <p>{remediation.explanation}</p>
          </div>

          <div style={{ marginTop: 'auto', paddingTop: '2rem' }}>
            <button
              className="btn-primary"
              onClick={handleVerify}
              disabled={loading}
              style={{
                width: '100%',
                justifyContent: 'center',
                padding: '0.75rem',
                fontSize: '0.875rem',
                backgroundColor: 'var(--success)',
              }}
            >
              {loading ? (
                <>⏳ Verifying...</>
              ) : (
                <>
                  <CheckCircle size={16} />
                  Verify Fix / Re-analyze
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
