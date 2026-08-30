import { useState } from 'react';
import { X, Wrench, Shield, Server, FileText } from 'lucide-react';
import { apiClient } from '../api/client';

export default function FindingDetail({ finding, scanId, onClose, onRemediation }) {
  const [loading, setLoading] = useState(false);

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

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-group">
            <span className={`badge ${finding.severity}`}>{finding.severity}</span>
            <h2>{finding.title}</h2>
            <div className="finding-meta">
              <Shield size={12} /> {finding.rule_id}
              <span className="dot-separator" />
              <Server size={12} /> {finding.device_hostname}
              <span className="dot-separator" />
              {finding.vendor}
            </div>
          </div>
          <button className="close-btn" onClick={onClose}>
            <X size={20} />
          </button>
        </div>

        <div className="modal-body">
          <div className="section">
            <h3>Description</h3>
            <p>{finding.description}</p>
          </div>

          <div className="section">
            <h3>Security Impact</h3>
            <p>{finding.security_impact}</p>
          </div>

          {finding.evidence_lines && finding.evidence_lines.length > 0 && (
            <div className="section">
              <h3>Configuration Evidence</h3>
              <div className="code-container">
                <div className="code-header">
                  <FileText size={12} style={{ display: 'inline', marginRight: '4px' }}/>
                  configuration snippet
                </div>
                <div className="code-block">
                  {finding.evidence_lines.map((line, i) => (
                    <div key={i} className="code-line highlight">
                      {finding.line_numbers && finding.line_numbers[i] ? (
                        <span className="line-number">
                          {String(finding.line_numbers[i])}
                        </span>
                      ) : (
                        <span className="line-number">{i + 1}</span>
                      )}
                      {line}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {finding.compliance && finding.compliance.length > 0 && (
            <div className="section">
              <h3>Compliance</h3>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                {finding.compliance.map((c, i) => (
                  <span key={i} className="badge" style={{
                    backgroundColor: 'var(--surface-hover)',
                    color: 'var(--text-primary)',
                    border: '1px solid var(--border)',
                  }}>
                    {c.framework} {c.control_id}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="section">
            <h3>Recommendation</h3>
            <p>{finding.recommendation}</p>
          </div>

          <div style={{ marginTop: 'auto', paddingTop: '2rem' }}>
            <button
              className="btn-primary"
              onClick={handleGenerateFix}
              disabled={loading}
              style={{ width: '100%', justifyContent: 'center', padding: '0.75rem', fontSize: '0.875rem' }}
            >
              {loading ? (
                <>⏳ Generating Fix...</>
              ) : (
                <>
                  <Wrench size={16} />
                  Generate Remediation
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
