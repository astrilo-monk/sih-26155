export default function ScoreOverview({ score, critical, high, medium, low }) {
  const getStatus = (s) => {
    if (s < 40) return { label: 'CRITICAL RISK', desc: 'Immediate remediation required.', color: 'var(--critical)' };
    if (s < 70) return { label: 'NEEDS ATTENTION', desc: 'Multiple security vulnerabilities detected.', color: 'var(--high)' };
    if (s < 90) return { label: 'FAIR', desc: 'Minor configuration issues present.', color: 'var(--medium)' };
    return { label: 'GOOD', desc: 'Configuration is largely secure.', color: 'var(--success)' };
  };

  const status = getStatus(score);
  const total = critical + high + medium + low;
  
  // Calculate widths for the severity distribution bar
  const safeTotal = total === 0 ? 1 : total;
  const cWidth = (critical / safeTotal) * 100;
  const hWidth = (high / safeTotal) * 100;
  const mWidth = (medium / safeTotal) * 100;
  const lWidth = (low / safeTotal) * 100;

  return (
    <div className="posture-section">
      <div className="section-header">
        <span>Security Posture</span>
      </div>
      
      <div className="posture-grid">
        <div className="score-display">
          <div className="score-value" style={{ color: status.color }}>
            {score}<span className="max">/100</span>
          </div>
          <div className="score-info">
            <div className="score-status" style={{ color: status.color }}>{status.label}</div>
            <div className="score-desc">{status.desc}</div>
          </div>
        </div>

        <div style={{ paddingTop: '0.5rem' }}>
          {total === 0 ? (
            <div className="severity-breakdown">
              <div className="sev-item">
                <span className="sev-label">Critical</span>
                <span className="sev-count" style={{ color: 'var(--text-tertiary)' }}>0</span>
              </div>
              <div className="sev-item">
                <span className="sev-label">High</span>
                <span className="sev-count" style={{ color: 'var(--text-tertiary)' }}>0</span>
              </div>
              <div className="sev-item">
                <span className="sev-label">Medium</span>
                <span className="sev-count" style={{ color: 'var(--text-tertiary)' }}>0</span>
              </div>
              <div className="sev-item">
                <span className="sev-label">Low</span>
                <span className="sev-count" style={{ color: 'var(--text-tertiary)' }}>0</span>
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', width: '100%', marginBottom: '1rem' }}>
              {cWidth > 0 && (
                <div className="sev-item" style={{ width: `${cWidth}%`, flexShrink: 0, overflow: 'visible' }}>
                  <span className="sev-label">Critical</span>
                  <span className="sev-count" style={{ color: 'var(--critical)' }}>{critical}</span>
                </div>
              )}
              {hWidth > 0 && (
                <div className="sev-item" style={{ width: `${hWidth}%`, flexShrink: 0, overflow: 'visible' }}>
                  <span className="sev-label">High</span>
                  <span className="sev-count" style={{ color: 'var(--high)' }}>{high}</span>
                </div>
              )}
              {mWidth > 0 && (
                <div className="sev-item" style={{ width: `${mWidth}%`, flexShrink: 0, overflow: 'visible' }}>
                  <span className="sev-label">Medium</span>
                  <span className="sev-count" style={{ color: 'var(--medium)' }}>{medium}</span>
                </div>
              )}
              {lWidth > 0 && (
                <div className="sev-item" style={{ width: `${lWidth}%`, flexShrink: 0, overflow: 'visible' }}>
                  <span className="sev-label">Low</span>
                  <span className="sev-count" style={{ color: 'var(--low)' }}>{low}</span>
                </div>
              )}
            </div>
          )}

          <div className="severity-bar-container" style={{ marginTop: total === 0 ? '1.5rem' : '0' }}>
            {total === 0 ? (
              <div className="severity-segment" style={{ width: '100%', backgroundColor: 'var(--success)' }} />
            ) : (
              <>
                {cWidth > 0 && <div className="severity-segment" style={{ width: `${cWidth}%`, backgroundColor: 'var(--critical)' }} />}
                {hWidth > 0 && <div className="severity-segment" style={{ width: `${hWidth}%`, backgroundColor: 'var(--high)' }} />}
                {mWidth > 0 && <div className="severity-segment" style={{ width: `${mWidth}%`, backgroundColor: 'var(--medium)' }} />}
                {lWidth > 0 && <div className="severity-segment" style={{ width: `${lWidth}%`, backgroundColor: 'var(--low)' }} />}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
