import { useState, useEffect } from 'react';

export default function BeforeAfter({ comparison, onClose }) {
  const [animatedNewScore, setAnimatedNewScore] = useState(comparison.original_score);

  // Animate the new score counting up from the original
  useEffect(() => {
    const start = comparison.original_score;
    const end = comparison.new_score;
    const duration = 1500;
    const startTime = performance.now();

    function animate(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setAnimatedNewScore(Math.round(start + (end - start) * eased));
      if (progress < 1) requestAnimationFrame(animate);
    }

    // Small delay before animation starts so user sees the "before" state
    const timeout = setTimeout(() => requestAnimationFrame(animate), 500);
    return () => clearTimeout(timeout);
  }, [comparison]);

  const getScoreColor = (s) => {
    if (s < 40) return 'var(--critical)';
    if (s < 70) return 'var(--high)';
    if (s < 85) return 'var(--medium)';
    return 'var(--low)';
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: '800px' }} onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-group">
            <span className="badge" style={{
              backgroundColor: 'rgba(16, 185, 129, 0.15)',
              color: 'var(--success)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
            }}>verification result</span>
            <h2>Before / After Comparison</h2>
          </div>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          <div className="comparison-grid">
            <div className="comparison-card">
              <h3 style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>Before</h3>
              <div className="stat-value" style={{ fontSize: '3rem', color: getScoreColor(comparison.original_score) }}>
                {comparison.original_score}
              </div>
              <div className="stat-label">Security Score</div>
              <div className="stat-group">
                <div className="stat-item">
                  <span className="stat-value critical-color">{comparison.original_critical}</span>
                  <span className="stat-label">Critical</span>
                </div>
                <div className="stat-item">
                  <span className="stat-value" style={{ color: 'var(--text-primary)' }}>{comparison.original_findings}</span>
                  <span className="stat-label">Total</span>
                </div>
              </div>
            </div>

            <div className="comparison-card after">
              <h3 style={{ color: 'var(--success)', marginBottom: '1rem' }}>After</h3>
              <div className="stat-value" style={{ fontSize: '3rem', color: getScoreColor(animatedNewScore) }}>
                {animatedNewScore}
              </div>
              <div className="stat-label">Security Score</div>
              <div className="stat-group">
                <div className="stat-item">
                  <span className="stat-value critical-color">{comparison.new_critical}</span>
                  <span className="stat-label">Critical</span>
                </div>
                <div className="stat-item">
                  <span className="stat-value" style={{ color: 'var(--text-primary)' }}>{comparison.new_findings}</span>
                  <span className="stat-label">Total</span>
                </div>
              </div>
            </div>
          </div>

          {comparison.resolved_findings && comparison.resolved_findings.length > 0 && (
            <div className="resolved-list">
              <h3 style={{
                fontSize: '0.875rem',
                textTransform: 'uppercase',
                color: 'var(--text-secondary)',
                marginBottom: '0.75rem',
                letterSpacing: '0.05em',
              }}>Resolved Issues</h3>
              {comparison.resolved_findings.map((title, i) => (
                <div key={i} className="resolved-item">
                  <span>✓</span>
                  <span>{title}</span>
                </div>
              ))}
            </div>
          )}

          <div style={{ marginTop: '2rem', textAlign: 'center' }}>
            <button className="btn-primary" onClick={onClose} style={{ padding: '0.75rem 2rem' }}>
              Back to Dashboard
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
