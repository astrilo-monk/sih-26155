import { useState, useEffect } from 'react';
import { X, Check } from 'lucide-react';

export default function BeforeAfter({ comparison, onClose }) {
  const [animatedNewScore, setAnimatedNewScore] = useState(comparison.original_score);

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

    const timeout = setTimeout(() => requestAnimationFrame(animate), 500);
    return () => clearTimeout(timeout);
  }, [comparison]);

  const getScoreColor = (s) => {
    if (s < 40) return 'var(--critical)';
    if (s < 70) return 'var(--high)';
    if (s < 90) return 'var(--medium)';
    return 'var(--success)';
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: '700px' }} onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-group">
            <span className="badge" style={{
              backgroundColor: 'var(--success-bg)',
              color: 'var(--success)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
            }}>verification result</span>
            <h2>Before / After Comparison</h2>
          </div>
          <button className="close-btn" onClick={onClose}>
            <X size={20} />
          </button>
        </div>

        <div className="modal-body">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
            <div className="overview-card" style={{ textAlign: 'center' }}>
              <h3 style={{ color: 'var(--text-secondary)', marginBottom: '1rem', fontSize: '0.875rem' }}>Before</h3>
              <div style={{ fontSize: '3.5rem', fontWeight: 700, color: getScoreColor(comparison.original_score), lineHeight: 1 }}>
                {comparison.original_score}
              </div>
              <div style={{ fontSize: '0.875rem', color: 'var(--text-tertiary)', marginTop: '0.5rem' }}>Security Score</div>
              <div style={{ display: 'flex', justifyContent: 'space-around', marginTop: '2rem', paddingTop: '1.5rem', borderTop: '1px solid var(--border)' }}>
                <div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--critical)' }}>{comparison.original_critical}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Critical</div>
                </div>
                <div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 600 }}>{comparison.original_findings}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Total</div>
                </div>
              </div>
            </div>

            <div className="overview-card" style={{ textAlign: 'center', borderColor: 'var(--success)', boxShadow: '0 0 20px rgba(16, 185, 129, 0.05)' }}>
              <h3 style={{ color: 'var(--success)', marginBottom: '1rem', fontSize: '0.875rem' }}>After</h3>
              <div style={{ fontSize: '3.5rem', fontWeight: 700, color: getScoreColor(animatedNewScore), lineHeight: 1 }}>
                {animatedNewScore}
              </div>
              <div style={{ fontSize: '0.875rem', color: 'var(--text-tertiary)', marginTop: '0.5rem' }}>Security Score</div>
              <div style={{ display: 'flex', justifyContent: 'space-around', marginTop: '2rem', paddingTop: '1.5rem', borderTop: '1px solid var(--border)' }}>
                <div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--critical)' }}>{comparison.new_critical}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Critical</div>
                </div>
                <div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 600 }}>{comparison.new_findings}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Total</div>
                </div>
              </div>
            </div>
          </div>

          {comparison.resolved_findings && comparison.resolved_findings.length > 0 && (
            <div className="section" style={{ marginTop: '1rem' }}>
              <h3>Resolved Issues</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {comparison.resolved_findings.map((title, i) => (
                  <div key={i} style={{ 
                    display: 'flex', alignItems: 'center', gap: '0.75rem', 
                    padding: '0.75rem', backgroundColor: 'var(--success-bg)', 
                    borderRadius: 'var(--radius)', color: 'var(--text-primary)',
                    fontSize: '0.875rem'
                  }}>
                    <Check size={16} color="var(--success)" />
                    {title}
                  </div>
                ))}
              </div>
            </div>
          )}

          <div style={{ marginTop: 'auto', paddingTop: '2rem', textAlign: 'center' }}>
            <button className="btn-primary" onClick={onClose} style={{ padding: '0.75rem 2rem' }}>
              Back to Dashboard
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
