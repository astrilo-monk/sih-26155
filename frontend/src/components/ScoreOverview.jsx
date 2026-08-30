import { ShieldAlert, ShieldCheck, AlertTriangle, AlertCircle, Info } from 'lucide-react';

export default function ScoreOverview({ score, critical, high, medium, low }) {
  const getStatus = (s) => {
    if (s < 40) return { label: 'Critical', color: 'var(--critical)', Icon: ShieldAlert };
    if (s < 70) return { label: 'Needs Attention', color: 'var(--high)', Icon: AlertTriangle };
    if (s < 90) return { label: 'Fair', color: 'var(--medium)', Icon: Info };
    return { label: 'Good', color: 'var(--success)', Icon: ShieldCheck };
  };

  const status = getStatus(score);
  const StatusIcon = status.Icon;

  return (
    <div className="overview-section">
      <div className="overview-card score-panel">
        <div className="score-value-group">
          <div className="section-title">Security Score</div>
          <div className="score-number" style={{ color: status.color }}>
            {score}<span style={{ fontSize: '1rem', color: 'var(--text-tertiary)', fontWeight: 500 }}>/100</span>
          </div>
          <div className="score-status" style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', color: status.color }}>
            <StatusIcon size={16} />
            {status.label}
          </div>
        </div>
      </div>
      
      <div className="severity-stats">
        <div className="stat-box" style={{ borderTop: '3px solid var(--critical)' }}>
          <div className="stat-header">
            Critical
            <AlertCircle size={14} color="var(--critical)" />
          </div>
          <div className="stat-value" style={{ color: 'var(--text-primary)' }}>{critical}</div>
        </div>
        <div className="stat-box" style={{ borderTop: '3px solid var(--high)' }}>
          <div className="stat-header">
            High
            <AlertTriangle size={14} color="var(--high)" />
          </div>
          <div className="stat-value" style={{ color: 'var(--text-primary)' }}>{high}</div>
        </div>
        <div className="stat-box" style={{ borderTop: '3px solid var(--medium)' }}>
          <div className="stat-header">
            Medium
            <Info size={14} color="var(--medium)" />
          </div>
          <div className="stat-value" style={{ color: 'var(--text-primary)' }}>{medium}</div>
        </div>
        <div className="stat-box" style={{ borderTop: '3px solid var(--low)' }}>
          <div className="stat-header">
            Low
            <ShieldCheck size={14} color="var(--low)" />
          </div>
          <div className="stat-value" style={{ color: 'var(--text-primary)' }}>{low}</div>
        </div>
      </div>
    </div>
  );
}
