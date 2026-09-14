// Posture is PASS / (PASS + FAIL) over the controls that could be decided; coverage says how many could.
// A posture is never shown as a full verdict unless every applicable control was decided.
const LIMITED_COVERAGE = 50;

const band = (s) => {
  if (s < 40) return { label: 'CRITICAL RISK', desc: 'Immediate remediation required.', color: 'var(--critical)' };
  if (s < 70) return { label: 'NEEDS ATTENTION', desc: 'Multiple security vulnerabilities detected.', color: 'var(--high)' };
  if (s < 90) return { label: 'FAIR', desc: 'Minor configuration issues present.', color: 'var(--medium)' };
  return { label: 'GOOD', desc: 'Configuration is largely secure.', color: 'var(--success)' };
};

export function assessment(posture, coverage = 0, criticalUnassessed = []) {
  if (posture == null) {
    return { label: 'NOT ASSESSED', desc: 'No control could be decided from confirmed evidence.', color: 'var(--text-tertiary)', scope: 'Not assessed' };
  }
  const b = band(posture);
  if (coverage >= 100 && criticalUnassessed.length === 0) return { ...b, scope: 'Full assessment' };
  if (coverage < LIMITED_COVERAGE) {
    return {
      label: 'LIMITED ASSESSMENT',
      desc: `This posture reflects only the ${coverage}% of applicable controls that could be decided — not the whole device.`,
      color: b.color,
      scope: 'Limited assessment',
    };
  }
  return {
    label: `${b.label} · PARTIAL`,
    desc: `Based on the ${coverage}% of applicable controls that could be decided.`,
    color: b.color,
    scope: 'Partial assessment',
  };
}

export default function ScoreOverview({ score, coverage = 0, bounds, criticalUnassessed = [], critical, high, medium, low }) {
  const status = assessment(score, coverage, criticalUnassessed);
  const total = critical + high + medium + low;
  const severities = [
    ['Critical', critical, 'var(--critical)'],
    ['High', high, 'var(--high)'],
    ['Medium', medium, 'var(--medium)'],
    ['Low', low, 'var(--low)'],
  ];

  return (
    <div className="posture-section">
      <div className="section-header">
        <span>Security Posture</span>
        <span>posture and coverage are reported separately</span>
      </div>

      <div className="posture-grid">
        <div className="score-display">
          <div className="score-value" style={{ color: status.color }} title="Posture of the decided controls (0–100)">
            {score ?? '—'}
          </div>
          <div className="score-info">
            <div className="score-status" style={{ color: status.color }}>{status.label}</div>
            <div className="score-desc">{status.desc}</div>
            <div className="score-desc" style={{ color: 'var(--text-primary)' }}>
              Posture {score ?? '—'} · Coverage {coverage}% · {status.scope}
            </div>
            {bounds && score != null && coverage < 100 && (
              <div className="score-desc">Range {bounds[0]}–{bounds[1]} if undecided controls fail / pass</div>
            )}
            {criticalUnassessed.length > 0 && (
              <div className="score-desc" style={{ color: 'var(--critical)' }}>
                Critical control(s) not assessed: {criticalUnassessed.join(', ')}
              </div>
            )}
          </div>
        </div>

        <div style={{ paddingTop: '0.5rem' }}>
          <div className="severity-breakdown">
            {severities.map(([label, n, color]) => (
              <div className="sev-item" key={label}>
                <span className="sev-label">{label}</span>
                <span className="sev-count" style={{ color: n ? color : 'var(--text-tertiary)' }}>{n}</span>
              </div>
            ))}
          </div>
          <div className="severity-bar-container" style={{ marginTop: '1.5rem' }}>
            {total === 0 ? (
              <div className="severity-segment" style={{ width: '100%', backgroundColor: 'var(--border-light)' }} />
            ) : (
              severities.filter(([, n]) => n > 0).map(([label, n, color]) => (
                <div key={label} className="severity-segment" style={{ width: `${(n / total) * 100}%`, backgroundColor: color }} />
              ))
            )}
          </div>
          <div className="score-desc" style={{ marginTop: '0.5rem' }}>Decisive findings only — suspected findings are not counted.</div>
        </div>
      </div>
    </div>
  );
}
