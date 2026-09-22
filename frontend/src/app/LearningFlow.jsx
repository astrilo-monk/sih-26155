// The human-in-the-loop path every unfamiliar line takes, shown above this scan's questions and the learned list
const STAGES = ['Unknown syntax', 'Administrator review', 'Mapping', 'Confirmation', 'Learned mapping'];

export default function LearningFlow({ scanHref, here }) {
  return (
    <div className="wrap learning-flow">
      <p className="eyebrow">Adaptive learning</p>
      <ol className="flow-steps" aria-label="How NetAuditAI learns new syntax">
        {STAGES.map((s, i) => (
          <li key={s}><span className="mono">{String(i + 1).padStart(2, '0')}</span> {s}</li>
        ))}
      </ol>
      <nav className="flow-tabs" aria-label="Adaptive learning">
        {scanHref && <a href={scanHref} aria-current={here === 'teach' ? 'page' : undefined}>This scan’s unknown syntax</a>}
        <a href="#/app/learned" aria-current={here === 'learned' ? 'page' : undefined}>Learned mappings</a>
      </nav>
    </div>
  );
}
