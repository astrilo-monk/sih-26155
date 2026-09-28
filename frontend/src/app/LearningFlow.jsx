// The human-in-the-loop path every unfamiliar line takes, shown above this scan's questions
const STAGES = ['Unknown syntax', 'Your review', 'Mapping', 'Confirmation', 'Learned mapping'];

export default function LearningFlow() {
  return (
    <div className="wrap learning-flow">
      <p className="eyebrow">Adaptive learning</p>
      <ol className="flow-steps" aria-label="How NetAuditAI learns new syntax">
        {STAGES.map((s, i) => (
          <li key={s}><span className="mono">{String(i + 1).padStart(2, '0')}</span> {s}</li>
        ))}
      </ol>
    </div>
  );
}
