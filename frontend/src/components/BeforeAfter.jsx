// Posture and coverage before and after a verified remediation (scoring v2, never the legacy score).
const fmt = (summary) => (summary?.posture == null ? '—' : summary.posture);

export default function BeforeAfter({ before, after }) {
  if (!before) return null;
  const rows = [
    ['Posture', fmt(before), fmt(after ?? before)],
    ['Coverage', `${before.coverage}%`, `${(after ?? before).coverage}%`],
    ['Critical not assessed', before.critical_unassessed.length, (after ?? before).critical_unassessed.length],
  ];
  return (
    <table className="data-table" style={{ maxWidth: '26rem' }}>
      <thead>
        <tr><th /><th>Before</th><th>After</th></tr>
      </thead>
      <tbody>
        {rows.map(([label, b, a]) => (
          <tr key={label}>
            <td>{label}</td>
            <td className="mono">{b}</td>
            <td className="mono" style={{ color: a !== b ? 'var(--success)' : undefined }}>{a}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
