// Heuristic / AI verdicts: shown with their evidence, never scored until confirmed.
// AI verdicts arrive as status "unknown" with the AI's proposed_status.
export const PROVISIONAL_ASSURANCE = new Set(['heuristic', 'ai_verified']);
const LABELS = { fail: 'Suspected FAIL', pass: 'Probable PASS' };
const verdict = (r) => r.proposed_status || r.status;

export default function ProvisionalResults({ results = [] }) {
  const provisional = results.filter((r) => PROVISIONAL_ASSURANCE.has(r.assurance) && LABELS[verdict(r)]);
  if (provisional.length === 0) return null;

  return (
    <div className="posture-section">
      <div className="section-header">
        <span>Provisional Results</span>
        <span>{provisional.length} awaiting confirmation · not scored</span>
      </div>
      <div className="data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Verdict</th>
              <th>Control</th>
              <th>Reason</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {provisional.map((r, i) => (
              <tr key={`${r.config_index}-${r.control_id}-${i}`}>
                <td>
                  <span className={`badge ${verdict(r) === 'fail' ? r.severity : 'neutral'}`}>{LABELS[verdict(r)]}</span>
                </td>
                <td>
                  <div className="finding-title-cell">
                    {/* the question reads right for both verdicts; titles name the problem */}
                    <span className="strong">{r.question}</span>
                    <span className="mono" style={{ color: 'var(--text-secondary)' }}>
                      {r.control_id} · {r.assurance === 'heuristic' ? 'lexicon heuristic' : 'AI verified'}
                    </span>
                  </div>
                </td>
                <td>{r.reason}</td>
                <td className="mono" style={{ color: 'var(--text-secondary)' }}>
                  {r.evidence.line_numbers.map((n, j) => (
                    <div key={n}>{n}: {r.evidence.lines[j]}</div>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
