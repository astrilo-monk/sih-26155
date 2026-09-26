// Potential attack paths: how this device's confirmed problems chain together, and the one fix that breaks
// each chain. Every step is a decided FAIL (app/analysis/attack_paths.py), so a path is never a guess.
export default function AttackPaths({ paths = [], labels = [], onFix }) {
  if (paths.length === 0) return null;
  const multi = labels.length > 1;
  return (
    <section className="paths" aria-labelledby="paths-title">
      <h2 className="paths-k" id="paths-title">Potential attack paths</h2>
      <p className="paths-lede">
        How the problems found here add up. A path appears only when every step is a confirmed problem. It shows what
        the configuration allows, not a test of the live device.
      </p>
      <ol className="path-list">
        {paths.map((p) => (
          <li key={`${p.config_index}-${p.path_id}`} className={`path sev-${p.severity}`}>
            <div className="path-head">
              <h3 className="path-title">{p.title}</h3>
              <span className="path-sev">{p.severity}</span>
              {multi && <span className="mono small muted">{labels[p.config_index]}</span>}
            </div>
            <ol className="path-flow">
              {p.steps.map((s, i) => (
                <li key={s.title} className="path-step">
                  <span className="path-n" aria-hidden="true">{i + 1}</span>
                  <strong className="path-step-title">{s.title}</strong>
                  <span className="path-how">{s.how}</span>
                  <ul className="path-why">
                    {s.controls.map((c) => (
                      <li key={c.control_id}>
                        <span className="mono">{c.control_id}</span> {c.title}
                        {c.lines[0] && <code className="path-line">line {c.lines[0].number}: {c.lines[0].text}</code>}
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
              <li className="path-step path-outcome">
                <span className="path-n" aria-hidden="true">!</span>
                <strong className="path-step-title">{p.outcome}</strong>
              </li>
            </ol>
            <p className="path-break">
              <span>
                <b>Break it:</b> fix {p.break_with.join(' and ')}, the “{p.break_step}” step, and the whole path closes.
              </span>
              {onFix && <button type="button" className="btn btn-sm" onClick={onFix}>Go to fixes</button>}
            </p>
          </li>
        ))}
      </ol>
    </section>
  );
}
