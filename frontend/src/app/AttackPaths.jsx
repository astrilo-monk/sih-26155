// Potential attack paths: how this device's confirmed problems chain together, and the one fix that breaks
// each chain. Every step is a decided FAIL (app/analysis/attack_paths.py), so a path is never a guess.

function Chain({ path }) {
  return (
    <ol className="chain-rail" aria-label="The chain, step by step">
      {path.steps.map((s, i) => {
        const breaks = s.title === path.break_step;
        return (
          <li key={s.title} className={`rail-node${breaks ? ' rail-break' : ''}`}>
            <span className="rail-dot" aria-hidden="true">{i + 1}</span>
            <span className="rail-label">{s.title}</span>
            {breaks && <span className="rail-tag">fix here</span>}
          </li>
        );
      })}
      <li className="rail-node rail-end">
        <span className="rail-dot" aria-hidden="true">!</span>
        <span className="rail-label">{path.outcome}</span>
      </li>
    </ol>
  );
}

function Steps({ path }) {
  return (
    <ol className="path-steps">
      {path.steps.map((s, i) => (
        <li key={s.title} className={`path-step${s.title === path.break_step ? ' path-step-break' : ''}`}>
          <span className="path-n" aria-hidden="true">{i + 1}</span>
          <div className="path-step-body">
            <p className="path-step-title">{s.title}</p>
            <p className="path-how">{s.how}</p>
          </div>
          <ul className="path-why">
            {s.controls.map((c) => (
              <li key={c.control_id}>
                <span className="path-check"><span className="mono">{c.control_id}</span> {c.title}</span>
                {c.lines[0] && <code className="path-line">line {c.lines[0].number}: {c.lines[0].text}</code>}
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ol>
  );
}

export default function AttackPaths({ paths = [], labels = [], onFix }) {
  if (paths.length === 0) return null;
  const multi = labels.length > 1;
  return (
    <section className="paths" aria-labelledby="paths-title">
      <h2 className="paths-k" id="paths-title">Potential attack paths</h2>
      <ol className="path-list">
        {paths.map((p) => (
          <li key={`${p.config_index}-${p.path_id}`} className={`path-card sev-${p.severity}`}>
            <div className="path-top">
              <div className="path-name">
                <span className="path-sev">{p.severity}</span>
                <h3 className="path-title">{p.title}</h3>
                {multi && <span className="path-device mono">{labels[p.config_index]}</span>}
              </div>
              <div className="path-close">
                <p>
                  <b>Break it:</b> fix {p.break_with.join(' and ')}, the “{p.break_step}” step, and the whole path closes.
                </p>
                {onFix && <button type="button" className="btn btn-sm btn-primary" onClick={onFix}>Go to fixes</button>}
              </div>
            </div>
            <Chain path={p} />
            <Steps path={p} />
          </li>
        ))}
      </ol>
    </section>
  );
}

// The Attack paths page (sidebar): the chains for every device of the scan, or why there are none.
export function AttackPathsPage({ scan, labels, go }) {
  const paths = scan.attack_paths || [];
  const fixes = [...new Set(paths.flatMap((p) => p.break_with))];
  const critical = paths.filter((p) => p.severity === 'critical').length;
  return (
    <div className="wrap enter">
      <header className="page-head">
        <p className="eyebrow">Attack paths</p>
        <h1 className="page-title">How the problems add up</h1>
        <p className="lede">
          A path appears only when every step is a confirmed problem. It shows what the configuration allows, not a
          test of the live device.
        </p>
      </header>
      {paths.length ? (
        <>
          <div className="paths-summary">
            <div><span className="tnum">{paths.length}</span> potential attack path{paths.length === 1 ? '' : 's'}</div>
            <div><span className="tnum">{critical}</span> critical</div>
            <div>
              <span className="tnum">{fixes.length}</span> fix{fixes.length === 1 ? '' : 'es'} close{fixes.length === 1 ? 's' : ''} them all
              <span className="paths-fixes mono">{fixes.join(' · ')}</span>
            </div>
          </div>
          <AttackPaths paths={paths} labels={labels} onFix={scan.archived ? null : () => go('fix')} />
          {scan.path_validation && (
            <p className="muted path-proof">
              Each path and its fix were checked against a positive and a negative configuration (commit{' '}
              <span className="mono">{scan.path_validation.commit}</span>, {scan.path_validation.generated}).
            </p>
          )}
        </>
      ) : (
        <p className="muted">No attack path: the confirmed problems on {labels.length > 1 ? 'these devices' : 'this device'} do
          not chain into one. Suspected problems never open a path.</p>
      )}
    </div>
  );
}
