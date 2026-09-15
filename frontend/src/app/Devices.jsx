import { checkItems, deviceLabels, isDecisive, isProblem, vendorState } from '../lib/domain';

// How NetAuditAI read each uploaded configuration: platform, how much it could decide, AI help, and fixes
export default function Devices({ scan, audit }) {
  const labels = deviceLabels(scan.devices);
  const items = checkItems(scan, audit.plan);
  const adaptive = scan.adaptive_configs || [];

  return (
    <div className="wrap devices-page enter">
      <header className="page-head">
        <p className="eyebrow">Devices</p>
        <h1 className="page-title">How each configuration was read</h1>
        <p className="lede">NetAuditAI identifies the vendor without guessing. A dedicated parser is used only when the vendor is confirmed.</p>
      </header>
      <ul className="device-cards">
        {scan.devices.map((device, index) => {
          const ident = (scan.vendor_identification || []).find((v) => v.config_index === index);
          const vs = vendorState(ident);
          const own = items.filter((i) => i.configIndex === index);
          const decided = own.filter((i) => i.results.some(isDecisive)).length;
          const ai = adaptive.find((c) => c.config_index === index);
          const reasons = ai?.provisional_reasons || [];
          const evidence = ai?.vendor_evidence;
          return (
            <li key={index} className="device-card">
              <header className="device-card-head">
                <h2 className="device-name mono">{labels[index]}</h2>
                <span className={`tag ${vs.key === 'confirmed' ? 'tag-pass' : 'tag-review'}`}>{vs.label}</span>
              </header>
              <dl className="kv">
                <dt>Read by</dt>
                <dd>{vs.key === 'confirmed' ? 'A dedicated parser' : 'Generic analysis (no dedicated parser)'}
                  {vs.key === 'confirmed' && ident?.parse_coverage != null && ` · ${Math.round(ident.parse_coverage * 100)}% of lines understood`}</dd>
                <dt>Checks decided</dt><dd>{decided} of {own.length}</dd>
                <dt>Problems</dt><dd>{own.filter(isProblem).length}</dd>
                <dt>AI help</dt>
                <dd>{vs.key === 'confirmed' ? 'Not used — the parser decides'
                  : ai?.ai_available ? `${ai.ai_calls || 0} request(s), ${ai.ai_cache_hits || 0} answered from cache — suggestions only, never counted`
                    : 'Off or unavailable'}{ai?.ai_unavailable_lines ? ` · unavailable for ${ai.ai_unavailable_lines} line(s)` : ''}</dd>
                <dt>Automatic fixes</dt><dd>{vs.key === 'confirmed' ? 'Available where a proven fix exists' : 'Not available until the vendor is confirmed'}</dd>
                {ai?.learned_matches > 0 && <><dt>Recognized from what you taught</dt><dd>{ai.learned_matches} line(s)</dd></>}
                {evidence && evidence.status !== 'unknown' && (
                  <><dt>Vendor hint</dt><dd>{evidence.status === 'identified' ? evidence.likely_vendor : 'conflicting'} <span className="muted">(information only — never selects a parser)</span></dd></>
                )}
              </dl>
              <p className="small muted">{vs.note}</p>
              {reasons.length > 0 && (
                <ul className="small muted reasons">{reasons.map((r) => <li key={r}>{r}</li>)}</ul>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
