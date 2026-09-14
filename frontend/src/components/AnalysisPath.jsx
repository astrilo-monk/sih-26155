// How each configuration actually went through the pipeline — so a generic / adaptive result is never
// mistaken for parser-backed assurance.
import { PROVISIONAL_ASSURANCE } from './ProvisionalResults';

const Step = ({ label, value, tone = 'neutral' }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', minWidth: '9rem' }}>
    <span style={{ fontSize: '0.6875rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{label}</span>
    <span className={`badge ${tone}`} style={{ alignSelf: 'flex-start' }}>{value}</span>
  </div>
);

const Arrow = () => <span style={{ color: 'var(--text-tertiary)', alignSelf: 'flex-end', paddingBottom: '0.2rem' }}>→</span>;

export default function AnalysisPath({ scanResult }) {
  const devices = scanResult.devices || [];
  return (
    <div className="posture-section">
      <div className="section-header">
        <span>Analysis Path</span>
        <span>configuration → vendor → facts → controls → posture · AI only for unresolved controls</span>
      </div>
      {devices.map((device, index) => {
        const ident = (scanResult.vendor_identification || []).find((v) => v.config_index === index);
        const adaptive = (scanResult.adaptive_configs || []).find((c) => c.config_index === index);
        const results = (scanResult.results || []).filter((r) => r.config_index === index);
        const confirmed = ident?.status === 'confirmed';
        const count = (pred) => new Set(results.filter(pred).map((r) => r.control_id)).size;
        const decided = count((r) => ['pass', 'fail'].includes(r.status) && !PROVISIONAL_ASSURANCE.has(r.assurance));
        const provisional = count((r) => PROVISIONAL_ASSURANCE.has(r.assurance));
        const recognized = count((r) => r.assurance === 'confirmed');
        const controls = new Set(results.map((r) => r.control_id)).size;
        return (
          <div key={index} style={{ marginBottom: '1rem' }}>
            <div className="drawer-section-title">{device.hostname}</div>
            {!confirmed && (
              <div className="drawer-text" style={{ color: 'var(--medium)', marginBottom: '0.5rem' }}>
                Generic / adaptive analysis: no dedicated parser for this configuration
                {ident?.status === 'unverified' ? ` (it resembles ${ident.detected_vendor}, but ${ident.reason})` : ''}.
                Lexicon heuristics and AI proposals are provisional and never scored; only administrator-confirmed
                recognizers are decisive. Vendor-specific remediation is blocked.
              </div>
            )}
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              <Step label="Vendor detection"
                    value={confirmed ? `${ident.detected_vendor} · confirmed` : ident?.status === 'unverified' ? 'unverified' : 'unknown'}
                    tone={confirmed ? 'low' : 'medium'} />
              <Arrow />
              <Step label="Facts from"
                    value={confirmed ? `dedicated parser · ${Math.round((ident.parse_coverage ?? 0) * 100)}% grammar` : 'generic tokenizer'}
                    tone={confirmed ? 'low' : 'medium'} />
              <Arrow />
              <Step label="Controls" value={`${controls} run · ${decided} decided`} />
              <Arrow />
              <Step label="AI escalation"
                    value={confirmed ? 'not used' : adaptive?.ai_available ? `${adaptive.ai_calls} call(s) · ${adaptive.ai_cache_hits} cached` : 'off / unavailable'} />
              <Arrow />
              <Step label="Human review" value={`${provisional} provisional`} tone={provisional ? 'medium' : 'neutral'} />
              <Arrow />
              <Step label="Recognizers" value={`${recognized} control(s) confirmed`} tone={recognized ? 'low' : 'neutral'} />
              <Arrow />
              <Step label="Remediation" value={confirmed ? 'deterministic · verified' : 'blocked'} tone={confirmed ? 'low' : 'critical'} />
            </div>
          </div>
        );
      })}
    </div>
  );
}
