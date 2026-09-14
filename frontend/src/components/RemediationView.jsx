import { X } from 'lucide-react';
import BeforeAfter from './BeforeAfter';

// The five states an operator must be able to tell apart (plus "nothing to fix").
export const REMEDIATION_GROUPS = {
  fixed: { label: 'Fixed', badge: 'low', hint: 'Generated and verified by a full rescan' },
  needs_input: { label: 'Proposed', badge: 'medium', hint: 'A deterministic change is ready once you provide the values below' },
  manual_review: { label: 'Requires human review', badge: 'high', hint: 'No known-safe automatic change' },
  verification_failed: { label: 'Requires human review', badge: 'high', hint: 'Generated, but the rescan did not confirm it' },
  provisional: { label: 'Requires human review', badge: 'high', hint: 'Heuristic / AI verdict: confirm it on the Review & Recognizers page first' },
  no_recipe: { label: 'Unable to remediate', badge: 'neutral', hint: 'No deterministic strategy for this control on this vendor' },
  vendor_unverified: { label: 'Unverified vendor', badge: 'critical', hint: 'Vendor commands are blocked for unknown / unverified vendors' },
  not_failing: { label: 'Nothing to fix', badge: 'neutral', hint: 'The control has no decisive FAIL' },
};

export function StatusBadge({ status }) {
  const group = REMEDIATION_GROUPS[status] || { label: status, badge: 'neutral' };
  return <span className={`badge ${group.badge}`} title={group.hint}>{group.label}</span>;
}

function DiffBlock({ diff }) {
  const lines = diff.split('\n').filter((l) => !l.startsWith('---') && !l.startsWith('+++'));
  return (
    <div className="config-block">
      <div className="config-header"><span>proposed change</span></div>
      <div className="config-body">
        {lines.map((line, i) => (
          <div key={i} className={`config-line ${line.startsWith('+') ? 'fix-highlight' : line.startsWith('-') ? 'highlight' : ''}`}>
            <span>{line}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function RemediationDetail({ remediation: r }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div className="drawer-text">
        <StatusBadge status={r.status} /> {r.reason}
      </div>
      {r.explanation && <div className="drawer-text">{r.explanation}</div>}
      {r.warnings?.length > 0 && (
        <div className="drawer-text" style={{ color: 'var(--medium)' }}>
          {r.warnings.map((w) => <div key={w}>⚠ {w}</div>)}
        </div>
      )}
      {r.evidence?.line_numbers?.length > 0 && (
        <div>
          <div className="drawer-section-title">Before — cited configuration {r.scopes?.length > 0 && `(${r.scopes.join(', ')})`}</div>
          <div className="config-block">
            <div className="config-body">
              {r.evidence.line_numbers.map((n, i) => (
                <div key={n} className="config-line highlight">
                  <span className="line-num">{n}</span>
                  <span>{r.evidence.lines[i]}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
      {r.diff && (
        <div>
          <div className="drawer-section-title">Proposed deterministic change</div>
          <DiffBlock diff={r.diff} />
        </div>
      )}
      {r.checks?.length > 0 && (
        <div>
          <div className="drawer-section-title">Rescan verification</div>
          {r.checks.map((c) => (
            <div key={c.name} className="drawer-text" style={{ color: c.passed ? 'var(--success)' : 'var(--critical)' }}>
              {c.passed ? '✓' : '✗'} {c.detail}
            </div>
          ))}
        </div>
      )}
      {r.before && r.after && (
        <div>
          <div className="drawer-section-title">After — {r.rule_id} {r.control_status_before} → {r.control_status_after}</div>
          <BeforeAfter before={r.before} after={r.after} />
        </div>
      )}
    </div>
  );
}

export default function RemediationView({ remediation, onClose, onOpenQueue }) {
  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer" style={{ maxWidth: '800px' }} onClick={(e) => e.stopPropagation()}>
        <div className="drawer-header">
          <div className="drawer-title-group">
            <StatusBadge status={remediation.status} />
            <div className="drawer-title">{remediation.title}</div>
            <div className="drawer-meta">
              <span>{remediation.rule_id}</span>
              <span className="dot-separator" />
              <span>{remediation.device_hostname}</span>
              <span className="dot-separator" />
              <span>{remediation.vendor}</span>
            </div>
          </div>
          <button className="btn-ghost" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <div className="drawer-content">
          <RemediationDetail remediation={remediation} />
        </div>
        {remediation.status === 'needs_input' && (
          <div className="drawer-footer">
            <button className="btn-primary" style={{ width: '100%', justifyContent: 'center' }} onClick={onOpenQueue}>
              Enter values on the Remediation page
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
