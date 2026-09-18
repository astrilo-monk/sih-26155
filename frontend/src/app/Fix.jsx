import { useState } from 'react';
import FileDiff from '../components/ui/FileDiff';
import Count from '../components/ui/Count';
import { Severity, StatusMark } from '../components/ui/Evidence';
import {
  auditCounts, candidateMeta, candidateSource, CANNOT_FIX_REASON, checkItems, isProblem, itemState,
  NEEDS_ADMIN_REASON, quotedCommands, stateMeta, vendorName, vendorState,
} from '../lib/domain';

const CHECK_NAMES = {
  vendor: 'Vendor still confirmed',
  parse_coverage: 'Whole file still readable',
  target: 'This problem is gone',
  no_regression: 'Nothing else got worse',
  controls: 'Every check re-run',
  generic_path: 'Still read by generic analysis',
};

const lowerFirst = (s) => (/^[A-Z][a-z]/.test(s) ? s[0].toLowerCase() + s.slice(1) : s);
const joinWords = (words) => (words.length < 2 ? words.join('') : `${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}`);
// "MGMT-001 now passes: Telnet is not allowed…" → "Telnet is not allowed…"
const plainOutcome = (reason = '') => reason.replace(/^[A-Z]+-\d+ now passes:\s*/, '');

// The rescan checks behind a verified fix
export function VerifyList({ checks }) {
  return (
    <ul className="checks">
      {checks.map((c, i) => (
        <li key={c.name} className={c.passed ? 'ok' : 'bad'} style={{ '--c': i }}>
          <span className="check-mark" aria-hidden="true">{c.passed ? '✓' : '×'}</span>
          <span className="visually-hidden">{c.passed ? 'Passed: ' : 'Failed: '}</span>
          <span className="check-name">{CHECK_NAMES[c.name] || c.name}</span>
          <span className="check-detail">{c.detail}</span>
        </li>
      ))}
    </ul>
  );
}

function CopyButton({ text, label }) {
  const [copied, setCopied] = useState(null);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied('Copied');
    } catch {
      setCopied('Copy isn’t available here — select the text instead');
    }
  };
  return (
    <span className="copy">
      <button type="button" className="btn btn-sm" onClick={copy}>{label}</button>
      {copied && <span className="small muted" role="status">{copied}</span>}
    </span>
  );
}

// The generated change and its rescan checks, for people who want to see them
function ChangeDetails({ rem, summary = 'Show the change' }) {
  const [open, setOpen] = useState(false);
  if (!rem?.diff && !rem?.checks?.length) return null;
  return (
    <div className="more">
      <button type="button" className="more-toggle" aria-expanded={open} onClick={() => setOpen((v) => !v)}>{summary}</button>
      {open && (
        <div className="more-body reveal-open">
          {rem.diff && <FileDiff diff={rem.diff} file={rem.device_hostname} caption="Proposed change" />}
          {rem.checks?.length > 0 && <VerifyList checks={rem.checks} />}
          {rem.explanation && <p className="small muted">{rem.explanation}</p>}
        </div>
      )}
    </div>
  );
}

// A candidate remediation for a device whose vendor isn't confirmed: text a person proposes (or AI drafts),
// which NetAuditAI checks against the uploaded configuration and a person confirms. Nothing is ever sent to
// a device, and no candidate changes what the scan found.
export function CandidateFix({ item, audit }) {
  const candidate = audit.candidates?.[item.key] || null;
  const [editing, setEditing] = useState(false);
  const [command, setCommand] = useState('');
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);

  const step = async (action, body) => {
    setBusy(action);
    setError(null);
    try {
      await audit.candidateStep(item, action, body);
      setEditing(false);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  };
  const openEditor = () => {
    setCommand(candidate?.command || '');
    setEditing(true);
    setError(null);
  };
  const errorLine = error && <p className="field-error" role="alert">{error}</p>;
  const meta = candidate ? candidateMeta(candidate.status) : null;

  const editor = (
    <form
      className="candidate-form"
      onSubmit={(e) => { e.preventDefault(); step('propose', { command }); }}
    >
      <label className="field">
        <span className="field-label">Command for this device</span>
        <textarea
          className="input mono" rows={3} aria-label="Command for this device" name="candidate-command"
          value={command} onChange={(e) => setCommand(e.target.value)}
          placeholder={item.primary?.evidence?.lines?.[0] ? `e.g. the command that removes: ${item.primary.evidence.lines[0].trim()}` : ''}
        />
        <span className="field-help">Exactly as you would type it on the device. NetAuditAI never runs it — it checks what it can against this configuration and keeps it for your confirmation.</span>
      </label>
      <div className="actions">
        <button type="submit" className="btn btn-primary" disabled={busy || !command.trim()}>
          {busy === 'propose' ? 'Checking…' : 'Use this command'}
        </button>
        <button type="button" className="btn btn-quiet" onClick={() => setEditing(false)} disabled={!!busy}>Cancel</button>
      </div>
      {errorLine}
    </form>
  );

  if (!candidate) {
    return (
      <div className="fix fix-candidate">
        <p className="fix-lead"><span className="fix-mark fix-mark-ask" aria-hidden="true">?</span> Needs administrator input</p>
        <p className="small muted">{NEEDS_ADMIN_REASON}</p>
        {item.finding?.recommendation && <p><strong>What to change: </strong>{item.finding.recommendation}</p>}
        {editing ? editor : (
          <>
            <div className="actions">
              <button type="button" className="btn btn-primary" onClick={() => step('generate')} disabled={!!busy}>
                {busy === 'generate' ? 'Asking AI…' : 'Generate candidate fix'}
              </button>
              <button type="button" className="btn" onClick={openEditor} disabled={!!busy}>Enter command manually</button>
            </div>
            {errorLine}
          </>
        )}
        <p className="small muted"><strong>Candidate status:</strong> No candidate yet. NetAuditAI never applies a candidate automatically.</p>
      </div>
    );
  }

  return (
    <div className={`fix fix-candidate tone-${meta.tone}`}>
      <p className="candidate-k">Candidate remediation</p>
      <p className="candidate-badges">
        <span className="tag">{candidateSource(candidate.source)}</span>
        <span className={`tag tag-${meta.tone}`}>{meta.label}</span>
        {candidate.confidence && <span className="small muted">AI confidence: {candidate.confidence}</span>}
      </p>
      <pre className="cmd"><code>{candidate.command}</code></pre>
      {candidate.explanation && <p><strong>Why: </strong>{candidate.explanation}</p>}
      {candidate.assumptions?.length > 0 && (
        <p className="small muted">Assumes: {candidate.assumptions.join('; ')}</p>
      )}
      {candidate.control_status_after && (
        <p className="small">
          <span className="mono">{candidate.rule_id}</span>{' '}
          {candidate.control_status_before} → {candidate.control_status_after} on a copy of your configuration
        </p>
      )}
      <p>{candidate.reason}</p>
      {candidate.checks?.length > 0 && <VerifyList checks={candidate.checks} />}
      {candidate.diff && <FileDiff diff={candidate.diff} file={candidate.device_hostname} caption="Simulated change (on a copy — your file is untouched)" />}
      <p className="small muted">{meta.note}</p>
      {editing ? editor : (
        <>
          <div className="actions">
            {candidate.status === 'draft' && (
              <button type="button" className="btn btn-primary" onClick={() => step('verify')} disabled={!!busy}>
                {busy === 'verify' ? 'Checking…' : 'Verify candidate'}
              </button>
            )}
            {(candidate.status === 'verified' || candidate.status === 'unverified') && (
              <button type="button" className="btn btn-primary" onClick={() => step('confirm')} disabled={!!busy}>
                {busy === 'confirm' ? 'Confirming…' : candidate.status === 'verified' ? 'Confirm' : 'Confirm anyway'}
              </button>
            )}
            <button type="button" className="btn" onClick={openEditor} disabled={!!busy}>
              {candidate.status === 'confirmed' || candidate.status === 'rejected' ? 'Propose another command' : 'Edit'}
            </button>
            {candidate.status !== 'rejected' && candidate.status !== 'confirmed' && (
              <button type="button" className="btn btn-quiet" onClick={() => step('reject')} disabled={!!busy}>Reject</button>
            )}
            <CopyButton text={candidate.command} label="Copy command" />
          </div>
          {errorLine}
        </>
      )}
    </div>
  );
}

// "What can we do?" for one problem — the same block on the Fix page and in the finding drawer
export function FixAction({ item, scan, audit }) {
  const state = itemState(item, audit.applied);
  const rem = audit.verified[item.key] || item.remediation;
  const vs = vendorState((scan.vendor_identification || []).find((v) => v.config_index === item.configIndex));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [values, setValues] = useState({});

  const run = async (action) => {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const expected = (
    <><dt>Expected result</dt><dd>After you change the device, scan its configuration again. “{item.question || item.title}” should then pass.</dd></>
  );
  const recommendation = item.finding?.recommendation;
  const errorLine = error && <p className="field-error" role="alert">{error}</p>;

  if (state === 'fixed') {
    return (
      <div className="fix fix-done" role="status">
        <p className="fix-lead"><span className="fix-mark" aria-hidden="true">✓</span> Fix verified</p>
        {rem?.reason && <p>{plainOutcome(rem.reason)}</p>}
        <p className="small muted">This fix is in your corrected configuration. NetAuditAI rescanned it to make sure the problem is gone and nothing else got worse.</p>
        <ChangeDetails rem={rem} />
      </div>
    );
  }

  if (state === 'can_fix') {
    return (
      <div className="fix fix-can">
        <p className="fix-lead"><span className="fix-mark" aria-hidden="true">✓</span> NetAuditAI can fix this safely.</p>
        <p className="small muted">It changes only the failing setting, then rescans the corrected configuration to prove the problem is gone.</p>
        <button type="button" className="btn btn-primary" onClick={() => run(() => audit.fixOne(item))} disabled={busy}>
          {busy ? 'Fixing and verifying…' : 'Fix this'}
        </button>
        {errorLine}
        <ChangeDetails rem={rem} summary="Preview the change" />
      </div>
    );
  }

  if (state === 'needs_input') {
    const specs = (audit.plan?.inputs || []).filter((s) => rem.missing_inputs.includes(s.name));
    const submit = (e) => {
      e.preventDefault();
      run(async () => {
        const res = await audit.answer(item, values);
        if (res && res.status === 'needs_input') setError(res.reason);
      });
    };
    return (
      <form className="fix fix-input" onSubmit={submit}>
        <p className="fix-lead">We know the problem. We need your {joinWords(specs.map((s) => lowerFirst(s.label)))} to fix it.</p>
        <div className="fields">
          {specs.map((spec) => (
            <label key={spec.name} className="field">
              <span className="field-label">{spec.label}</span>
              <input
                className="input mono"
                aria-label={spec.label}
                type={spec.name === 'ntp_key' ? 'password' : 'text'}
                // a saved browser password must never be filled into a configuration value unseen
                autoComplete={spec.name === 'ntp_key' ? 'new-password' : 'off'}
                name={`remediation-${spec.name}`}
                value={values[spec.name] || ''}
                onChange={(e) => setValues((prev) => ({ ...prev, [spec.name]: e.target.value }))}
              />
              <span className="field-help">{spec.help}</span>
            </label>
          ))}
        </div>
        <button type="submit" className="btn btn-primary" disabled={busy || specs.some((s) => !(values[s.name] || '').trim())}>
          {busy ? 'Generating and verifying…' : 'Generate fix'}
        </button>
        {errorLine}
        <p className="small muted">Your values are checked, then written only into a fixed, known-safe change — never run as commands.</p>
      </form>
    );
  }

  if (state === 'needs_admin') return <CandidateFix item={item} audit={audit} />;

  if (state === 'manual' || state === 'cannot_fix') {
    // quoted commands are backend text, and only for a confirmed vendor
    const commands = state === 'manual' && vs.key === 'confirmed' ? quotedCommands(rem?.reason, recommendation) : [];
    const why = state === 'cannot_fix' ? CANNOT_FIX_REASON[rem?.status] : rem?.reason;
    return (
      <div className="fix fix-manual">
        <p className="fix-lead">
          {state === 'manual'
            ? 'We won’t change this automatically because doing so could affect how the network behaves.'
            : 'We can’t fix this automatically.'}
        </p>
        <dl className="fix-steps">
          {why && <><dt>Why</dt><dd>{why}</dd></>}
          {recommendation && <><dt>What to change</dt><dd>{recommendation}</dd></>}
          {commands.length > 0 && (
            <>
              <dt>Commands for {vendorName((scan.devices[item.configIndex] || {}).vendor)}</dt>
              <dd>
                <pre className="cmd"><code>{commands.join('\n')}</code></pre>
                {commands.some((c) => c.includes('…')) && <p className="small muted">Replace … with your own value.</p>}
                <CopyButton text={commands.join('\n')} label="Copy commands" />
              </dd>
            </>
          )}
          {expected}
        </dl>
      </div>
    );
  }

  if (state === 'verification_failed') {
    return (
      <div className="fix fix-failed" role="alert">
        <p className="fix-lead">We generated a fix, but the rescan didn’t confirm it — so it is not in your download.</p>
        {rem?.reason && <p>{rem.reason}</p>}
        {recommendation && <p><strong>What to change: </strong>{recommendation}</p>}
        <ChangeDetails rem={rem} summary="Show the generated change for review" />
      </div>
    );
  }

  // A decisive failure whose fix options are not known yet
  return (
    <div className="fix" aria-busy={audit.planLoading}>
      <p className="muted">
        {audit.planLoading ? 'Checking whether NetAuditAI can fix this…'
          : audit.planError ? `We couldn’t work out a fix: ${audit.planError}` : 'NetAuditAI couldn’t work out a fix for this.'}
      </p>
      {recommendation && <p><strong>What to change: </strong>{recommendation}</p>}
    </div>
  );
}

function FixCard({ item, scan, audit, label, onOpen }) {
  const state = itemState(item, audit.applied);
  const meta = stateMeta(state);
  // A question is open so it can be answered; a card the person just acted on stays open to show its outcome.
  // Automatic fixes start closed: "Fix all" above covers them without repeating the same sentence six times.
  const [open, setOpen] = useState(state === 'needs_input' || state === 'needs_admin' || !!audit.verified[item.key]);
  return (
    <li className={`fix-card tone-${meta.tone} sev-edge-${item.severity}`}>
      <div className="fix-card-head">
        <Severity level={item.severity} />
        <button type="button" className="fix-card-title" onClick={() => onOpen(item)}>{item.title}</button>
        {label && <span className="small muted">{label}</span>}
        <StatusMark state={state} size="compact" />
        <button type="button" className="btn btn-quiet btn-sm" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
          {open ? 'Hide' : state === 'fixed' ? 'Details' : 'How to fix'}
        </button>
      </div>
      {open && <div className="fix-card-body reveal-open"><FixAction item={item} scan={scan} audit={audit} /></div>}
    </li>
  );
}

function Group({ id, title, hint, items, ...rest }) {
  if (items.length === 0) return null;
  return (
    <section className="fix-group" aria-labelledby={`${id}-title`} id={id}>
      <header className="fix-group-head">
        <h2 className="section-title" id={`${id}-title`}>{title} <span className="count-pill tnum">{items.length}</span></h2>
        {hint && <p className="small muted">{hint}</p>}
      </header>
      <ul className="fix-cards">
        {items.map((item) => (
          <FixCard key={item.key} item={item} label={rest.labels.length > 1 ? rest.labels[item.configIndex] : null} {...rest} />
        ))}
      </ul>
    </section>
  );
}

export default function Fix({ scan, audit, labels, onOpen, onTeach }) {
  const { plan, planLoading, planError, applied } = audit;
  const [downloading, setDownloading] = useState(false);
  const [downloaded, setDownloaded] = useState(false);
  const [error, setError] = useState(null);

  const items = checkItems(scan, plan).filter(isProblem);
  const counts = auditCounts(scan, plan, applied, audit.queue);
  const inState = (...states) => items.filter((i) => states.includes(itemState(i, applied)));
  const canFix = inState('can_fix');
  const fixed = inState('fixed');
  const devices = plan?.devices || [];
  const verifiedTotal = devices.reduce((sum, d) => sum + d.fixed_controls.length, 0);
  const downloadable = devices.some((d) => d.fixed_config);
  const scored = devices.filter((d) => d.before && d.after && d.fixed_controls.length > 0);
  const unconfirmed = devices.filter((d) => d.vendor_status !== 'confirmed');
  const remaining = items.length - fixed.length;
  const shared = { scan, audit, labels, onOpen };

  const handleDownload = async () => {
    setDownloading(true);
    setError(null);
    try {
      await audit.download();
      setDownloaded(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setDownloading(false);
    }
  };

  const downloadButton = (
    <button type="button" className="btn btn-accent" onClick={handleDownload} disabled={!downloadable || downloading}>
      {downloading ? 'Preparing…' : 'Download corrected configuration'}
    </button>
  );

  const scoreMoves = scored.map((d) => (
    <p key={d.config_index} className="score-move">
      {labels.length > 1 && <span className="mono small">{labels[d.config_index]}</span>}
      <span className="score-k">Before</span><span className="score-v tnum">{d.before.posture ?? '—'}</span>
      <span className="score-arrow" aria-hidden="true">→</span>
      <span className="score-k">After</span>
      <span className="score-v score-after tnum">{d.after.posture == null ? '—' : <Count value={d.after.posture} from={d.before.posture ?? 0} duration={700} />}</span>
    </p>
  ));

  return (
    <div className="wrap fix-page enter">
      <header className="page-head">
        <p className="eyebrow">Fix</p>
        <h1 className="page-title">Fix what can be fixed</h1>
        <p className="lede">NetAuditAI fixes what it can prove is safe, asks you for anything it needs, and tells you exactly what to change by hand.</p>
      </header>

      {planError && (
        <div className="notice notice-danger" role="alert">
          <span className="notice-mark">×</span>
          <strong>We couldn’t prepare the fixes.</strong>
          <span>{planError}</span>
          <button type="button" className="btn btn-sm notice-action" onClick={() => audit.loadPlan()}>Try again</button>
        </div>
      )}
      {error && <div className="notice notice-danger" role="alert"><span className="notice-mark">×</span><span>{error}</span></div>}

      {!plan && planLoading && (
        <div className="loading-block" aria-busy="true">
          <div className="scan-bar" aria-hidden="true"><span /></div>
          <p className="muted">Generating each fix and rescanning to check it…</p>
        </div>
      )}

      {plan && items.length === 0 && (
        <div className="empty-state tone-pass">
          <p className="empty-mark" aria-hidden="true">✓</p>
          <h2 className="empty-title">Your configuration is already clean.</h2>
          <p>Nothing that NetAuditAI checked needs fixing.</p>
          {counts.review > 0 && (
            <button type="button" className="btn" onClick={onTeach}>Answer {counts.review} question{counts.review === 1 ? '' : 's'} about unfamiliar lines</button>
          )}
        </div>
      )}

      {plan && items.length > 0 && (
        <>
          {fixed.length > 0 ? (
            <section className="verified enter" role="status" aria-labelledby="verified-title">
              <p className="verified-k" id="verified-title"><span aria-hidden="true">✓</span> Fixes verified</p>
              {scoreMoves}
              <p className="verified-sum">{fixed.length} problem{fixed.length === 1 ? '' : 's'} fixed · {remaining} remaining</p>
              {fixed.length < verifiedTotal && (
                <p className="small muted">The “after” score includes every fix NetAuditAI verified ({verifiedTotal}), including ones you haven’t applied here yet — they are all in the download.</p>
              )}
              <div className="actions">
                {/* answering one question must not take away the one-click path for the verified automatic fixes */}
                {canFix.length > 0 && (
                  <button type="button" className="btn btn-primary" onClick={() => audit.markApplied(canFix.map((i) => i.key))}>
                    Fix the other {canFix.length} automatically
                  </button>
                )}
                {remaining > 0 && (
                  <button type="button" className="btn" onClick={() => document.getElementById('fix-remaining')?.scrollIntoView({ block: 'start' })}>
                    View remaining problems
                  </button>
                )}
                {downloadButton}
              </div>
            </section>
          ) : canFix.length > 0 && (
            <section className="fix-all" aria-labelledby="fix-all-title">
              <h2 className="section-title" id="fix-all-title">We can fix {canFix.length} problem{canFix.length === 1 ? '' : 's'} automatically</h2>
              <p className="muted">Each fix changes only the failing setting, and NetAuditAI already rescanned the corrected configuration to verify it.</p>
              {scoreMoves}
              <button type="button" className="btn btn-primary btn-lg" onClick={() => audit.markApplied(canFix.map((i) => i.key))}>
                Fix all {canFix.length}
              </button>
            </section>
          )}

          <div id="fix-remaining">
            <Group id="fix-can" title="Can fix automatically" items={canFix} {...shared} />
            <Group id="fix-input" title="Needs your input" hint="Answer these and NetAuditAI generates and verifies the fix." items={inState('needs_input')} {...shared} />
            <Group id="fix-candidate" title="Needs administrator input"
                   hint="NetAuditAI doesn’t write commands for a vendor it couldn’t confirm. Propose one — or let AI draft one — and NetAuditAI checks it against this configuration."
                   items={inState('needs_admin')} {...shared} />
            <Group id="fix-manual" title="Needs manual action" hint="NetAuditAI shows what to change; you make the change on the device."
                   items={inState('manual', 'cannot_fix', 'verification_failed')} {...shared} />
            <Group id="fix-pending" title="Still being checked" items={inState('problem')} {...shared} />
          </div>
          <Group id="fix-done" title="Fixed" items={fixed} {...shared} />
        </>
      )}

      {plan && counts.review > 0 && items.length > 0 && (
        <div className="notice notice-info">
          <span className="notice-mark">?</span>
          <strong>{counts.review} line{counts.review === 1 ? '' : 's'} NetAuditAI doesn’t recognize.</strong>
          <span>What they mean isn’t counted — and can’t be fixed — until you tell NetAuditAI.</span>
          <button type="button" className="btn btn-sm notice-action" onClick={onTeach}>Teach NetAuditAI</button>
        </div>
      )}

      {unconfirmed.length > 0 && (
        <p className="small muted">
          NetAuditAI never writes vendor commands for {joinWords(unconfirmed.map((d) => labels[d.config_index] ?? d.device_hostname))} by itself: the vendor isn’t confirmed. You can propose a command, or have AI draft one, and NetAuditAI checks it against the uploaded configuration before you confirm it. It never connects to the device.
        </p>
      )}

      {plan && items.length > 0 && (
        <div className="download-bar">
          {downloadButton}
          <span className="small">
            {downloadable
              ? `Includes every fix NetAuditAI verified (${verifiedTotal}). Only changes that passed the rescan are included — review before deploying.`
              : 'Nothing to download yet: no fix has been verified.'}
          </span>
        </div>
      )}

      {downloaded && (
        <div className="notice notice-ok" role="status">
          <span className="notice-mark">✓</span>
          <strong>Downloaded your corrected configuration.</strong>
          <span>To double-check it, scan the corrected file as a new audit.</span>
          <a className="btn btn-sm notice-action" href="#/app">Scan it</a>
        </div>
      )}
    </div>
  );
}
