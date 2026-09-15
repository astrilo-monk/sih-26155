import { useMemo, useState } from 'react';
import { apiClient } from '../api/client';
import { Evidence } from '../components/ui/Evidence';
import { deviceLabels, explainGate, sayFact, vendorName } from '../lib/domain';
import LegacyInterpretations from './LegacyInterpretations';

// Teach NetAuditAI: a person says what an unfamiliar line means. Underneath, the answer drafts a recognizer, the
// backend checks its safety gates and replays it, and only then saves it — nothing is counted before that, and
// nothing here can bypass those checks. The technical draft stays under Advanced details.

const STEPS = ['Unfamiliar line', 'Your answer', 'Checked', 'Learned'];
const fmtValue = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
const questionKey = (item, line) => `${item.config_index}-${item.control_id}-${line.line_number}`;

function Toggle({ label, children }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="more">
      <button type="button" className="more-toggle" aria-expanded={open} onClick={() => setOpen((v) => !v)}>{label}</button>
      {open && <div className="more-body reveal-open">{children(open)}</div>}
    </div>
  );
}

// The rule an answer would save, for expert users: preview it, and optionally edit it before continuing
function AdvancedDraft({ scanId, q, edits, setEdits }) {
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState(null);
  const base = { config_index: q.item.config_index, control_id: q.item.control_id, line_number: q.line.line_number };

  const load = async (request) => {
    try {
      setPreview(await apiClient.draftRecognizer(scanId, request));
      setError(null);
    } catch (err) {
      setError(err.message);
    }
  };

  const d = preview?.draft;
  const current = edits || (d && { command_pattern: d.command_pattern, scope_template: d.scope_template ?? '', value: d.value ?? '', any_dialect: false });
  const edit = (field) => (e) => {
    const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
    setEdits({ ...current, [field]: value });
  };

  return (
    <div className="advanced">
      <dl className="kv">
        <dt>Reading</dt>
        <dd className="mono">{q.line.predicate}{q.line.subject ? ` · ${q.line.subject}` : ''} = {fmtValue(q.line.value)}</dd>
        <dt>Check</dt><dd><span className="mono">{q.item.control_id}</span> {q.item.question}</dd>
        <dt>Current result</dt><dd>{q.item.status}{q.item.assurance ? ` (${q.item.assurance})` : ''} — {q.item.reason}</dd>
      </dl>
      {!preview && <button type="button" className="btn btn-sm" onClick={() => load(base)}>Show the rule NetAuditAI would save</button>}
      {error && <p className="field-error" role="alert">{error}</p>}
      {d && (
        <>
          <div className="fields">
            <label className="field">
              <span className="field-label">Template</span>
              <input className="input mono" aria-label="Template" value={current.command_pattern} onChange={edit('command_pattern')} />
              <span className="field-help">Slots: {'{int} {ip} {duration:min|s|h} {enum:name} {polarity} {any}'}</span>
            </label>
            <label className="field">
              <span className="field-label">Scope (optional)</span>
              <input className="input mono" aria-label="Scope" value={current.scope_template} onChange={edit('scope_template')} />
            </label>
            <label className="field">
              <span className="field-label">Value (JSON)</span>
              <input className="input mono" aria-label="Value" value={current.value} onChange={edit('value')} />
            </label>
          </div>
          <label className="check">
            <input type="checkbox" checked={!!current.any_dialect} onChange={edit('any_dialect')} />
            <span>Apply to any dialect <span className="muted">— by default it matches only configurations sharing this one’s top-level keywords</span></span>
          </label>
          <button type="button" className="btn btn-sm" onClick={() => load({ ...base, ...current })}>Re-check</button>
          {preview.errors.length > 0 ? (
            <ul className="small">{preview.errors.map((e) => <li key={e} className="text-fail">Safety check: {e}</li>)}</ul>
          ) : (
            <p className="small muted">
              Safety checks passed. Replay: {preview.replay.length} result change(s) across {preview.configs_checked} configuration(s):{' '}
              {preview.replay.map((c) => `${c.hostname} · ${c.control_id}: ${c.before} → ${c.after}`).join('; ') || 'none'}
            </p>
          )}
          <p className="small muted">Edits are used when you continue. They pass through the same safety checks.</p>
        </>
      )}
    </div>
  );
}

export default function Teach({ scan, audit, focusKey, onScanUpdated, onScanExpired }) {
  const scanId = scan.scan_id;
  const labels = deviceLabels(scan.devices);
  const items = audit.queue?.provisional;
  const questions = useMemo(() => (items || []).flatMap((item) => item.lines.map((line) => ({ key: questionKey(item, line), item, line }))), [items]);

  const [skipped, setSkipped] = useState(() => new Set());
  const [focus, setFocus] = useState(focusKey || null);
  const [phase, setPhase] = useState({ kind: 'ask' });
  const [choice, setChoice] = useState('');
  const [edits, setEdits] = useState(null);

  const open = questions.filter((q) => !skipped.has(q.key));
  // Progress counts unfamiliar checks — the unit every other page counts — not the lines inside them
  const itemOf = (q) => `${q.item.config_index}-${q.item.control_id}`;
  const openItems = [...new Set(open.map(itemOf))];
  // Once answered, the question stays on screen (the queue refreshes underneath) until the person continues
  const current = phase.q || open.find((q) => focus && q.key.startsWith(`${focus}-`)) || open[0] || null;
  const allConfirmed = (scan.vendor_identification || []).length > 0 && scan.vendor_identification.every((v) => v.status === 'confirmed');

  const resetAnswer = () => {
    setChoice('');
    setEdits(null);
  };
  const next = () => {
    setFocus(null);
    setPhase({ kind: 'ask' });
    resetAnswer();
  };

  const say = (q) => sayFact(q.line);
  const options = current ? [
    { value: current.key, q: current, text: say(current) ? `Yes — it ${say(current)}` : `Yes — it answers “${current.item.question}”` },
    ...questions
      .filter((q) => q.key !== current.key && q.item.config_index === current.item.config_index && q.line.line_number === current.line.line_number)
      .filter((q, i, all) => say(q) !== say(current) && all.findIndex((x) => say(x) === say(q)) === i)
      .map((q) => ({ value: q.key, q, text: say(q) ? `It ${say(q)}` : `It answers “${q.item.question}”` })),
    { value: 'reject', text: 'Something else — NetAuditAI misread this line' },
    { value: 'skip', text: 'I’m not sure — skip for now' },
  ] : [];

  const scanGone = (err) => {
    if (err.status === 404 && /scan/i.test(err.message)) {
      onScanExpired?.(scanId);
      return true;
    }
    return false;
  };

  const submit = async () => {
    const q = current;
    if (choice === 'skip') {
      setSkipped((s) => new Set(s).add(q.key));
      next();
      return;
    }
    setPhase({ kind: 'checking', q });
    try {
      if (choice === 'reject') {
        const updated = await apiClient.rejectProvisionalLine(scanId, {
          config_index: q.item.config_index, control_id: q.item.control_id, line_number: q.line.line_number,
        });
        onScanUpdated?.(updated);
        setPhase({ kind: 'rejected', q });
        return;
      }
      const target = questions.find((x) => x.key === choice) || q;
      const request = {
        config_index: target.item.config_index, control_id: target.item.control_id, line_number: target.line.line_number,
        ...(target.key === q.key && edits ? edits : {}),
      };
      // the backend drafts, runs its safety checks and replays; only a clean draft is saved
      const draft = await apiClient.draftRecognizer(scanId, request);
      if (draft.errors.length > 0) {
        setPhase({ kind: 'failed', q, message: draft.errors[0] });
        return;
      }
      const saved = await apiClient.saveRecognizer(scanId, request);
      onScanUpdated?.(saved.scan);
      setPhase({ kind: 'learned', q, target, saved });
    } catch (err) {
      if (!scanGone(err)) setPhase({ kind: 'failed', q, message: err.message });
    }
  };

  const stepOn = { ask: choice ? 1 : 0, checking: 2, failed: 1, rejected: 1, learned: 3 }[phase.kind];
  const moreAfter = phase.q && open.some((x) => !(x.item.config_index === phase.q.item.config_index && x.item.control_id === phase.q.item.control_id));
  const continueButton = (
    <button type="button" className="btn btn-primary" onClick={next}>{moreAfter ? 'Continue to next issue' : 'Continue'}</button>
  );

  return (
    <div className="wrap teach enter">
      <header className="page-head">
        <p className="eyebrow">Teach NetAuditAI</p>
        <h1 className="page-title">Help NetAuditAI understand this configuration</h1>
        <p className="lede">
          When NetAuditAI meets a line it doesn’t recognize, it asks what the line does. It checks your answer against the
          line, then remembers it for future scans.
        </p>
      </header>

      {audit.queueError && (
        <div className="notice notice-danger" role="alert">
          <span className="notice-mark">×</span><strong>The questions couldn’t be loaded.</strong><span>{audit.queueError}</span>
          <button type="button" className="btn btn-sm notice-action" onClick={audit.loadQueue}>Try again</button>
        </div>
      )}

      {items == null && !audit.queueError && <p className="muted" aria-busy="true">Loading questions…</p>}

      {items != null && !current && (
        <div className="empty-state tone-pass">
          <p className="empty-mark" aria-hidden="true">✓</p>
          <h2 className="empty-title">{skipped.size > 0 ? 'No more questions for now.' : 'Nothing needs your answer.'}</h2>
          <p>
            {allConfirmed
              ? `NetAuditAI read every line of this configuration with its dedicated ${vendorName(scan.vendor_identification[0].detected_vendor)} parser, so there is nothing to teach.`
              : skipped.size > 0
                ? `You skipped ${skipped.size} question${skipped.size === 1 ? '' : 's'}. Skipped lines stay uncounted.`
                : 'Checks NetAuditAI couldn’t decide stay “Not enough information” — they are never counted as passed.'}
          </p>
          <div className="actions">
            {skipped.size > 0 && <button type="button" className="btn" onClick={() => setSkipped(new Set())}>Review skipped questions</button>}
            <a className="btn btn-primary" href={`#/app/scan/${scanId}`}>Back to results</a>
          </div>
        </div>
      )}

      {current && (
        <article className={`teach-card phase-${phase.kind}`} aria-labelledby="teach-title">
          <ol className="teach-steps" aria-label="Progress">
            {STEPS.map((s, i) => (
              <li key={s} className={`${i <= stepOn ? 'is-on' : ''} ${i === stepOn ? 'is-current' : ''}`}>{s}</li>
            ))}
          </ol>

          {(phase.kind === 'ask' || phase.kind === 'checking') && (
            <>
              <p className="eyebrow">
                Question {Math.max(1, openItems.indexOf(itemOf(current)) + 1)} of {Math.max(1, openItems.length)}
                {labels.length > 1 && ` · ${labels[current.item.config_index]}`}
              </p>
              <h2 className="teach-title" id="teach-title">We don’t recognize this configuration yet</h2>
              <p className="muted">NetAuditAI found a line it hasn’t learned. Nothing about it is counted until you answer.</p>
              <Evidence lineNumbers={[current.line.line_number]} lines={[current.line.text]} />
              {say(current) && <p className="teach-guess">We think this line {say(current)}.</p>}
              <fieldset className="choices" disabled={phase.kind === 'checking'}>
                <legend>What does this line do?</legend>
                {options.map((o) => (
                  <label key={o.value} className={`choice ${choice === o.value ? 'is-checked' : ''}`}>
                    <input type="radio" name="teach-choice" value={o.value} checked={choice === o.value} onChange={() => setChoice(o.value)} />
                    <span>{o.text}</span>
                  </label>
                ))}
              </fieldset>
              <p className="small muted">When you continue, NetAuditAI checks that this meaning really matches the line before it saves anything.</p>
              <div className="actions">
                <button type="button" className="btn btn-primary" onClick={submit} disabled={!choice || phase.kind === 'checking'}>
                  {phase.kind === 'checking' ? 'Checking…' : 'Continue'}
                </button>
              </div>
              <Toggle label="Advanced details">
                {() => <AdvancedDraft key={current.key} scanId={scanId} q={current} edits={edits} setEdits={setEdits} />}
              </Toggle>
            </>
          )}

          {phase.kind === 'failed' && (
            <div className="teach-result is-failed" role="alert">
              <h2 className="teach-title" id="teach-title">NetAuditAI couldn’t safely save this rule.</h2>
              <p>{explainGate(phase.message)}</p>
              <Evidence lineNumbers={[current.line.line_number]} lines={[current.line.text]} />
              <div className="actions">
                <button type="button" className="btn btn-primary" onClick={() => setPhase({ kind: 'ask' })}>Try again</button>
                <button type="button" className="btn" onClick={() => { setPhase({ kind: 'ask' }); resetAnswer(); }}>Cancel</button>
              </div>
              <Toggle label="Advanced details">{() => <p className="small mono">{phase.message}</p>}</Toggle>
            </div>
          )}

          {phase.kind === 'learned' && (
            <div className="teach-result is-learned" role="status">
              <p className="learned-mark" aria-hidden="true">✓</p>
              <h2 className="teach-title" id="teach-title">NetAuditAI learned this</h2>
              <p>This configuration pattern will be recognized on future scans.</p>
              <Evidence lineNumbers={[phase.target.line.line_number]} lines={[phase.target.line.text]} />
              {say(phase.target) && <p>It {say(phase.target)}.</p>}
              <p className="small muted">
                {phase.saved.replay.length > 0
                  ? `It updated ${phase.saved.replay.length} result${phase.saved.replay.length === 1 ? '' : 's'} in the scans NetAuditAI holds.`
                  : 'No result changed in this scan.'}
              </p>
              <div className="actions">{continueButton}</div>
              <Toggle label="Advanced details">
                {() => (
                  <dl className="kv">
                    <dt>Saved rule</dt><dd className="mono">#{phase.saved.mapping.id}</dd>
                    {phase.saved.mapping.command_pattern && <><dt>Template</dt><dd className="mono">{phase.saved.mapping.command_pattern}</dd></>}
                    <dt>Replay</dt>
                    <dd className="mono">{phase.saved.replay.map((c) => `${c.hostname} · ${c.control_id}: ${c.before} → ${c.after}`).join('; ') || 'no change'}</dd>
                  </dl>
                )}
              </Toggle>
            </div>
          )}

          {phase.kind === 'rejected' && (
            <div className="teach-result" role="status">
              <h2 className="teach-title" id="teach-title">Got it.</h2>
              <p>NetAuditAI will stop guessing about line {current.line.line_number}. It stays uncounted.</p>
              <div className="actions">{continueButton}</div>
            </div>
          )}
        </article>
      )}

      {items != null && (
        <LegacyInterpretations scan={scan} onScanUpdated={onScanUpdated} onScanExpired={onScanExpired} />
      )}

    </div>
  );
}
