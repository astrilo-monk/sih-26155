import { useEffect, useMemo, useState } from 'react';
import { apiClient } from '../api/client';
import { Evidence } from '../components/ui/Evidence';
import { deviceLabels, explainGate, sayFact, sayMeaning, statusState, vendorName } from '../lib/domain';
import { UnresolvedDetail } from './Unresolved';
import LegacyInterpretations from './LegacyInterpretations';

// Teach NetAuditAI: a person shows it which line of their own configuration answers a check it could not
// decide, and says what that line means. Underneath, the answer drafts a recognizer, the backend checks its
// safety gates and replays it, and only then saves it — nothing is counted before that, and nothing here can
// bypass those checks. The uploaded configuration is only ever read. The technical draft stays under Advanced.

const STEPS = ['The check', 'The line', 'Your answer', 'Learned'];
const fmtValue = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
const itemKey = (item) => `${item.config_index}-${item.control_id}`;
const meaningKey = (m) => `${m.predicate}|${m.subject ?? ''}|${JSON.stringify(m.value ?? null)}`;

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
function AdvancedDraft({ scanId, base, item, line, edits, setEdits }) {
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState(null);

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
        <dt>Check</dt><dd><span className="mono">{item.control_id}</span> {item.question}</dd>
        <dt>Current result</dt><dd>{item.status} — {item.reason}</dd>
        <dt>Line</dt><dd className="mono">{line.line_number}: {line.text}</dd>
        {line.predicate && <><dt>Our reading</dt><dd className="mono">{line.predicate}{line.subject ? ` · ${line.subject}` : ''} = {fmtValue(line.value)}</dd></>}
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

// Pick any line of the uploaded configuration. Only tokenizer statements can be taught from; the rest are
// shown so the file reads as the file, but cannot be chosen.
function ConfigPicker({ scanId, configIndex, chosen, onPick }) {
  const [body, setBody] = useState(null);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    let active = true;
    apiClient.getConfigLines(scanId, configIndex)
      .then((result) => { if (active) setBody(result); })
      .catch((err) => { if (active) setError(err.message); });
    return () => { active = false; };
  }, [scanId, configIndex]);

  if (error) return <p className="field-error" role="alert">The configuration couldn’t be loaded: {error}</p>;
  if (!body) return <p className="muted" aria-busy="true">Loading the configuration…</p>;

  const needle = filter.trim().toLowerCase();
  const lines = needle ? body.lines.filter((l) => l.text.toLowerCase().includes(needle)) : body.lines;

  return (
    <div className="config-picker">
      <label className="field">
        <span className="field-label">Find a line</span>
        <input className="input" type="search" value={filter} placeholder="e.g. source-address"
          aria-label="Find a line" onChange={(e) => setFilter(e.target.value)} />
      </label>
      <ol className="config-lines" aria-label="Uploaded configuration">
        {lines.map((line) => (
          <li key={line.line_number} className={chosen === line.line_number ? 'is-chosen' : ''}>
            <button type="button" className="config-line" disabled={!line.teachable}
              aria-pressed={chosen === line.line_number} onClick={() => onPick(line.line_number)}>
              <span className="config-n tnum">{line.line_number}</span>
              <code>{line.text || ' '}</code>
            </button>
          </li>
        ))}
      </ol>
      {lines.length === 0 && <p className="muted">No line matches “{filter}”.</p>}
    </div>
  );
}

export default function Teach({ scan, audit, focusKey, onScanUpdated, onScanExpired }) {
  const scanId = scan.scan_id;
  const labels = deviceLabels(scan.devices);
  const unresolved = audit.queue?.unresolved;
  const open = useMemo(() => (unresolved || []).filter((i) => i.action === 'teach'), [unresolved]);

  const [skipped, setSkipped] = useState(() => new Set());
  const [focus, setFocus] = useState(focusKey || null);
  const [phase, setPhase] = useState({ kind: 'ask' });
  const [line, setLine] = useState(null);
  const [choice, setChoice] = useState('');
  const [edits, setEdits] = useState(null);
  const [options, setOptions] = useState(null);
  const [optionsError, setOptionsError] = useState(null);
  const [picking, setPicking] = useState(false);

  const queue = open.filter((i) => !skipped.has(itemKey(i)));
  // Once answered, the check stays on screen (the queue refreshes underneath) until the person continues
  const item = phase.item || queue.find((i) => itemKey(i) === focus) || queue[0] || null;
  const key = item ? itemKey(item) : null;
  const allConfirmed = (scan.vendor_identification || []).length > 0 && scan.vendor_identification.every((v) => v.status === 'confirmed');

  // A new check starts with its best suggested line and no answer
  useEffect(() => {
    if (phase.kind !== 'ask') return;
    setLine(item?.suggested_lines?.[0]?.line_number ?? null);
    setChoice('');
    setEdits(null);
    setPicking(!item?.suggested_lines?.length);
  }, [key, phase.kind]);

  // What this line may mean for this check — the backend decides, from the check's own settings
  useEffect(() => {
    if (!item || line == null) {
      setOptions(null);
      return undefined;
    }
    let active = true;
    setOptions(null);
    setOptionsError(null);
    apiClient.getMeaningOptions(scanId, { controlId: item.control_id, lineNumber: line, configIndex: item.config_index })
      .then((body) => { if (active) setOptions(body.options); })
      .catch((err) => { if (active) setOptionsError(err.message); });
    return () => { active = false; };
  }, [scanId, key, line]);

  const chosenLine = item?.suggested_lines?.find((l) => l.line_number === line)
    || (line != null ? { line_number: line, text: '', predicate: null } : null);

  const next = () => {
    setFocus(null);
    setPhase({ kind: 'ask' });
  };

  const scanGone = (err) => {
    if (err.status === 404 && /scan/i.test(err.message)) {
      onScanExpired?.(scanId);
      return true;
    }
    return false;
  };

  const submit = async () => {
    if (choice === 'skip') {
      setSkipped((s) => new Set(s).add(key));
      next();
      return;
    }
    const meaning = (options || []).find((o) => meaningKey(o) === choice);
    setPhase({ kind: 'checking', item });
    try {
      if (choice === 'reject') {
        const updated = await apiClient.rejectProvisionalLine(scanId, {
          config_index: item.config_index, control_id: item.control_id, line_number: line,
        });
        onScanUpdated?.(updated);
        setPhase({ kind: 'rejected', item, line: chosenLine });
        return;
      }
      const request = {
        config_index: item.config_index,
        control_id: item.control_id,
        line_number: line,
        predicate: meaning.predicate,
        asserted_value: meaning.value,
        subject: meaning.subject,
        ...(edits || {}),
      };
      // the backend drafts, runs its safety checks and replays; only a clean draft is saved
      const draft = await apiClient.draftRecognizer(scanId, request);
      if (draft.errors.length > 0) {
        setPhase({ kind: 'failed', item, line: chosenLine, message: draft.errors[0] });
        return;
      }
      const saved = await apiClient.saveRecognizer(scanId, request);
      onScanUpdated?.(saved.scan);
      setPhase({ kind: 'learned', item, line: chosenLine, meaning, saved, before: scan });
    } catch (err) {
      if (!scanGone(err)) setPhase({ kind: 'failed', item, line: chosenLine, message: err.message });
    }
  };

  const stepOn = { ask: line == null ? 0 : choice ? 2 : 1, checking: 2, failed: 2, rejected: 2, learned: 3 }[phase.kind];
  const moreAfter = phase.item && queue.some((i) => itemKey(i) !== itemKey(phase.item));
  const continueButton = (
    <button type="button" className="btn btn-primary" onClick={next}>{moreAfter ? 'Continue to the next check' : 'Continue'}</button>
  );
  const base = item && line != null ? { config_index: item.config_index, control_id: item.control_id, line_number: line } : null;

  return (
    <div className="wrap teach enter">
      <header className="page-head">
        <p className="eyebrow">Teach NetAuditAI</p>
        <h1 className="page-title">Finish this assessment</h1>
        <p className="lede">
          NetAuditAI could not decide some checks from this configuration alone. Show it which line answers one and
          say what that line means. It checks your answer against the line, re-checks the same configuration, and
          remembers the meaning for future scans. Your file is never changed.
        </p>
      </header>

      {audit.queueError && (
        <div className="notice notice-danger" role="alert">
          <span className="notice-mark">×</span><strong>The unresolved checks couldn’t be loaded.</strong><span>{audit.queueError}</span>
          <button type="button" className="btn btn-sm notice-action" onClick={audit.loadQueue}>Try again</button>
        </div>
      )}

      {unresolved == null && !audit.queueError && <p className="muted" aria-busy="true">Loading the checks that need you…</p>}

      {unresolved != null && !item && (
        <div className="empty-state tone-pass">
          <p className="empty-mark" aria-hidden="true">✓</p>
          <h2 className="empty-title">{skipped.size > 0 ? 'No more checks for now.' : 'Nothing is waiting for your input.'}</h2>
          <p>
            {allConfirmed
              ? `NetAuditAI read this configuration with its dedicated ${vendorName(scan.vendor_identification[0].detected_vendor)} parser, so there is nothing to teach.`
              : skipped.size > 0
                ? `You skipped ${skipped.size} check${skipped.size === 1 ? '' : 's'}. Skipped checks stay undecided and uncounted.`
                : 'Every check NetAuditAI could decide is decided. Anything still undecided is shown on Results with the reason.'}
          </p>
          <div className="actions">
            {skipped.size > 0 && <button type="button" className="btn" onClick={() => setSkipped(new Set())}>Review skipped checks</button>}
            <a className="btn btn-primary" href={`#/app/scan/${scanId}`}>Back to results</a>
          </div>
        </div>
      )}

      {item && (
        <article className={`teach-card phase-${phase.kind}`} aria-labelledby="teach-title">
          <ol className="teach-steps" aria-label="Progress">
            {STEPS.map((s, i) => (
              <li key={s} className={`${i <= stepOn ? 'is-on' : ''} ${i === stepOn ? 'is-current' : ''}`}>{s}</li>
            ))}
          </ol>

          {(phase.kind === 'ask' || phase.kind === 'checking') && (
            <>
              <p className="eyebrow">
                Check {Math.max(1, queue.findIndex((i) => itemKey(i) === key) + 1)} of {Math.max(1, queue.length)}
                {labels.length > 1 && ` · ${labels[item.config_index]}`}
              </p>
              <h2 className="teach-title" id="teach-title">{item.question}</h2>
              <p className="teach-status">
                <span className={`state-chip tone-${statusState(item.status) === 'not_configured' ? 'nc' : 'unknown'}`}>
                  {item.status === 'not_configured' ? 'Not configured' : 'Not enough information'}
                </span>
                {item.reason}
              </p>

              <fieldset className="choices" disabled={phase.kind === 'checking'}>
                <legend>Which line of your configuration answers this?</legend>
                {(item.suggested_lines || []).length > 0 && !picking && (
                  <ul className="teach-lines">
                    {item.suggested_lines.map((l) => (
                      <li key={l.line_number}>
                        <label className={`choice ${line === l.line_number ? 'is-checked' : ''}`}>
                          <input type="radio" name="teach-line" checked={line === l.line_number}
                            onChange={() => { setLine(l.line_number); setChoice(''); setEdits(null); }} />
                          <span>
                            <code className="mono">{l.line_number}: {l.text}</code>
                            {l.scope_path?.length > 0 && <span className="small muted"> in {l.scope_path.join(' › ')}</span>}
                            {sayFact(l) && <span className="teach-guess"> We think it {sayFact(l)}.</span>}
                          </span>
                        </label>
                      </li>
                    ))}
                  </ul>
                )}
                <button type="button" className="btn btn-sm" onClick={() => setPicking((v) => !v)}>
                  {picking ? 'Back to the suggested lines' : 'Show the whole configuration'}
                </button>
                {picking && (
                  <ConfigPicker scanId={scanId} configIndex={item.config_index} chosen={line}
                    onPick={(n) => { setLine(n); setChoice(''); setEdits(null); }} />
                )}
              </fieldset>

              {line != null && (
                <>
                  <Evidence lineNumbers={[line]} lines={[chosenLine.text]} title="The line you chose" />
                  {optionsError && <p className="field-error" role="alert">{optionsError}</p>}
                  {options == null && !optionsError && <p className="muted" aria-busy="true">Loading what this line could mean…</p>}
                  {options && (
                    <fieldset className="choices" disabled={phase.kind === 'checking'}>
                      <legend>What does this line say about this check?</legend>
                      {options.map((o) => (
                        <label key={meaningKey(o)} className={`choice ${choice === meaningKey(o) ? 'is-checked' : ''}`}>
                          <input type="radio" name="teach-meaning" value={meaningKey(o)}
                            checked={choice === meaningKey(o)} onChange={() => setChoice(meaningKey(o))} />
                          <span>It {sayMeaning(o) || `answers “${item.question}”`}</span>
                        </label>
                      ))}
                      {chosenLine.predicate && (
                        <label className={`choice ${choice === 'reject' ? 'is-checked' : ''}`}>
                          <input type="radio" name="teach-meaning" value="reject" checked={choice === 'reject'} onChange={() => setChoice('reject')} />
                          <span>Something else — NetAuditAI misread this line</span>
                        </label>
                      )}
                      <label className={`choice ${choice === 'skip' ? 'is-checked' : ''}`}>
                        <input type="radio" name="teach-meaning" value="skip" checked={choice === 'skip'} onChange={() => setChoice('skip')} />
                        <span>I’m not sure — skip this check for now</span>
                      </label>
                    </fieldset>
                  )}
                </>
              )}

              <p className="small muted">
                When you continue, NetAuditAI checks that this meaning really is stated on that line before it saves
                anything. A line that doesn’t say it can’t teach it.
              </p>
              <div className="actions">
                <button type="button" className="btn btn-primary" onClick={submit} disabled={!choice || phase.kind === 'checking'}>
                  {phase.kind === 'checking' ? 'Checking…' : 'Continue'}
                </button>
              </div>
              <Toggle label="Why this check is undecided">{() => <UnresolvedDetail item={item} />}</Toggle>
              {base && (
                <Toggle label="Advanced details">
                  {() => <AdvancedDraft key={`${key}-${line}`} scanId={scanId} base={base} item={item} line={chosenLine} edits={edits} setEdits={setEdits} />}
                </Toggle>
              )}
            </>
          )}

          {phase.kind === 'failed' && (
            <div className="teach-result is-failed" role="alert">
              <h2 className="teach-title" id="teach-title">NetAuditAI couldn’t safely save this.</h2>
              <p>{explainGate(phase.message)}</p>
              <Evidence lineNumbers={[phase.line.line_number]} lines={[phase.line.text]} />
              <p className="small muted">The check stays undecided. It is never counted as passed or failed.</p>
              <div className="actions">
                <button type="button" className="btn btn-primary" onClick={() => setPhase({ kind: 'ask' })}>Try another line</button>
                {continueButton}
              </div>
              <Toggle label="Advanced details">{() => <p className="small mono">{phase.message}</p>}</Toggle>
            </div>
          )}

          {phase.kind === 'learned' && (() => {
            const after = phase.saved.scan;
            const result = (after.results || []).find((r) => r.control_id === phase.item.control_id
              && (r.config_index ?? 0) === phase.item.config_index);
            const decided = ['pass', 'fail'].includes(result?.status);
            return (
              <div className="teach-result is-learned" role="status">
                <p className="learned-mark" aria-hidden="true">✓</p>
                <h2 className="teach-title" id="teach-title">NetAuditAI learned this</h2>
                <Evidence lineNumbers={[phase.line.line_number]} lines={[phase.line.text]} />
                <p>It {sayMeaning(phase.meaning) || 'answers this check'}. This pattern will be recognized on future scans.</p>
                {decided ? (
                  <>
                    <p className="teach-decided">
                      <span className="mono">{phase.item.control_id}</span> is now{' '}
                      <strong className={`tone-${result.status === 'pass' ? 'pass' : 'fail'}`}>{result.status === 'pass' ? 'Passed' : 'Failed'}</strong>
                      {' '}— {result.reason}
                    </p>
                    <ul className="fixmix">
                      <li className="tone-pass"><b className="tnum">{after.posture ?? '—'}</b> security posture <span className="muted">(was {phase.before.posture ?? '—'})</span></li>
                      <li className="tone-pass"><b className="tnum">{after.coverage}%</b> checked <span className="muted">(was {phase.before.coverage}%)</span></li>
                      <li className="tone-input"><b className="tnum">{after.unresolved_count}</b> still need input <span className="muted">(was {phase.before.unresolved_count})</span></li>
                    </ul>
                  </>
                ) : (
                  <p className="teach-decided">
                    <span className="mono">{phase.item.control_id}</span> is still undecided: what this line says isn’t
                    enough on its own to answer the check. Nothing was counted.
                  </p>
                )}
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
            );
          })()}

          {phase.kind === 'rejected' && (
            <div className="teach-result" role="status">
              <h2 className="teach-title" id="teach-title">Got it.</h2>
              <p>NetAuditAI will stop guessing about line {phase.line.line_number}. The check stays undecided and uncounted.</p>
              <div className="actions">{continueButton}</div>
            </div>
          )}
        </article>
      )}

      {unresolved != null && (
        <LegacyInterpretations scan={scan} onScanUpdated={onScanUpdated} onScanExpired={onScanExpired} />
      )}

    </div>
  );
}
