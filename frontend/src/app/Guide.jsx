import { useState } from 'react';
import { Notice } from '../components/ui/primitives';
import { auditCounts } from '../lib/domain';
import Teach from './Teach';

// The guided path: upload → answer the questions → download the fixed file. It owns no logic of its own -
// every number, fix and download comes from the same audit state the expert pages read, so the two can
// never disagree. Its only job is to show one step at a time in plain words.

const STEPS = ['Upload your file', 'Answer the questions', 'Download the fixed file'];

function Steps({ current }) {
  return (
    <div className="wrap">
      <ol className="steps-inline" aria-label="Where you are">
        {STEPS.map((label, i) => (
          <li key={label} className={i === current ? 'is-current' : undefined}
              aria-current={i === current ? 'step' : undefined}>
            <span className="mono">{String(i + 1).padStart(2, '0')}</span> {label}
          </li>
        ))}
      </ol>
    </div>
  );
}

function Finish({ audit, counts, base, questions, onAnswer }) {
  const [downloading, setDownloading] = useState(false);
  const [downloaded, setDownloaded] = useState(false);
  const [error, setError] = useState(null);

  const devices = audit.plan?.devices || [];
  const fixedCount = devices.reduce((sum, d) => sum + d.fixed_controls.length, 0);
  const downloadable = devices.some((d) => d.fixed_config);
  // Problems the engine will not change for you: they need a person, here or on the device.
  const byHand = counts.problems - fixedCount;

  const download = async () => {
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

  if (audit.planError) {
    return (
      <div className="wrap">
        <Notice kind="danger" label="We couldn’t prepare the fixes." role="alert"
                action={<button type="button" className="btn btn-sm btn-quiet" onClick={() => audit.loadPlan()}>Try again</button>}>
          <p>{audit.planError}</p>
        </Notice>
      </div>
    );
  }

  if (!audit.plan) {
    return (
      <div className="wrap loading-block" aria-busy="true">
        <div className="scan-bar" aria-hidden="true"><span /></div>
        <p className="muted">Fixing what we can and rescanning to check each change…</p>
      </div>
    );
  }

  return (
    <div className="wrap enter">
      <header className="page-head">
        <p className="eyebrow">Step 3 of 3</p>
        <h1 className="display page-title">
          {fixedCount > 0 ? 'Your fixed file is ready.' : counts.problems === 0 ? 'Nothing needed fixing.' : 'We can’t fix these for you.'}
        </h1>
        <p className="lede">
          {fixedCount > 0
            ? `We corrected ${fixedCount} problem${fixedCount === 1 ? '' : 's'} in a copy of your file and re-scanned that copy to check every change. Your original file was not touched.`
            : counts.problems === 0
              ? 'We found no security problem we could decide from this configuration.'
              : 'Every problem we found needs a person to decide the change. We show you exactly what to change.'}
        </p>
      </header>

      {error && <Notice kind="danger" label="Download failed." role="alert"><p>{error}</p></Notice>}

      {downloadable && (
        <div className="actions">
          <button type="button" className="btn btn-accent btn-lg" onClick={download} disabled={downloading}>
            {downloading ? 'Preparing…' : 'Download my fixed file'}
          </button>
        </div>
      )}

      {downloaded && (
        <Notice label="Saved to your downloads." role="status" action={<a className="btn btn-sm btn-quiet" href="#/app">Scan the fixed file</a>}>
          <p>Read it before you put it on a device. To double-check our work, scan the fixed file as a new upload.</p>
        </Notice>
      )}

      <ul className="fixmix">
        <li className="tone-pass"><b className="tnum">{fixedCount}</b> fixed and re-checked for you</li>
        {byHand > 0 && <li className="tone-manual"><b className="tnum">{byHand}</b> need a change only you can decide</li>}
        {questions > 0 && <li className="tone-input"><b className="tnum">{questions}</b> question{questions === 1 ? '' : 's'} left unanswered</li>}
      </ul>

      <div className="actions">
        {byHand > 0 && <a className="btn" href={`#${base}/fix`}>Show me what to change by hand</a>}
        {questions > 0 && <button type="button" className="btn btn-quiet" onClick={onAnswer}>Go back to the questions</button>}
        <a className="btn btn-quiet" href={`#${base}`}>See the full report</a>
      </div>
    </div>
  );
}

export default function Guide({ scan, audit, base, onScanUpdated, onScanExpired }) {
  const counts = auditCounts(scan, audit.plan, audit.applied, audit.queue);
  const questions = (counts.resolvable ?? 0) + (counts.review ?? 0);
  // Answering is optional: skipping goes straight to the fixed file, and coming back re-opens the questions.
  const [skipped, setSkipped] = useState(false);
  const asking = questions > 0 && !skipped;

  return (
    <div className="guide">
      <Steps current={asking ? 1 : 2} />
      {asking ? (
        <>
          <div className="wrap">
            <Notice label={`Step 2 of 3 · ${questions} question${questions === 1 ? '' : 's'}`}
                    action={<button type="button" className="btn btn-sm btn-quiet" onClick={() => setSkipped(true)}>Skip to my fixed file</button>}>
              <p>
                Your file uses wording we don’t recognize yet. Each question shows you one line from your own
                file and asks what it means. Answer what you know -we check your answer against the line before
                we believe it, and we remember it for next time.
              </p>
            </Notice>
          </div>
          <Teach scan={scan} audit={audit} focusKey={null} onScanUpdated={onScanUpdated} onScanExpired={onScanExpired} />
        </>
      ) : (
        <Finish audit={audit} counts={counts} base={base} questions={questions}
                onAnswer={() => setSkipped(false)} />
      )}
    </div>
  );
}
