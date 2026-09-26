import { useState } from 'react';

// Three steps for someone's first scan, closed for good with one click. Remembered in this browser only; if
// storage is blocked the card simply shows again next time.
const KEY = 'netauditai.firstRunTips.dismissed';

const TIPS = [
  ['Read your score', 'The big number is how secure this configuration is, from 0 to 100. Each problem below says why it matters.'],
  ['Fix the problems', 'Open Remediation. Some fixes are automatic; for others NetAuditAI asks you for a value or a command.'],
  ['Download and rescan', 'Download the corrected file, apply it to the device yourself, then scan the device again to confirm.'],
];

function dismissed() {
  try {
    return localStorage.getItem(KEY) === '1';
  } catch {
    return false;
  }
}

export default function FirstRunTips() {
  const [hidden, setHidden] = useState(dismissed);
  if (hidden) return null;
  const close = () => {
    try {
      localStorage.setItem(KEY, '1');
    } catch {
      // storage blocked: it just shows again next time
    }
    setHidden(true);
  };
  return (
    <section className="first-run" aria-labelledby="first-run-title">
      <h2 className="section-title" id="first-run-title">New here? Three steps</h2>
      <ol className="first-run-steps">
        {TIPS.map(([title, body]) => <li key={title}><strong>{title}.</strong> {body}</li>)}
      </ol>
      <button type="button" className="btn btn-sm" onClick={close}>Got it</button>
    </section>
  );
}
