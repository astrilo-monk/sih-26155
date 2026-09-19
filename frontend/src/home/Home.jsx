import { useState } from 'react';
import FileDiff from '../components/ui/FileDiff';
import { Severity, StatusMark } from '../components/ui/Evidence';
import { assessment, statusState } from '../lib/domain';
import { motionAllowed, prefersReducedMotion, useInView, useReveal, useScrollProgress, useSequence } from '../lib/hooks';
import '../styles/home.css';

// Every specimen on this page is real backend output for the repository's sample configurations, with secrets
// exactly as the backend redacts them. The animations replay those recorded states in order — they never
// suggest a scan is running.
const SAMPLE = 'sample/cisco/01_cisco_multi_vulnerability.cfg';

const HERO_LINES = [
  [11, 'line vty 0 4'],
  [12, ' login'],
  [13, ' password <SECRET:password>'],
  [14, ' transport input telnet ssh', true],
  [15, ' exec-timeout 0 0'],
];
const HERO_DIFF = '@@ -14,1 +14,1 @@\n- transport input telnet ssh\n+ transport input ssh';
const FIX_DIFF = '--- before\n+++ after\n@@ -12,5 +12,5 @@\n  login\n  password <SECRET:password>\n- transport input telnet ssh\n+ transport input ssh\n  exec-timeout 0 0\n !';
const RESCAN_CHECKS = [
  ['Vendor', 'Still confirmed as cisco_ios'],
  ['Parse coverage', 'Parse coverage 100% → 100%, lines outside the grammar 0 → 0'],
  ['Target control', 'MGMT-001 now passes: Telnet is not allowed for remote management'],
  ['No regression', 'No other control got worse'],
];

const NAV = [
  ['how', 'How it works'],
  ['evidence', 'Evidence'],
  ['adaptive', 'Adaptive learning'],
  ['remediation', 'Remediation'],
  ['frameworks', 'Frameworks'],
];

const DIALECTS = [
  { platform: 'Cisco IOS', line: 'transport input telnet ssh', source: SAMPLE, path: 'Dedicated parser' },
  { platform: 'FortiGate', line: 'set allowaccess ping https ssh http telnet', source: 'sample/frontinet/04_fortigate_vulnerable.cfg', path: 'Dedicated parser' },
  { platform: 'PAN-OS style', line: 'set deviceconfig system service disable-telnet no', source: 'sample/paloalto.cfg', path: 'Generic analysis' },
  { platform: 'Unfamiliar dialect', line: 'remote-console protocol telnet', source: 'sample/unknown.cfg', path: 'Generic analysis' },
];

const PIPELINE = [
  ['Config', 'The exported configuration is ingested and its secrets are redacted before anything else reads it.', 'ingest · redaction'],
  ['Understand', 'The platform is identified deterministically and parse coverage measured. Unfamiliar files are tokenized generically.', 'vendor identification · coverage'],
  ['Evaluate', 'Security facts are extracted and every control runs against every configuration.', 'security facts · controls'],
  ['Prove', 'Each result carries its cited lines and an assurance level. Undecidable semantics stay Unknown or go to a person.', 'evidence · assurance'],
  ['Fix', 'A deterministic recipe changes failing settings only — and only for a confirmed vendor.', 'recipes · diff'],
  ['Verify', 'The fixed file is re-parsed and every control re-run: the target must pass and nothing else may get worse.', 'rescan checks'],
];

const STATUSES = [
  ['fail', 'Validated evidence shows the control is violated.'],
  ['pass', 'Validated evidence shows the control is satisfied.'],
  ['unknown', 'Statements exist, but none could decide the control. Shown, never scored.'],
  ['not_configured', 'Nothing in the file states the setting. Never silently treated as a pass.'],
];

const ASSURANCE_LADDER = [
  ['Parser evidence', 'A dedicated parser read the line', true],
  ['Confirmed recognizer', 'A rule an administrator confirmed', true],
  ['Documented default', 'The platform’s documented behaviour', true],
  ['Heuristic reading', 'A wording match on unfamiliar syntax', false],
  ['AI proposal', 'A cited reading whose quote was verified', false],
];

const SUPPORT = [
  ['Vendor identification', 'Deterministic, confirmed', 'Deterministic, confirmed', 'Reported as unknown or unverified — never guessed'],
  ['Reading the file', 'Dedicated parser', 'Dedicated parser', 'Generic structure analysis'],
  ['Decisive results', 'Parser evidence and documented defaults', 'Parser evidence and documented defaults', 'Human-confirmed recognizers only'],
  ['AI escalation', 'Not used', 'Not used', 'Bounded, for undecided controls; always provisional'],
  ['Remediation', 'Deterministic recipes, verified by rescan', 'Deterministic recipes, verified by rescan', 'Blocked until a vendor is confirmed'],
];

const FORTI = { posture: 4, coverage: 82, critical: ['MGMT-005'] };
const UNFAMILIAR = { posture: null, coverage: 0, critical: [] };

// "is-on" once the sequence has reached a stage; "is-current" for the stage just reached
const stageClass = (on, i) => `${on > i ? 'is-on' : ''} ${on === i + 1 ? 'is-current' : ''}`;

function Brand() {
  return (
    <a className="brand" href="#/" aria-label="NetAuditAI home">
      <span className="brand-mark" aria-hidden="true"><span /></span>
      <span className="brand-name">NetAudit<span>AI</span></span>
    </a>
  );
}

function SectionHead({ no, id, title, children }) {
  return (
    <header className="hsec-head reveal">
      <span className="sec-no">{no}</span>
      <div>
        <h2 className="display hsec-title" id={id}>{title}</h2>
        {children && <p className="lede">{children}</p>}
      </div>
    </header>
  );
}

function ReplayButton({ done, onReplay }) {
  if (!motionAllowed()) return null;
  return (
    <button type="button" className="btn-link small replay-btn" onClick={onReplay} disabled={!done}>
      Replay
    </button>
  );
}

// Config → security fact → control → FAIL → deterministic fix → rescan → PASS, replayed from one real scan
function EvidenceChain() {
  const [on, replay] = useSequence(6, { stepMs: 620, startDelay: 350 });
  return (
    <figure className={`chain ${on >= 6 ? 'is-done' : ''}`} aria-labelledby="chain-caption">
      <ol className="chain-steps">
        <li className={`chain-step ${stageClass(on, 0)}`}>
          <div className="chain-label"><span className="sec-no">01</span> Configuration</div>
          <div className="evidence compact">
            <div className="evidence-body">
              {HERO_LINES.map(([n, text, cited]) => (
                <div key={n} className={`ev-row ${cited ? 'cited' : 'context'}`}>
                  <span className="ln">{n}</span><code>{text}</code>
                </div>
              ))}
            </div>
          </div>
        </li>
        <li className={`chain-step ${stageClass(on, 1)}`}>
          <div className="chain-label"><span className="sec-no">02</span> Security fact</div>
          <p className="fact mono">
            <span className="fact-pred">mgmt.remote_access.protocol_enabled</span>
            <span className="fact-subj"> · telnet</span> <span className="fact-eq">=</span> <span className="fact-val">true</span>
          </p>
          <p className="chain-note">scope <span className="mono">line vty 0 4</span> · Cisco IOS parser</p>
        </li>
        <li className={`chain-step ${stageClass(on, 2)}`}>
          <div className="chain-label"><span className="sec-no">03</span> Control</div>
          <p className="chain-control"><span className="mono">MGMT-001</span> Is cleartext Telnet disabled for remote management? <Severity level="critical" /></p>
        </li>
        <li className={`chain-step chain-verdict ${stageClass(on, 3)}`}>
          <div className="chain-label"><span className="sec-no">04</span> Result</div>
          <div className="chain-row"><StatusMark state="problem" size="lg" /><span className="tag tag-pass">Parser evidence · line 14</span></div>
        </li>
        <li className={`chain-step ${stageClass(on, 4)}`}>
          <div className="chain-label"><span className="sec-no">05</span> Deterministic fix</div>
          <FileDiff diff={HERO_DIFF} file="DMZ-EDGE-10" caption="recipe for MGMT-001" />
        </li>
        <li className={`chain-step chain-verdict ${stageClass(on, 5)}`}>
          <div className="chain-label"><span className="sec-no">06</span> Rescan</div>
          <div className="chain-row"><StatusMark state="pass" size="lg" /><span className="chain-note">MGMT-001 now passes</span></div>
          <ul className="chain-checks" aria-label="Verification checks">
            {RESCAN_CHECKS.map(([name], i) => (
              <li key={name} style={{ '--c': i }}>
                <span className="check-mark" aria-hidden="true">✓</span>
                <span className="visually-hidden">Passed: </span>{name}
              </li>
            ))}
          </ul>
        </li>
      </ol>
      <figcaption id="chain-caption" className="chain-caption">
        <span>
          Recorded output for <span className="mono">{SAMPLE}</span>, replayed step by step. The password on line 13 is
          redacted by the backend before it reaches the browser.
        </span>
        <ReplayButton done={on >= 6} onReplay={replay} />
      </figcaption>
    </figure>
  );
}

// Stage progression follows the reader's scroll through the section
function Pipeline() {
  const [ref, progress] = useScrollProgress();
  const reached = Math.min(PIPELINE.length, Math.floor(progress * PIPELINE.length + 0.35));
  return (
    <div className="pipeline-wrap" ref={ref}>
      <div className="pipe-rail" aria-hidden="true"><span style={{ transform: `scaleX(${progress})` }} /></div>
      <ol className="pipeline">
        {PIPELINE.map(([name, text, tech], i) => (
          <li key={name} className={`pipe-step ${i < reached ? 'is-on' : ''} ${i === reached - 1 ? 'is-current' : ''}`}>
            <span className="pipe-no mono">{String(i + 1).padStart(2, '0')}</span>
            <h3 className="pipe-name">{name}</h3>
            <p>{text}</p>
            <span className="pipe-tech mono">{tech}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

// Unknown line → provisional reading → human confirmation → recognizer → recognized on the next scan
function LearningLoop() {
  const [ref, seen] = useInView(0.3);
  const [on, replay] = useSequence(5, { stepMs: 760, startDelay: 150, active: seen });
  const confirmed = on >= 4;
  return (
    <div className="learn-wrap" ref={ref}>
      <div className="pipe-rail" aria-hidden="true"><span style={{ transform: `scaleX(${on / 5})` }} /></div>
      <ol className="learn">
        <li className={`learn-step ${stageClass(on, 0)}`}>
          <span className="learn-no mono">A</span>
          <h3>Unknown line</h3>
          <figure className="evidence compact"><div className="evidence-body">
            <div className="ev-row cited"><span className="ln">71</span><code>remote-console protocol telnet</code></div>
          </div></figure>
          <p className="small muted">sample/unknown.cfg — no vendor could be confirmed.</p>
        </li>
        <li className={`learn-step ${stageClass(on, 1)}`}>
          <span className="learn-no mono">B</span>
          <h3>Provisional reading</h3>
          <p className="fact mono"><span className="fact-pred">mgmt.remote_access.protocol_enabled</span><span className="fact-subj"> · telnet</span> <span className="fact-eq">=</span> <span className="fact-val">true</span></p>
          <p className="small"><span className="tag tag-review">Suspected fail · not counted</span></p>
        </li>
        <li className={`learn-step ${stageClass(on, 2)}`}>
          <span className="learn-no mono">C</span>
          <h3>Human confirmation</h3>
          <p>Does line 71 establish this for <span className="mono">MGMT-001</span>?</p>
          <div className="learn-buttons" aria-hidden="true">
            <span className={`btn btn-primary btn-sm ${confirmed ? 'is-pressed' : ''}`}>{confirmed ? '✓ Confirmed' : 'Confirm meaning'}</span>
            <span className={`btn btn-sm ${confirmed ? 'is-muted' : ''}`}>Reject reading</span>
          </div>
        </li>
        <li className={`learn-step ${stageClass(on, 3)}`}>
          <span className="learn-no mono">D</span>
          <h3>Typed recognizer</h3>
          <dl className="kv learn-kv">
            <dt>Template</dt><dd className="mono">remote-console protocol {'{enum:protocol}'}</dd>
            <dt>Value</dt><dd className="mono">{'{"telnet": true, "*": false}'}</dd>
            <dt>Replay</dt><dd className="mono">MGMT-001: fail (heuristic) → fail (confirmed)</dd>
          </dl>
        </li>
        <li className={`learn-step ${stageClass(on, 4)}`}>
          <span className="learn-no mono">E</span>
          <h3>Future scan recognized</h3>
          <div className="chain-row"><StatusMark state="problem" /><span className="tag tag-pass">Human-confirmed recognizer</span></div>
          <p>A new scan of the same file decides MGMT-001 from the saved recognizer — no heuristic, no AI. It persists in SQLite across scans and restarts.</p>
        </li>
      </ol>
      <div className="learn-foot">
        <p className="learn-note small muted">
          Draft, replay and the next-scan result above are real backend output. Before saving, a recognizer must pass
          safety gates: the template has to match the line, and a line holding a secret cannot become a recognizer.
        </p>
        <ReplayButton done={on >= 5} onReplay={replay} />
      </div>
    </div>
  );
}

export default function Home() {
  const [menuOpen, setMenuOpen] = useState(false);
  const pageRef = useReveal();

  const go = (id) => {
    setMenuOpen(false);
    document.getElementById(id)?.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
  };

  const forti = assessment(FORTI.posture, FORTI.coverage, FORTI.critical);
  const unfamiliar = assessment(UNFAMILIAR.posture, UNFAMILIAR.coverage, UNFAMILIAR.critical);

  return (
    <div className="home" ref={pageRef}>
      <header className="home-bar">
        <div className="wrap home-bar-inner">
          <Brand />
          <nav aria-label="Primary" className={`home-links ${menuOpen ? 'is-open' : ''}`} id="home-links">
            {NAV.map(([id, label]) => (
              <button key={id} type="button" className="home-link" onClick={() => go(id)}>{label}</button>
            ))}
          </nav>
          <div className="home-bar-actions">
            <button type="button" className="btn btn-quiet btn-sm menu-toggle" aria-expanded={menuOpen}
                    aria-controls="home-links" onClick={() => setMenuOpen((v) => !v)}>
              {menuOpen ? 'Close' : 'Menu'}
            </button>
            <a className="btn btn-primary btn-sm" href="#/app">Try now</a>
          </div>
        </div>
      </header>

      <main>
        {/* HERO */}
        <section className="hero">
          <div className="wrap hero-grid">
            <div className="hero-copy enter">
              <p className="eyebrow">Network configuration audit</p>
              <h1 className="display hero-title">
                Know exactly what’s wrong with a network configuration — <em>and the line that proves it.</em>
              </h1>
              <p className="lede">
                NetAuditAI evaluates device configurations against security controls and cites the configuration
                evidence behind every authoritative finding. When syntax is unfamiliar, it says so — and asks you.
              </p>
              <div className="hero-actions">
                <a className="btn btn-accent btn-lg" href="#/app">Start a scan</a>
                <button type="button" className="btn btn-lg" onClick={() => go('how')}>See how it works</button>
              </div>
              <p className="hero-fine small">
                Dedicated parsers today: <strong>Cisco IOS</strong> and <strong>FortiGate</strong>. Other
                configurations take a generic analysis path with human-confirmed recognizers.
              </p>
            </div>
            <EvidenceChain />
          </div>
        </section>

        {/* 01 THE PROBLEM */}
        <section className="hsec" aria-labelledby="problem-title">
          <div className="wrap">
            <SectionHead no="01" id="problem-title" title="Every vendor says it differently. The control is the same.">
              Cisco, Fortinet, Juniper, Palo Alto, Arista, Aruba and MikroTik each use their own syntax. Security
              requirements don’t: they are controls. NetAuditAI evaluates the control, whatever the dialect.
            </SectionHead>
            <div className="dialects reveal">
              <div className="dialect-control">
                <span className="eyebrow">Control</span>
                <p><span className="mono">MGMT-001</span> Is cleartext Telnet disabled for remote management?</p>
              </div>
              <div className="table-wrap">
                <table className="data dialect-table">
                  <thead>
                    <tr><th scope="col">Platform</th><th scope="col">How the file says Telnet is allowed</th><th scope="col">Read by</th></tr>
                  </thead>
                  <tbody>
                    {DIALECTS.map((d) => (
                      <tr key={d.platform}>
                        <th scope="row">{d.platform}</th>
                        <td><code className="inline-code">{d.line}</code><span className="dialect-src mono">{d.source}</span></td>
                        <td><span className={`tag ${d.path === 'Dedicated parser' ? 'tag-pass' : 'tag-info'}`}>{d.path}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </section>

        {/* 02 HOW IT WORKS */}
        <section className="hsec hsec-alt" id="how" aria-labelledby="how-title">
          <div className="wrap">
            <SectionHead no="02" id="how-title" title="From raw configuration to verified fix.">
              Six stages, each one deterministic unless it explicitly says otherwise.
            </SectionHead>
            <Pipeline />
          </div>
        </section>

        {/* 03 EVIDENCE */}
        <section className="hsec" id="evidence" aria-labelledby="evidence-title">
          <div className="wrap">
            <SectionHead no="03" id="evidence-title" title="Every authoritative finding has evidence behind it.">
              A result is only decisive when it rests on validated evidence. The finding tells you which kind — and
              shows you the line.
            </SectionHead>
            <div className="evidence-grid">
              <article className="specimen reveal" aria-label="Example finding">
                <header className="specimen-head">
                  <span className="mono">MGMT-004</span>
                  <Severity level="critical" />
                  <span className="specimen-src small muted">From a real scan of {SAMPLE}</span>
                </header>
                <h3 className="specimen-title">Weak or Default SNMP Community Strings</h3>
                <div className="chain-row"><StatusMark state="problem" size="lg" /><span className="tag tag-pass">Parser evidence</span></div>
                <dl className="kv specimen-kv">
                  <dt>Device</dt><dd><span className="mono">DMZ-EDGE-10</span> · Cisco IOS, confirmed</dd>
                  <dt>Scope</dt><dd className="mono">snmp community #2</dd>
                  <dt>Why</dt><dd>A read-write SNMP community uses a well-known default string.</dd>
                </dl>
                <figure className="evidence">
                  <figcaption className="evidence-head"><span>Line 18</span><span className="evidence-scope">secret redacted by the backend</span></figcaption>
                  <div className="evidence-body">
                    <div className="ev-row context"><span className="ln">17</span><code>snmp-server community &lt;SECRET:snmp-community&gt; RO</code></div>
                    <div className="ev-row cited"><span className="ln">18</span><code>snmp-server community &lt;SECRET:snmp-community&gt; RW</code></div>
                  </div>
                </figure>
              </article>
              <div className="ladder reveal">
                <h3 className="ladder-title">Assurance, stated on every result</h3>
                <ul>
                  {ASSURANCE_LADDER.map(([name, text, decisive]) => (
                    <li key={name} className={decisive ? 'decisive' : 'provisional'}>
                      <span className={`tag ${decisive ? 'tag-pass' : 'tag-review'}`}>{decisive ? 'Decisive' : 'Provisional'}</span>
                      <strong>{name}</strong>
                      <span className="muted">{text}</span>
                    </li>
                  ))}
                </ul>
                <p className="small muted">Provisional readings are listed with their evidence but change nothing — not posture,
                  coverage, severity counts, findings or remediation — until a person confirms them.</p>
              </div>
            </div>
          </div>
        </section>

        {/* 04 UNCERTAINTY */}
        <section className="hsec hsec-alt" aria-labelledby="uncertainty-title">
          <div className="wrap">
            <SectionHead no="04" id="uncertainty-title" title="Unfamiliar syntax is not a failure. Absence is not a pass.">
              NetAuditAI keeps four outcomes apart, and reports how much of the device it could actually decide.
            </SectionHead>
            <div className="home-status-grid reveal">
              {STATUSES.map(([s, text]) => (
                <div key={s} className="status-card"><StatusMark state={statusState(s)} size="lg" /><p>{text}</p></div>
              ))}
            </div>
            <div className="posture-pair reveal">
              {[
                ['FortiGate, confirmed vendor', 'sample/frontinet/04_fortigate_vulnerable.cfg', FORTI, forti,
                  'One critical control (MGMT-005) could not be assessed from the file.'],
                ['Unfamiliar dialect, no confirmed vendor', 'sample/unknown.cfg', UNFAMILIAR, unfamiliar,
                  '7 provisional readings are waiting for a person to confirm or reject them.'],
              ].map(([name, src, v, a, note]) => (
                <article key={name} className="posture-mini">
                  <header><h3>{name}</h3><span className="mono small muted">{src}</span></header>
                  <div className="pm-metrics">
                    <div><span className="metric-label">Posture</span><span className="pm-value tnum">{v.posture ?? '—'}</span></div>
                    <div><span className="metric-label">Coverage</span><span className="pm-value tnum">{v.coverage}%</span></div>
                    <div><span className="metric-label">Assessment</span><span className="pm-scope">{a.label}</span></div>
                  </div>
                  <div className="coverage-bar" role="img" aria-label={`${v.coverage}% of applicable controls decided`}><span style={{ width: `${v.coverage}%` }} /></div>
                  <p className="small muted">{note}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        {/* 05 ADAPTIVE LEARNING */}
        <section className="hsec" id="adaptive" aria-labelledby="adaptive-title">
          <div className="wrap">
            <SectionHead no="05" id="adaptive-title" title="It learns unfamiliar syntax — only when you confirm it.">
              Controlled, human-in-the-loop adaptation. Not model training: nothing changes until an administrator
              confirms a reading, and what is saved is a typed rule you can read, replay and disable.
            </SectionHead>
            <LearningLoop />
          </div>
        </section>

        {/* 06 REMEDIATION */}
        <section className="hsec hsec-alt" id="remediation" aria-labelledby="remediation-title">
          <div className="wrap">
            <SectionHead no="06" id="remediation-title" title="Fixes you can review, then prove.">
              Remediation is a deterministic recipe, not generated text. Only failing settings change, and a fix is
              reported as verified only after the rescan says so.
            </SectionHead>
            <div className="rem-grid">
              <div className="reveal">
                <FileDiff diff={FIX_DIFF} file="DMZ-EDGE-10_fixed.cfg" caption="MGMT-001" />
                <ul className="checks home-checks">
                  {RESCAN_CHECKS.map(([name, detail], i) => (
                    <li key={name} className="ok" style={{ '--c': i }}>
                      <span className="check-mark" aria-hidden="true">✓</span>
                      <span className="visually-hidden">Passed: </span>
                      <span className="check-name">{name}</span>
                      <span>{detail}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <ul className="principles-list reveal">
                <li><strong>Deterministic recipes.</strong> The same finding on the same file always produces the same change. AI never writes remediation.</li>
                <li><strong>Only failing settings.</strong> Unrelated lines, nesting and comments are preserved.</li>
                <li><strong>Confirmed vendors only.</strong> Vendor-specific commands are never generated for an unknown or unverified platform.</li>
                <li><strong>Decisive findings only.</strong> Provisional readings cannot trigger a fix.</li>
                <li><strong>Verified by rescan.</strong> Vendor still confirmed, coverage intact, target passes, nothing else worse — or it is not called a fix.</li>
              </ul>
            </div>
          </div>
        </section>

        {/* 07 FRAMEWORKS */}
        <section className="hsec" id="frameworks" aria-labelledby="frameworks-title">
          <div className="wrap">
            <SectionHead no="07" id="frameworks-title" title="The same results, read through a framework.">
              Framework views regroup control results by requirement. Nothing is re-evaluated, and a view is not a
              certification.
            </SectionHead>
            <div className="fw-grid reveal">
              <article className="fw-card">
                <span className="tag tag-pass">Mapped</span>
                <h3>NIST SP 800-53 Rev. 5</h3>
                <p>Release 5.2.0. Every configuration, including those on the generic analysis path.</p>
              </article>
              <article className="fw-card">
                <span className="tag tag-pass">Mapped · confirmed vendors</span>
                <h3>CIS Benchmarks</h3>
                <p>Cisco IOS XE 17.x v2.1.0 and v2.2.1, FortiGate 7.4.x v1.0.1 — only where the requirement is auditable from device configuration.</p>
              </article>
              <article className="fw-card fw-card-none">
                <span className="tag tag-muted">Not mapped</span>
                <h3>Not claimed</h3>
                <p>ISO/IEC 27001, CIS Controls v8 and DISA STIG are not mapped today.</p>
              </article>
            </div>
          </div>
        </section>

        {/* 08 SUPPORTED TODAY */}
        <section className="hsec hsec-alt" aria-labelledby="support-title">
          <div className="wrap">
            <SectionHead no="08" id="support-title" title="Supported today, stated plainly.">
              The control model is vendor-agnostic. Dedicated parsing and remediation are not — and the product never
              pretends otherwise.
            </SectionHead>
            <div className="table-wrap reveal">
              <table className="data support-table">
                <thead>
                  <tr><th scope="col">Capability</th><th scope="col">Cisco IOS</th><th scope="col">FortiGate</th><th scope="col">Other configurations</th></tr>
                </thead>
                <tbody>
                  {SUPPORT.map(([cap, cisco, forti, other]) => (
                    <tr key={cap}><th scope="row">{cap}</th><td>{cisco}</td><td>{forti}</td><td>{other}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="cta">
          <div className="wrap cta-inner reveal">
            <h2 className="display">Audit a configuration.</h2>
            <p className="lede">Upload a device configuration and see what is wrong, what can be fixed and what needs you.</p>
            <a className="btn btn-accent btn-lg" href="#/app">Start a scan</a>
          </div>
        </section>
      </main>

      <footer className="home-foot">
        <div className="wrap home-foot-inner">
          <Brand />
          <span className="small muted">Evidence-first network configuration auditing.</span>
        </div>
      </footer>
    </div>
  );
}
