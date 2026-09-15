// Domain rules every view shares. They mirror guarantees the backend already enforces — the backend stays
// the authority; these only keep the UI from presenting provisional or partial results as decisive.

// Heuristic / AI verdicts: shown with their evidence, never counted until a human confirms them
export const PROVISIONAL_ASSURANCE = new Set(['heuristic', 'ai_verified']);
export const isProvisional = (r) => PROVISIONAL_ASSURANCE.has(r?.assurance);
// A PASS/FAIL backed by parser, confirmed-recognizer or documented-default evidence
export const isDecisive = (r) => ['pass', 'fail'].includes(r?.status) && !!r.assurance && !isProvisional(r);

// How a result was detected, in plain words (shown under "Detection method", never as the primary status)
export const ASSURANCE = {
  parser: { label: 'Read directly by a dedicated parser', technical: 'parser', decisive: true },
  confirmed: { label: 'Recognized from a meaning someone taught NetAuditAI', technical: 'confirmed recognizer', decisive: true },
  default: { label: 'Documented platform default', technical: 'default', decisive: true },
  heuristic: { label: 'A best guess from the wording — needs review', technical: 'heuristic', decisive: false },
  ai_verified: { label: 'An AI suggestion whose quoted line was checked — needs review', technical: 'ai_verified', decisive: false },
};

// A framework requirement or a bare control status (no assurance to consider) → state
const STATUS_STATE = { pass: 'pass', fail: 'problem', unknown: 'unknown', not_configured: 'not_configured', partial: 'partial', n_a: 'not_applicable' };
export const statusState = (status) => STATUS_STATE[status] || 'unknown';

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];
export const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

// Posture is PASS / (PASS + FAIL) over the controls that could be decided; coverage says how many could.
// A posture is never presented as a whole-device verdict unless every applicable control was decided.
export const LIMITED_COVERAGE = 50;

const band = (p) => {
  if (p < 40) return { label: 'Critical risk', tone: 'critical' };
  if (p < 70) return { label: 'Needs attention', tone: 'high' };
  if (p < 90) return { label: 'Fair', tone: 'medium' };
  return { label: 'Good', tone: 'good' };
};

export function assessment(posture, coverage = 0, criticalUnassessed = []) {
  if (posture == null) {
    return { scope: 'Not assessed', label: 'Not assessed', tone: 'none',
      desc: 'No control could be decided from validated evidence, so no posture was calculated.' };
  }
  const b = band(posture);
  if (coverage >= 100 && criticalUnassessed.length === 0) {
    return { scope: 'Full assessment', label: b.label, tone: b.tone, desc: 'Every applicable control was decided from validated evidence.' };
  }
  if (coverage < LIMITED_COVERAGE) {
    // a band ("Good", "Critical risk") would describe the whole device from a small sample: withheld
    return { scope: 'Limited assessment', label: 'Limited assessment', tone: 'limited',
      desc: `This posture reflects only the ${coverage}% of applicable controls that could be decided — not the whole device.` };
  }
  return { scope: 'Partial assessment', label: `${b.label} · partial`, tone: b.tone,
    desc: `Based on the ${coverage}% of applicable controls that could be decided.` };
}

// A device is its config_index; the hostname is only its label (numbered when two uploads share it)
export function deviceLabels(devices = []) {
  const names = devices.map((d) => d.hostname);
  return names.map((name, i) => (names.filter((n) => n === name).length > 1 ? `${name} (#${i + 1})` : name));
}

// Risk comes from decisive findings only; suspected findings are counted apart
export function deviceRows(scan) {
  const findings = scan?.findings || [];
  const results = scan?.results || [];
  return (scan?.devices || []).map((device, index) => {
    const ident = (scan.vendor_identification || []).find((v) => v.config_index === index);
    const own = findings.filter((f) => (f.config_index ?? 0) === index);
    const decisive = own.filter((f) => !isProvisional(f));
    const assessed = results.some((r) => r.config_index === index && isDecisive(r));
    let risk = 'NOT ASSESSED';
    if (assessed) {
      risk = 'LOW';
      for (const [severity, label] of [['critical', 'CRITICAL'], ['high', 'HIGH'], ['medium', 'MEDIUM']]) {
        if (decisive.some((f) => f.severity === severity)) { risk = label; break; }
      }
    }
    return {
      index,
      hostname: device.hostname,
      vendor: device.vendor,
      decisive: decisive.length,
      suspected: own.length - decisive.length,
      risk,
      identification: ident,
      analysis: ident?.status === 'confirmed' ? 'Dedicated parser'
        : ident?.status === 'unverified' ? 'Generic analysis (vendor unverified)' : 'Generic analysis',
    };
  });
}

const VENDOR_NAMES = { cisco_ios: 'Cisco IOS', fortinet: 'FortiGate', unknown: 'Unknown' };
export const vendorName = (v) => VENDOR_NAMES[v] || (v ? v.replace(/_/g, ' ') : 'Unknown');

// Confirmed vs unverified vs unknown: a weak keyword match is never presented as a confirmed vendor
export function vendorState(ident) {
  if (ident?.status === 'confirmed') {
    return { key: 'confirmed', label: `${vendorName(ident.detected_vendor)} · confirmed`, path: 'Dedicated parser',
      note: 'Trusted parser, platform defaults and deterministic remediation recipes apply.' };
  }
  if (ident?.status === 'unverified') {
    return { key: 'unverified', label: `Resembles ${vendorName(ident.detected_vendor)} · unverified`, path: 'Generic analysis path',
      note: `The syntax does not follow that vendor's grammar closely enough to trust its parser${ident.reason ? ` (${ident.reason})` : ''}. Vendor-specific remediation stays unavailable.` };
  }
  return { key: 'unknown', label: 'Vendor not identified', path: 'Generic analysis path',
    note: 'Controls are still evaluated through generic structure analysis. Vendor-specific remediation is unavailable until a vendor is confirmed.' };
}

// ── The one user-facing state model ──────────────────────────────────────────────────────────────────────────
// Every view shows these states and nothing else. Backend statuses (control status, assurance, remediation status)
// are mapped here only, so no component interprets them on its own. The technical state stays on the objects.
//
//   pass / not_configured / not_applicable / unknown   — how a control was decided (unknown = not enough information)
//   needs_review                                      — a heuristic / AI reading waiting for a person; never counted
//   problem                                           — a decisive failure whose fix options are not known yet
//   can_fix / needs_input / manual / cannot_fix       — a decisive failure, by what can be done about it
//   fixed / verification_failed                        — after a fix was generated and rescanned
export const STATE = {
  pass: { label: 'Passed', tone: 'pass', mark: '✓' },
  problem: { label: 'Problem', tone: 'fail', mark: '×' },
  can_fix: { label: 'Can fix automatically', tone: 'fix', mark: '↻', group: 'can_fix',
    hint: 'NetAuditAI can fix this safely.' },
  needs_input: { label: 'Needs your input', tone: 'input', mark: '?', group: 'needs_input',
    hint: 'We know the problem. We need one or two values from you to fix it.' },
  manual: { label: 'Manual action required', tone: 'manual', mark: '!', group: 'manual',
    hint: 'We won’t change this automatically because doing so could affect how the network behaves.' },
  cannot_fix: { label: 'Can’t fix automatically', tone: 'manual', mark: '–', group: 'manual',
    hint: 'NetAuditAI has no safe automatic fix for this.' },
  verification_failed: { label: 'Verification failed', tone: 'fail', mark: '!', group: 'manual',
    hint: 'A fix was generated, but the rescan did not confirm it. It is never included in a download.' },
  fixed: { label: 'Fixed', tone: 'pass', mark: '✓',
    hint: 'Fixed and verified by a full rescan.' },
  needs_review: { label: 'Needs review', tone: 'review', mark: '?',
    hint: 'NetAuditAI isn’t sure what a line means. It is not counted until you confirm it.' },
  unknown: { label: 'Not enough information', tone: 'unknown', mark: '?',
    hint: 'Nothing in the configuration could decide this check.' },
  not_configured: { label: 'Not configured', tone: 'nc', mark: '∅',
    hint: 'No line sets this. Absence is never treated as a pass.' },
  not_applicable: { label: 'Not applicable', tone: 'na', mark: '–' },
  partial: { label: 'Partly met', tone: 'partial', mark: '◐' },
};
export const stateMeta = (s) => STATE[s] || STATE.unknown;

// What can be done about a decisive failure, from the backend's remediation status
const REMEDIATION_STATE = {
  fixed: 'can_fix', // the plan generated this fix and a full rescan verified it: it is ready to apply
  needs_input: 'needs_input',
  manual_review: 'manual',
  verification_failed: 'verification_failed',
  no_recipe: 'cannot_fix',
  vendor_unverified: 'cannot_fix',
  provisional: 'needs_review',
};
export const remediationState = (status) => REMEDIATION_STATE[status] || null;

// Plain reasons for the two outcomes the backend states only as a status
export const CANNOT_FIX_REASON = {
  no_recipe: 'NetAuditAI has no proven automatic fix for this setting on this platform yet.',
  vendor_unverified: 'NetAuditAI couldn’t confirm which vendor this device is, so it never generates vendor commands for it.',
};

// One control result → its state. `remediation` is the backend remediation item for this control, when known;
// `applied` is true once a fix for it was generated and verified in this session.
export function resultState(r, { remediation, applied } = {}) {
  if (isProvisional(r) || r?.proposed_status) return 'needs_review';
  switch (r?.status) {
    case 'pass': return 'pass';
    case 'not_configured': return 'not_configured';
    case 'n_a': return 'not_applicable';
    case 'fail': {
      if (applied) return 'fixed';
      return remediationState(remediation?.status) || 'problem';
    }
    default: return 'unknown';
  }
}

export const itemKey = (configIndex, controlId) => `${configIndex ?? 0}-${controlId}`;

// Which of a control's results speaks for it: a decisive failure first, then a reading waiting for review, then
// undecided, absent, passed
const PRESSING = (r) => (r.status === 'fail' && isDecisive(r) ? 0 : isProvisional(r) || r.proposed_status ? 1
  : r.status === 'unknown' ? 2 : r.status === 'not_configured' ? 3 : r.status === 'pass' ? 4 : 5);

// One check per control per configuration: the unit every count and list uses. A control decided in several
// scopes keeps all its results (one piece of evidence each), its finding text and its remediation item.
export function checkItems(scan, plan) {
  const remediations = new Map((plan?.devices || []).flatMap((d) => d.remediations)
    .map((item) => [itemKey(item.config_index, item.rule_id), item]));
  const byKey = new Map();
  for (const r of scan?.results || []) {
    const key = itemKey(r.config_index, r.control_id);
    if (!byKey.has(key)) {
      byKey.set(key, {
        key, configIndex: r.config_index ?? 0, controlId: r.control_id, title: r.title, question: r.question,
        category: r.category, results: [], remediation: remediations.get(key) || null,
        finding: (scan.findings || []).find((f) => f.rule_id === r.control_id && (f.config_index ?? 0) === (r.config_index ?? 0)) || null,
      });
    }
    byKey.get(key).results.push(r);
  }
  return [...byKey.values()].map((item) => {
    const primary = [...item.results].sort((x, y) => PRESSING(x) - PRESSING(y))[0];
    const weighed = item.results.filter((r) => PRESSING(r) === PRESSING(primary));
    const severity = weighed.map((r) => r.severity).sort((x, y) => (SEVERITY_RANK[x] ?? 9) - (SEVERITY_RANK[y] ?? 9))[0];
    return { ...item, primary, severity };
  }).sort((a, b) => PRESSING(a.primary) - PRESSING(b.primary)
    || (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)
    || a.controlId.localeCompare(b.controlId) || a.configIndex - b.configIndex);
}

export const isProblem = (item) => item.results.some((r) => r.status === 'fail' && isDecisive(r));
// `applied`: Set of item keys whose fix was applied and verified in this session
export const itemState = (item, applied) =>
  resultState(item.primary, { remediation: item.remediation, applied: !!applied?.has(item.key) });

// Decisive failures only — what "problems found" means everywhere
export const problems = (scan, plan) => checkItems(scan, plan).filter(isProblem);

// ── Plain language for a security fact ─────────────────────────────────────────────────────────────────────────
// What a line means, in words a person can confirm. Built only from the predicate, subject and value the backend
// read — never from the raw line — so the sentence says exactly what would be learned.
const PROTOCOLS = { telnet: 'Telnet', http: 'HTTP', https: 'HTTPS', ssh: 'SSH', cdp: 'CDP', lldp: 'LLDP' };
const onOff = (v, on, off) => (v === true ? on : v === false ? off : null);
const list = (v) => (Array.isArray(v) ? v.join(', ') : typeof v === 'string' ? v : null);
const STORAGE = { plaintext: 'plain text', type7: 'weak reversible encryption (type 7)', type5: 'an MD5 hash (type 5)',
  type8: 'a PBKDF2 hash (type 8)', type9_scrypt: 'a strong scrypt hash (type 9)', type9: 'a strong scrypt hash (type 9)' };

export const MEANING = {
  'mgmt.remote_access.protocol_enabled': { topic: 'Remote access', say: (s, v) => onOff(v, `turns on ${PROTOCOLS[s] || s} remote access`, `turns off ${PROTOCOLS[s] || s} remote access`) },
  'mgmt.remote_access.source_restricted': { topic: 'Access control', say: (s, v) => onOff(v, 'limits which addresses can manage the device', 'lets any address manage the device') },
  'mgmt.ssh.version': { topic: 'Remote access', say: (s, v) => (v != null ? `sets the SSH version to ${v}` : null) },
  'mgmt.session.idle_timeout': { topic: 'Remote access', say: (s, v) => (v != null ? `sets an idle session timeout (${v})` : null) }, // the reading carries no unit: none is claimed
  'auth.central_aaa.enabled': { topic: 'Authentication', say: (s, v) => onOff(v, 'turns on central authentication (AAA)', 'turns off central authentication (AAA)') },
  'auth.password.storage': { topic: 'Authentication', say: (s, v) => (v ? `stores the ${s ? `${s.replace(/^user /, 'user ')} ` : ''}password as ${STORAGE[v] || v}` : null) },
  'auth.password.encryption_service': { topic: 'Authentication', say: (s, v) => onOff(v, 'turns on password encryption', 'turns off password encryption') },
  'snmp.community': { topic: 'Monitoring (SNMP)', say: () => 'configures an SNMP community' },
  'log.remote.destination': { topic: 'Logging', say: (s, v) => (list(v) ? `sends logs to ${list(v)}` : 'configures remote logging') },
  'time.ntp.server': { topic: 'Time (NTP)', say: (s, v) => (list(v) ? `uses NTP server ${list(v)}` : 'configures an NTP server') },
  'time.ntp.authenticated': { topic: 'Time (NTP)', say: (s, v) => onOff(v, 'turns on NTP authentication', 'turns off NTP authentication') },
  'banner.login.present': { topic: 'Login banner', say: (s, v) => onOff(v, 'shows a login banner', 'removes the login banner') },
  'boundary.source_routing.enabled': { topic: 'Traffic rules', say: (s, v) => onOff(v, 'allows IP source routing', 'blocks IP source routing') },
  'boundary.discovery_protocol.enabled': { topic: 'Device discovery', say: (s, v) => onOff(v, `turns on ${PROTOCOLS[s] || s} device discovery`, `turns off ${PROTOCOLS[s] || s} device discovery`) },
  'boundary.policy.permit_any': { topic: 'Traffic rules', say: (s, v) => onOff(v, 'allows all traffic (any source to any destination)', 'does not allow all traffic') },
  'crypto.ipsec.proposal': { topic: 'VPN encryption', say: () => 'sets VPN encryption settings' },
};

// "This line turns on Telnet remote access." — or null when the reading can't be put into words
export const sayFact = ({ predicate, subject, value } = {}) => MEANING[predicate]?.say(subject, value) || null;
export function describeFact(fact) {
  const said = sayFact(fact);
  return said ? `This line ${said}.` : null;
}
export const factTopic = (predicate) => MEANING[predicate]?.topic || 'Other setting';

// The backend's recognizer safety gates, in plain English. The original message stays available under
// Advanced details; nothing here decides whether saving is allowed — the backend does.
const GATE_WORDS = [
  [/secret/i, 'This line contains a secret, such as a password or key. NetAuditAI never stores secrets, so it can’t learn from this line.'],
  [/does not match its example line/i, 'The pattern no longer matches the configuration line, so NetAuditAI couldn’t verify what it would learn.'],
  [/contradicts the line/i, 'That meaning contradicts what the line itself says, so it can’t be saved.'],
  [/polarity must be stated|no true \/ false value|cannot say whether a setting is on or off|true \/ false value table/i, 'The line doesn’t clearly say whether this setting is on or off, so NetAuditAI can’t learn it safely.'],
  [/states no unit/i, 'The line gives a time without a unit (minutes, seconds or hours), so the value can’t be verified.'],
  [/must be JSON|no usable value|read from an/i, 'This line contains a value type NetAuditAI can’t verify safely.'],
  [/at least \d+ keywords/i, 'The pattern is too general: it could match unrelated lines.'],
  [/cannot answer/i, 'NetAuditAI can’t learn this kind of setting from a line yet.'],
  [/conflict|already/i, 'NetAuditAI already knows a different meaning for lines like this one.'],
];
export const explainGate = (message = '') =>
  (GATE_WORDS.find(([re]) => re.test(message))?.[1]) || 'NetAuditAI couldn’t verify what this line means, so it wasn’t saved.';

// Controls awaiting a person, from the scan alone: heuristic / AI verdicts (one per control per config) plus legacy
// review lines. A decisive failure that needs a manual fix is NOT human review.
export function reviewCount(scan) {
  const provisional = new Set((scan?.results || [])
    .filter((r) => isProvisional(r) || r.proposed_status)
    .map((r) => itemKey(r.config_index, r.control_id))).size;
  const pending = (scan?.adaptive_configs || []).reduce((sum, c) => sum + (c.pending_review || 0), 0);
  return provisional + pending;
}

// Every count a page shows, from one place.
// plan: the backend remediation plan (fix groups are null until it is known)
// applied: Set of item keys fixed this session
// queue: { provisional, legacyPending } from the backend — once loaded, review counts the lines actually waiting
export function auditCounts(scan, plan, applied = new Set(), queue = null) {
  const items = checkItems(scan, plan);
  const list = items.filter(isProblem);
  const states = list.map((p) => itemState(p, applied));
  const count = (pred) => states.filter(pred).length;
  const others = (state) => items.filter((i) => !isProblem(i) && itemState(i) === state).length;
  return {
    problems: list.length,
    severity: Object.fromEntries(SEVERITIES.map((s) => [s, list.filter((p) => p.severity === s).length])),
    canFix: plan ? count((s) => s === 'can_fix') : null,
    needsInput: plan ? count((s) => s === 'needs_input') : null,
    manual: plan ? count((s) => STATE[s]?.group === 'manual') : null,
    fixed: count((s) => s === 'fixed'),
    review: queue ? queue.provisional.length + (queue.legacyPending || 0) : reviewCount(scan),
    unknown: others('unknown'),
    notConfigured: others('not_configured'),
    passed: others('pass'),
  };
}

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// "What am I supposed to do now?" — one answer for the whole audit, in priority order
export function nextStep(c, { planLoading = false, planError = null } = {}) {
  if (c.canFix > 0) {
    return { tone: 'fix', to: 'fix', action: 'Fix them', title: `We can fix ${plural(c.canFix, 'problem')} automatically`,
      body: 'Each fix changes only the failing setting and is checked by rescanning the corrected configuration.' };
  }
  if (c.needsInput > 0) {
    return { tone: 'input', to: 'fix', action: 'Answer', title: c.needsInput === 1 ? 'We need one answer from you' : `We need ${c.needsInput} answers from you`,
      body: 'Tell us a value, such as a server address, and NetAuditAI generates and verifies the fix.' };
  }
  if (c.review > 0) {
    return { tone: 'review', to: 'teach', action: 'Teach NetAuditAI', title: 'NetAuditAI needs your help with lines it doesn’t recognize',
      body: `${plural(c.review, 'question')} ${c.review === 1 ? 'is' : 'are'} waiting for your answer. Nothing is counted until you confirm what a line means.` };
  }
  if (c.manual > 0) {
    return { tone: 'manual', to: 'fix', action: 'See what to change', title: 'We can’t safely change the rest automatically',
      body: `${plural(c.manual, 'problem')} ${c.manual === 1 ? 'needs' : 'need'} a change made by you. We show exactly what to change.` };
  }
  if (c.problems > 0 && c.canFix == null) {
    return planError
      ? { tone: 'manual', to: null, title: 'We couldn’t work out which problems can be fixed', body: planError }
      : { tone: 'info', to: null, busy: planLoading, title: 'Working out what can be fixed…', body: 'NetAuditAI generates each fix and rescans to check it.' };
  }
  if (c.fixed > 0) {
    return { tone: 'pass', to: 'fix', action: 'Download', title: 'You’re done.',
      body: 'Every problem is fixed in your corrected configuration. Download it from Fix.' };
  }
  return { tone: 'pass', to: null, title: 'You’re done.', body: 'Nothing needs your attention.' };
}

// Command text the backend quotes in a remediation reason or recommendation ('no ip http server'). Shown for a
// person to apply on the device — never generated here. A quoted redaction placeholder is not a command, and
// neither is a single quoted word: "Change user 'admin'" or "Remove 'telnet' from allowaccess" name things.
export function quotedCommands(...texts) {
  const seen = new Set();
  for (const text of texts) {
    for (const m of (text || '').matchAll(/'([^']{3,})'/g)) {
      const command = m[1].trim();
      if (/\s/.test(command) && !/^<SECRET:[^>]*>$/.test(command)) seen.add(command);
    }
  }
  return [...seen];
}

const filled = (values) => Object.fromEntries(Object.entries(values || {}).filter(([, v]) => v !== '' && v != null));

// True when two remediation input sets are the same once empty fields are ignored
export function sameInputs(a, b) {
  const x = filled(a);
  const y = filled(b);
  return Object.keys(x).length === Object.keys(y).length && Object.keys(x).every((k) => x[k] === y[k]);
}

// Evidence lines can arrive as "  70: text"; the gutter already shows 70
export const stripLineNo = (line = '', n) => {
  const m = /^\s*(\d+):\s?/.exec(line);
  return m && (n == null || Number(m[1]) === n) ? line.slice(m[0].length) : line;
};

// Unified diff → rows with old/new line numbers (hunk headers carry the starting numbers)
export function parseUnifiedDiff(diff = '') {
  const rows = [];
  let oldNo = 0;
  let newNo = 0;
  for (const line of diff.split('\n')) {
    if (line.startsWith('---') || line.startsWith('+++')) continue;
    const hunk = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$/.exec(line);
    if (hunk) {
      oldNo = Number(hunk[1]);
      newNo = Number(hunk[2]);
      rows.push({ type: 'hunk', old: null, cur: null, text: line });
    } else if (line.startsWith('+')) {
      rows.push({ type: 'add', old: null, cur: newNo++, text: line.slice(1) });
    } else if (line.startsWith('-')) {
      rows.push({ type: 'del', old: oldNo++, cur: null, text: line.slice(1) });
    } else if (line.startsWith('\\')) {
      continue;
    } else if (line !== '' || rows.length) {
      rows.push({ type: 'ctx', old: oldNo++, cur: newNo++, text: line.startsWith(' ') ? line.slice(1) : line });
    }
  }
  while (rows.length && rows[rows.length - 1].type === 'ctx' && rows[rows.length - 1].text === '') rows.pop();
  return rows;
}
