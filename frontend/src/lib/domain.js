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

const problemKey = (configIndex, controlId) => `${configIndex ?? 0}-${controlId}`;

// Decisive failures, one per control per configuration (a control failing in several scopes is one problem with
// several pieces of evidence), each with its finding text and remediation item when the plan is known.
export function problems(scan, plan) {
  const items = new Map((plan?.devices || []).flatMap((d) => d.remediations)
    .map((item) => [problemKey(item.config_index, item.rule_id), item]));
  const byKey = new Map();
  for (const r of scan?.results || []) {
    if (!(r.status === 'fail' && isDecisive(r))) continue;
    const key = problemKey(r.config_index, r.control_id);
    if (!byKey.has(key)) {
      const finding = (scan.findings || []).find((f) => f.rule_id === r.control_id && (f.config_index ?? 0) === (r.config_index ?? 0)) || null;
      byKey.set(key, { key, configIndex: r.config_index ?? 0, controlId: r.control_id, title: r.title,
        severity: r.severity, results: [], finding, remediation: items.get(key) || null });
    }
    byKey.get(key).results.push(r);
  }
  return [...byKey.values()].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)
    || a.controlId.localeCompare(b.controlId) || a.configIndex - b.configIndex);
}

// Controls awaiting a person: heuristic / AI verdicts (one per control per config) plus legacy review lines.
// A decisive failure that needs a manual fix is NOT human review.
export function reviewCount(scan) {
  const provisional = new Set((scan?.results || [])
    .filter((r) => isProvisional(r) || r.proposed_status)
    .map((r) => problemKey(r.config_index, r.control_id))).size;
  const pending = (scan?.adaptive_configs || []).reduce((sum, c) => sum + (c.pending_review || 0), 0);
  return provisional + pending;
}

// Every count a page shows, from one place. Remediation groups are null until the plan is known.
// `applied` is a Set of problem keys fixed in this session.
export function auditCounts(scan, plan, applied = new Set()) {
  const list = problems(scan, plan);
  const states = list.map((p) => resultState(p.results[0], { remediation: p.remediation, applied: applied.has(p.key) }));
  const count = (pred) => states.filter(pred).length;
  const results = scan?.results || [];
  const undecided = (status) => new Set(results.filter((r) => r.status === status && !isProvisional(r) && !r.proposed_status)
    .map((r) => problemKey(r.config_index, r.control_id))).size;
  return {
    problems: list.length,
    severity: Object.fromEntries(SEVERITIES.map((s) => [s, list.filter((p) => p.severity === s).length])),
    canFix: plan ? count((s) => s === 'can_fix') : null,
    needsInput: plan ? count((s) => s === 'needs_input') : null,
    manual: plan ? count((s) => STATE[s]?.group === 'manual') : null,
    fixed: count((s) => s === 'fixed'),
    review: reviewCount(scan),
    unknown: undecided('unknown'),
    notConfigured: undecided('not_configured'),
    passed: new Set(results.filter((r) => r.status === 'pass' && isDecisive(r)).map((r) => problemKey(r.config_index, r.control_id))).size,
  };
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
