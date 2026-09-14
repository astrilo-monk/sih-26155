// Domain rules every view shares. They mirror guarantees the backend already enforces — the backend stays
// the authority; these only keep the UI from presenting provisional or partial results as decisive.

// Heuristic / AI verdicts: shown with their evidence, never counted until a human confirms them
export const PROVISIONAL_ASSURANCE = new Set(['heuristic', 'ai_verified']);
export const isProvisional = (r) => PROVISIONAL_ASSURANCE.has(r?.assurance);
// A PASS/FAIL backed by parser, confirmed-recognizer or documented-default evidence
export const isDecisive = (r) => ['pass', 'fail'].includes(r?.status) && !!r.assurance && !isProvisional(r);

// Status is never communicated by colour alone: every status has a mark and a word
export const STATUS = {
  fail: { label: 'Fail', mark: '×', tone: 'fail' },
  pass: { label: 'Pass', mark: '✓', tone: 'pass' },
  unknown: { label: 'Unknown', mark: '?', tone: 'unknown' },
  not_configured: { label: 'Not configured', mark: '∅', tone: 'nc' },
  partial: { label: 'Partial', mark: '◐', tone: 'partial' },
  n_a: { label: 'Not applicable', mark: '–', tone: 'na' },
};
export const statusMeta = (s) => STATUS[s] || { label: s || '—', mark: '·', tone: 'na' };

export const ASSURANCE = {
  parser: { label: 'Parser evidence', decisive: true },
  confirmed: { label: 'Human-confirmed recognizer', decisive: true },
  default: { label: 'Documented platform default', decisive: true },
  heuristic: { label: 'Heuristic reading — provisional', decisive: false },
  ai_verified: { label: 'AI proposal, citation verified — provisional', decisive: false },
};

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];
export const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

// Suspected (heuristic / AI) findings are listed but never counted as decided severities
export const decisiveSeverityCounts = (findings = []) =>
  Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s && !isProvisional(f)).length]));

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

// Remediation outcomes, in the words an operator acts on
export const REMEDIATION = {
  fixed: { label: 'Verified', group: 'Verified', tone: 'pass', hint: 'Generated deterministically and verified by a full rescan' },
  needs_input: { label: 'Needs input', group: 'Needs input', tone: 'medium', hint: 'A deterministic change is ready once you provide the values it needs' },
  manual_review: { label: 'Requires review', group: 'Requires review', tone: 'high', hint: 'No known-safe automatic change exists for this finding' },
  verification_failed: { label: 'Verification failed', group: 'Requires review', tone: 'fail', hint: 'A change was generated, but the rescan did not confirm it — never included in a download' },
  provisional: { label: 'Blocked · provisional', group: 'Blocked', tone: 'unknown', hint: 'Heuristic / AI verdict: confirm it under Needs your input first' },
  no_recipe: { label: 'No recipe', group: 'No recipe', tone: 'na', hint: 'No deterministic strategy for this control on this platform' },
  vendor_unverified: { label: 'Blocked · vendor unconfirmed', group: 'Blocked', tone: 'unknown', hint: 'Vendor commands are never generated for unknown or unverified vendors' },
  not_failing: { label: 'Nothing to fix', group: null, tone: 'na', hint: 'The control has no decisive failure' },
};
export const REMEDIATION_GROUPS = ['Verified', 'Needs input', 'Requires review', 'No recipe', 'Blocked'];
export const remediationMeta = (s) => REMEDIATION[s] || { label: s, group: null, tone: 'na', hint: '' };

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
