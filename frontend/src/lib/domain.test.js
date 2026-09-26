import { describe, expect, it } from 'vitest';
import {
  assessment, auditCounts, deviceLabels, fixOrder, explainGate, nextStep, quotedCommands, parseUnifiedDiff, problems, resultState, sayFact, STATE,
  stripLineNo, vendorState,
} from './domain';

const finding = (config_index, severity, assurance) => ({ rule_id: 'MGMT-001', severity, assurance, config_index, device_hostname: 'x' });

// paloalto.cfg + unknown.cfg (both generic) + two FortiGates sharing one hostname
const SCAN = {
  devices: [
    { hostname: 'unknown', vendor: 'unknown' },
    { hostname: 'unknown', vendor: 'unknown' },
    { hostname: 'BRANCH-FGT-02', vendor: 'fortinet' },
    { hostname: 'BRANCH-FGT-02', vendor: 'fortinet' },
  ],
  vendor_identification: [
    { config_index: 0, status: 'unknown' }, { config_index: 1, status: 'unknown' },
    { config_index: 2, status: 'confirmed' }, { config_index: 3, status: 'confirmed' },
  ],
  findings: [
    finding(0, 'critical', 'heuristic'), finding(0, 'high', 'heuristic'), finding(1, 'critical', 'ai_verified'),
    finding(3, 'high', 'parser'),
  ],
  results: [
    { config_index: 0, status: 'fail', assurance: 'heuristic' },
    { config_index: 2, status: 'pass', assurance: 'parser' },
    { config_index: 3, control_id: 'MGMT-001', severity: 'high', status: 'fail', assurance: 'parser' },
  ],
};

it('keeps devices with the same hostname apart', () => {
  expect(deviceLabels(SCAN.devices)).toEqual(['unknown (#1)', 'unknown (#2)', 'BRANCH-FGT-02 (#3)', 'BRANCH-FGT-02 (#4)']);
});

it('counts only decisive failures by severity', () => {
  expect(auditCounts(SCAN).severity).toEqual({ critical: 0, high: 1, medium: 0, low: 0 });
});

it('never presents partial or low coverage as a full verdict', () => {
  expect(assessment(95, 30, []).label).toBe('Limited assessment');
  expect(assessment(0, 11, []).label).not.toMatch(/Critical risk/);
  expect(assessment(100, 83, ['MGMT-005'])).toMatchObject({ label: 'Good · partial', scope: 'Partial assessment' });
  expect(assessment(100, 100, ['MGMT-005']).scope).toBe('Partial assessment');
  expect(assessment(100, 100, [])).toMatchObject({ label: 'Good', scope: 'Full assessment' });
  expect(assessment(null, 0).scope).toBe('Not assessed');
});

it('distinguishes confirmed, unverified and unknown vendors', () => {
  expect(vendorState({ status: 'confirmed', detected_vendor: 'cisco_ios' })).toMatchObject({ key: 'confirmed', label: 'Cisco IOS · confirmed' });
  expect(vendorState({ status: 'unverified', detected_vendor: 'fortinet' }).label).toBe('Resembles FortiGate · unverified');
  expect(vendorState(undefined)).toMatchObject({ key: 'unknown', path: 'Generic analysis path' });
});

it('reads real line numbers from a unified diff', () => {
  const rows = parseUnifiedDiff('--- before\n+++ after\n@@ -12,5 +12,5 @@\n  login\n- transport input telnet ssh\n+ transport input ssh\n  exec-timeout 0 0');
  expect(rows.map((r) => [r.type, r.old, r.cur, r.text])).toEqual([
    ['hunk', null, null, '@@ -12,5 +12,5 @@'],
    ['ctx', 12, 12, ' login'],
    ['del', 13, null, ' transport input telnet ssh'],
    ['add', null, 13, ' transport input ssh'],
    ['ctx', 14, 14, ' exec-timeout 0 0'],
  ]);
});

it('strips a line-number prefix only when it is the cited number', () => {
  expect(stripLineNo('  70: remote-console protocol telnet', 70)).toBe('remote-console protocol telnet');
  expect(stripLineNo('10: not the cited line', 70)).toBe('10: not the cited line');
});

it('asks the next step in priority order and says when there is nothing to do', () => {
  const base = { problems: 0, canFix: 0, needsInput: 0, manual: 0, fixed: 0, review: 0 };
  expect(nextStep({ ...base, problems: 3, canFix: 1, needsInput: 1, manual: 1, review: 2 })).toMatchObject({ to: 'fix', title: 'We can fix 1 problem automatically' });
  expect(nextStep({ ...base, problems: 1, needsInput: 1 })).toMatchObject({ to: 'fix', title: 'We need one answer from you' });
  expect(nextStep({ ...base, review: 2 })).toMatchObject({ to: 'teach' });
  expect(nextStep({ ...base, problems: 1, manual: 1 }).title).toMatch(/can’t safely change/);
  expect(nextStep({ ...base, problems: 2, canFix: null, needsInput: null, manual: null }, { planLoading: true }).title).toMatch(/Working out/);
  expect(nextStep(base)).toMatchObject({ title: 'You’re done.', body: 'Nothing needs your attention.', to: null });
});

it('lists quoted backend commands, never a redaction placeholder', () => {
  expect(quotedCommands("Replace it ('enable algorithm-type scrypt secret …', 'username … algorithm-type scrypt secret …')", "SNMP community '<SECRET:redacted>' uses 'no ip http server'"))
    .toEqual(['enable algorithm-type scrypt secret …', 'username … algorithm-type scrypt secret …', 'no ip http server']);
  // a quoted name is not a command (real backend recommendation text)
  expect(quotedCommands("Change user 'admin' to use 'username admin algorithm-type scrypt secret <password>'.", "Remove 'telnet' from allowaccess"))
    .toEqual(['username admin algorithm-type scrypt secret <password>']);
});

it('maps every backend state to one user-facing state, never conflating pass, fail and provisional', () => {
  const r = (status, assurance, extra = {}) => ({ config_index: 0, control_id: 'MGMT-001', status, assurance, ...extra });
  expect(resultState(r('pass', 'parser'))).toBe('pass');
  expect(resultState(r('fail', 'parser'))).toBe('problem');
  // provisional readings are review, whatever verdict they carry
  expect(resultState(r('fail', 'heuristic'))).toBe('needs_review');
  expect(resultState(r('pass', 'ai_verified'))).toBe('needs_review');
  expect(resultState(r('unknown', null, { proposed_status: 'pass' }))).toBe('needs_review');
  // unknown is not enough information, not review; absence is never a pass
  expect(resultState(r('unknown', null))).toBe('unknown');
  expect(resultState(r('not_configured', null))).toBe('not_configured');
  // a decisive failure, by what can be done about it
  const withFix = (status) => resultState(r('fail', 'parser'), { remediation: { status } });
  expect(['fixed', 'needs_input', 'manual_review', 'verification_failed', 'no_recipe', 'vendor_unverified'].map(withFix))
    .toEqual(['can_fix', 'needs_input', 'manual', 'verification_failed', 'cannot_fix', 'needs_admin']);
  expect(resultState(r('fail', 'parser'), { remediation: { status: 'fixed' }, applied: true })).toBe('fixed');
  expect(Object.keys(STATE).every((k) => STATE[k].label && STATE[k].mark)).toBe(true);
});

it('counts problems once per control per configuration and keeps review, remediation and unknown apart', () => {
  const scan = {
    results: [
      { config_index: 0, control_id: 'MGMT-001', status: 'fail', assurance: 'parser', severity: 'critical', scope: 'vty 0 4' },
      { config_index: 0, control_id: 'MGMT-001', status: 'fail', assurance: 'parser', severity: 'critical', scope: 'vty 5 15' },
      { config_index: 0, control_id: 'LOG-001', status: 'fail', assurance: 'parser', severity: 'medium' },
      { config_index: 0, control_id: 'MGMT-008', status: 'fail', assurance: 'parser', severity: 'high' },
      { config_index: 0, control_id: 'MGMT-003', status: 'fail', assurance: 'heuristic', severity: 'high' },
      { config_index: 0, control_id: 'MGMT-006', status: 'unknown', assurance: null },
      { config_index: 0, control_id: 'MGMT-007', status: 'pass', assurance: 'parser' },
    ],
    findings: [],
  };
  const before = auditCounts(scan);
  expect(before).toMatchObject({ problems: 3, review: 1, unknown: 1, passed: 1, canFix: null, needsInput: null, manual: null });
  // once the backend queue is loaded, review is what is actually waiting (here: two lines, one of an undecided check)
  expect(auditCounts(scan, null, new Set(), { provisional: [{}, {}], legacyPending: 1 }).review).toBe(3);
  expect(before.severity).toEqual({ critical: 1, high: 1, medium: 1, low: 0 });

  const plan = { devices: [{ remediations: [
    { config_index: 0, rule_id: 'MGMT-001', status: 'fixed' },
    { config_index: 0, rule_id: 'LOG-001', status: 'needs_input' },
    { config_index: 0, rule_id: 'MGMT-008', status: 'manual_review' },
    { config_index: 0, rule_id: 'MGMT-003', status: 'provisional' },
  ] }] };
  const after = auditCounts(scan, plan);
  expect(after).toMatchObject({ problems: 3, canFix: 1, needsInput: 1, manual: 1, review: 1, fixed: 0 });
  expect(after.canFix + after.needsInput + after.manual).toBe(after.problems);
  expect(auditCounts(scan, plan, new Set(['0-MGMT-001']))).toMatchObject({ canFix: 0, fixed: 1 });
  expect(problems(scan, plan)[0]).toMatchObject({ controlId: 'MGMT-001', results: [expect.anything(), expect.anything()] });
});

it('puts a reading into plain words built only from what the backend read', () => {
  expect(sayFact({ predicate: 'mgmt.remote_access.protocol_enabled', subject: 'telnet', value: true }))
    .toBe('turns on Telnet remote access');
  expect(sayFact({ predicate: 'time.ntp.server', value: ['10.0.0.1'] })).toBe('uses NTP server 10.0.0.1');
  // a timeout read without its unit is stated without one
  expect(sayFact({ predicate: 'mgmt.session.idle_timeout', value: 600 })).toBe('sets an idle session timeout (600)');
  // a value the sentence cannot state is not guessed
  expect(sayFact({ predicate: 'mgmt.remote_access.protocol_enabled', subject: 'telnet', value: null })).toBeNull();
  expect(sayFact({ predicate: 'made.up', value: true })).toBeNull();
});

it('explains safety-gate failures in plain English without internal terms', () => {
  const messages = [
    'This line holds a secret value: a recognizer would store it, so it cannot be drafted from this line',
    'The template does not match its example line',
    'The value true contradicts the line, which says disabled',
    'The value must be JSON (true, false, a number, or an enum table)',
    'something entirely new',
  ];
  for (const m of messages) {
    const said = explainGate(m);
    expect(said).not.toMatch(/recognizer|template|slot|JSON|enum|polarity|predicate/i);
    expect(said.length).toBeGreaterThan(20);
  }
  expect(explainGate(messages[0])).toMatch(/secret/);
});

describe('fixOrder', () => {
  const item = (controlId, severity, state, configIndex = 0) => ({
    key: `${configIndex}|${controlId}`, controlId, severity, configIndex,
    primary: { status: 'fail', assurance: 'parser' },
    results: [{ status: 'fail', assurance: 'parser' }],
    remediation: { status: { can_fix: 'fixed', needs_input: 'needs_input', manual: 'manual_review' }[state] },
  });
  it('puts the fix that closes an attack path first, then value per effort, and explains each step', () => {
    const items = [item('MGMT-001', 'critical', 'can_fix'), item('MGMT-003', 'high', 'needs_input'),
      item('LOG-001', 'medium', 'can_fix'), item('AUTH-003', 'low', 'manual')];
    const paths = [{ config_index: 0, title: 'Remote takeover', break_with: ['MGMT-003'] }];
    const order = fixOrder(items, paths);
    expect(order.map((o) => o.item.controlId)).toEqual(['MGMT-003', 'MGMT-001', 'LOG-001', 'AUTH-003']);
    expect(order[0].why).toEqual(['closes the “Remote takeover” attack path', 'high problem', 'needs one answer from you']);
    expect(order[1].why).toEqual(['critical problem', 'fixed in one click']);
  });
});
