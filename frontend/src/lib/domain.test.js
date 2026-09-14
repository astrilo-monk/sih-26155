import { expect, it } from 'vitest';
import {
  assessment, decisiveSeverityCounts, deviceLabels, deviceRows, parseUnifiedDiff, sameInputs, stripLineNo, vendorState,
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
    { config_index: 3, status: 'fail', assurance: 'parser' },
  ],
};

it('keeps devices with the same hostname apart and never derives risk from suspected findings', () => {
  const rows = deviceRows(SCAN);
  expect(rows.map((r) => [r.decisive, r.suspected, r.risk])).toEqual([
    [0, 2, 'NOT ASSESSED'],
    [0, 1, 'NOT ASSESSED'],
    [0, 0, 'LOW'],
    [1, 0, 'HIGH'],
  ]);
  expect(rows.map((r) => r.analysis)).toEqual(['Generic analysis', 'Generic analysis', 'Dedicated parser', 'Dedicated parser']);
  expect(deviceLabels(SCAN.devices)).toEqual(['unknown (#1)', 'unknown (#2)', 'BRANCH-FGT-02 (#3)', 'BRANCH-FGT-02 (#4)']);
});

it('counts only decisive findings by severity', () => {
  expect(decisiveSeverityCounts(SCAN.findings)).toEqual({ critical: 0, high: 1, medium: 0, low: 0 });
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

it('compares remediation inputs ignoring empty fields', () => {
  expect(sameInputs({ syslog_server: '10.0.0.1', ntp_server: '' }, { syslog_server: '10.0.0.1' })).toBe(true);
  expect(sameInputs({ syslog_server: '10.0.0.2' }, { syslog_server: '10.0.0.1' })).toBe(false);
  expect(sameInputs({}, { syslog_server: '10.0.0.1' })).toBe(false);
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
