// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('../api/client', () => ({ apiClient: { downloadReport: vi.fn(), getDrift: vi.fn().mockResolvedValue({ devices: [] }) } }));

import { apiClient } from '../api/client';
import Results, { PostureSummary } from './Results';
import { reviewCount } from '../lib/domain';

afterEach(cleanup);

it('a high posture with low coverage is a limited assessment, never Good out of 100', () => {
  const { container } = render(<PostureSummary posture={95} coverage={30} bounds={[0, 100]} criticalUnassessed={['MGMT-005']} />);
  expect(screen.getByText('Limited assessment')).toBeTruthy();
  expect(screen.getByText('Posture 95 · Coverage 30% · Limited assessment')).toBeTruthy();
  expect(container.textContent).not.toContain('/100');
  expect(container.textContent).not.toContain('Good');
});

it('a low posture from one confirmed FAIL at low coverage does not claim the whole device is critical', () => {
  const { container } = render(<PostureSummary posture={0} coverage={11} />);
  expect(screen.getByText('Limited assessment')).toBeTruthy();
  expect(container.textContent).not.toContain('Critical risk');
});

it('unassessed critical controls make the assessment partial; only full coverage is full', () => {
  render(<PostureSummary posture={100} coverage={83} criticalUnassessed={['MGMT-005']} />);
  expect(screen.getByText('Good · partial')).toBeTruthy();
  cleanup();
  const { container } = render(<PostureSummary posture={100} coverage={100} criticalUnassessed={[]} />);
  expect(screen.getByText('Posture 100 · Coverage 100% · Full assessment')).toBeTruthy();
  expect(container.textContent).toContain('/100');
  expect(container.textContent).not.toContain('partial');
});

it('no decided control is not assessed and shows no posture number', () => {
  render(<PostureSummary posture={null} coverage={0} />);
  expect(screen.getAllByText(/Not assessed/).length).toBeGreaterThan(0);
  expect(screen.getByText('-')).toBeTruthy();
});

const audit = (extra = {}) => ({ plan: null, planLoading: false, planError: null, applied: new Set(), queue: null, ...extra });

const UNKNOWN = {
  scan_id: 'scan-1234567', timestamp: '2026-09-14T08:00:00', posture: null, coverage: 0, posture_bounds: [0, 100],
  critical_unassessed: ['MGMT-005'],
  devices: [{ hostname: 'CORE-GATE-07', vendor: 'unknown' }],
  vendor_identification: [{ config_index: 0, detected_vendor: 'unknown', status: 'unknown' }],
  findings: [{ rule_id: 'MGMT-001', severity: 'critical', assurance: 'heuristic', config_index: 0 }],
  results: [
    { config_index: 0, control_id: 'MGMT-001', title: 'Telnet enabled', status: 'fail', assurance: 'heuristic', severity: 'critical' },
    { config_index: 0, control_id: 'MGMT-003', title: 'Unrestricted management', status: 'unknown', assurance: 'ai_verified', proposed_status: 'pass', severity: 'critical' },
    { config_index: 0, control_id: 'MGMT-005', title: 'Weak passwords', status: 'not_configured', assurance: null, severity: 'critical' },
  ],
  adaptive_configs: [],
  frameworks: [],
};
const QUEUE = {
  provisional: [
    { config_index: 0, control_id: 'MGMT-001', lines: [{ line_number: 71, text: 'remote-console protocol telnet', predicate: 'mgmt.remote_access.protocol_enabled', subject: 'telnet', value: true }] },
    { config_index: 0, control_id: 'MGMT-003', lines: [
      { line_number: 67, text: 'management-plane source-restriction enabled', predicate: 'mgmt.remote_access.source_restricted', value: true },
      { line_number: 72, text: 'management-plane source-restriction disabled', predicate: 'mgmt.remote_access.source_restricted', value: false },
    ] },
    { config_index: 0, control_id: 'MGMT-006', lines: [{ line_number: 38, text: 'operator inactivity-lock 600', predicate: 'mgmt.session.idle_timeout', value: 600 }] },
  ],
  legacyPending: 0,
  // The resolution queue: exactly the applicable checks coverage left out
  unresolved: [
    { config_index: 0, control_id: 'MGMT-003', title: 'Unrestricted management', question: 'Is management access restricted to known sources?',
      severity: 'critical', category: 'management', status: 'unknown', action: 'teach',
      reason: 'AI proposes PASS, awaiting confirmation', evidence_lines: [], evidence: [],
      suggested_lines: [{ line_number: 67, text: 'management-plane source-restriction enabled', scope_path: [], predicate: 'mgmt.remote_access.source_restricted', subject: null, value: true }] },
    { config_index: 0, control_id: 'MGMT-005', title: 'Weak passwords', question: 'Are passwords stored irreversibly?',
      severity: 'critical', category: 'authentication', status: 'not_configured', action: 'teach',
      reason: 'No relevant setting was found in this configuration', evidence_lines: [], evidence: [], suggested_lines: [] },
  ],
  assessedCount: 1,
};

it('review count: provisional readings need human review; decisive failures blocked from automation do not', () => {
  const decisiveFail = (control_id) => ({ config_index: 0, control_id, status: 'fail', assurance: 'parser', severity: 'critical' });
  const scan = { results: [decisiveFail('MGMT-005'), decisiveFail('MGMT-008'), decisiveFail('BOUNDARY-001')], adaptive_configs: [] };
  expect(reviewCount(scan)).toBe(0);
  expect(reviewCount({ ...scan, results: [...scan.results, { config_index: 0, control_id: 'MGMT-003', status: 'unknown', assurance: 'ai_verified', proposed_status: 'pass' }] })).toBe(1);
});

it('an unfamiliar device: nothing provisional is counted, the real queue drives the next step, undecided checks stay apart', () => {
  const go = vi.fn();
  const onTeach = vi.fn();
  const { container } = render(<Results scan={UNKNOWN} audit={audit({ queue: QUEUE })} onOpen={() => {}} go={go} onTeach={onTeach} />);

  expect(container.textContent).toContain('0 problems found');
  expect(screen.getByText(/has no dedicated reader for this device/)).toBeTruthy();
  expect(screen.getByText(/We couldn’t check a critical setting: Weak passwords/)).toBeTruthy();
  expect(screen.getByText('NetAuditAI needs your help with lines it doesn’t recognize')).toBeTruthy();
  expect(screen.getByText(/3 questions are waiting for your answer/)).toBeTruthy();
  expect(screen.getByText('Unfamiliar configuration: probably turns on Telnet remote access')).toBeTruthy();
  // conflicting lines are never summarised as one probable meaning
  expect(screen.getByText('Unfamiliar configuration: these lines disagree')).toBeTruthy();
  // no empty fix list while the plan is unknown
  expect(container.querySelector('ul.fixmix')).toBeNull();
  // the undecided checks are their own actionable queue, never counted as passed or failed
  const queue = screen.getByRole('region', { name: /2 checks need your input to complete this assessment/ });
  expect(queue.textContent).toContain('Weak passwords');
  expect(queue.textContent).toContain('Nothing here mentions this setting');
  expect(queue.textContent).toContain('1 line in this configuration may answer it');
  fireEvent.click(screen.getByText('Weak passwords'));
  expect(onTeach).toHaveBeenCalledWith('0-MGMT-005');
  onTeach.mockClear();

  fireEvent.click(screen.getByRole('button', { name: 'Teach NetAuditAI' }));
  expect(go).toHaveBeenCalledWith('teach');
  fireEvent.click(screen.getByText('Unfamiliar configuration: probably turns on Telnet remote access'));
  expect(onTeach).toHaveBeenCalledWith('0-MGMT-001');
});

it('a file that holds no configuration is reported, not scored, and asks for nothing else', () => {
  const prose = { ...UNKNOWN, posture: null, coverage: 0, assessed_count: 0, unresolved_count: 15,
    findings: [], results: [], unreadable_configs: [0], critical_unassessed: [] };
  const { container } = render(<Results scan={prose} audit={audit({ queue: QUEUE })} onOpen={() => {}} go={() => {}} onTeach={() => {}} />);
  expect(screen.getByText(/doesn’t contain enough recognizable configuration to assess/)).toBeTruthy();
  expect(screen.getAllByText(/Not assessed/).length).toBeGreaterThan(0);
  // no score, and no queue of checks to work through: the only next step is a different file
  expect(container.textContent).not.toMatch(/What to do now|need your input to complete/);
});

it('offers the compliance report for the scan, and says so when it cannot be generated', async () => {
  apiClient.downloadReport.mockResolvedValueOnce();
  render(<Results scan={UNKNOWN} audit={audit({ queue: QUEUE })} onOpen={() => {}} go={() => {}} onTeach={() => {}} />);
  fireEvent.click(screen.getByRole('button', { name: 'Download PDF report' }));
  await waitFor(() => expect(apiClient.downloadReport).toHaveBeenCalledWith('scan-1234567'));

  apiClient.downloadReport.mockRejectedValueOnce(new Error('nope'));
  fireEvent.click(screen.getByRole('button', { name: 'Download PDF report' }));
  expect(await screen.findByText('The report couldn’t be generated.')).toBeTruthy();
});

const CISCO = {
  ...UNKNOWN, posture: 20, coverage: 100, critical_unassessed: [],
  devices: [{ hostname: 'R1', vendor: 'cisco_ios' }],
  vendor_identification: [{ config_index: 0, detected_vendor: 'cisco_ios', status: 'confirmed' }],
  results: [
    { config_index: 0, control_id: 'MGMT-001', title: 'Telnet enabled', status: 'fail', assurance: 'parser', severity: 'critical', evidence: { line_numbers: [14], lines: [' transport input telnet ssh'] } },
    { config_index: 0, control_id: 'MGMT-001', title: 'Telnet enabled', status: 'fail', assurance: 'parser', severity: 'critical', scope: 'vty 5 15' },
    { config_index: 0, control_id: 'LOG-001', title: 'No syslog', status: 'fail', assurance: 'parser', severity: 'high' },
    { config_index: 0, control_id: 'MGMT-007', title: 'SSH v2', status: 'pass', assurance: 'parser', severity: 'high' },
  ],
};
const PLAN = { devices: [{ remediations: [{ config_index: 0, rule_id: 'MGMT-001', status: 'fixed' }, { config_index: 0, rule_id: 'LOG-001', status: 'needs_input' }] }] };

it('a confirmed vendor: counts problems once per check, splits them by what can be done, and opens one', () => {
  const onOpen = vi.fn();
  const go = vi.fn();
  const { container } = render(<Results scan={CISCO} audit={audit({ plan: PLAN, queue: { provisional: [], legacyPending: 0 } })} onOpen={onOpen} go={go} onTeach={() => {}} />);

  expect(container.textContent).toContain('2 problems found');
  expect(container.textContent).toContain('/100');
  expect(container.textContent).toContain('1 can be fixed automatically');
  expect(container.textContent).toContain('1 need your input');
  expect(screen.getByText('We can fix 1 problem automatically')).toBeTruthy();
  expect(screen.getByText('transport input telnet ssh')).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Fix them' }));
  expect(go).toHaveBeenCalledWith('fix');
  fireEvent.click(screen.getByText('Telnet enabled'));
  expect(onOpen.mock.calls[0][0]).toMatchObject({ controlId: 'MGMT-001', results: [expect.anything(), expect.anything()] });
});

it('a clean configuration says so plainly', () => {
  const clean = { ...CISCO, posture: 100, results: [CISCO.results[3]] };
  render(<Results scan={clean} audit={audit({ plan: { devices: [] }, queue: { provisional: [], legacyPending: 0 } })} onOpen={() => {}} go={() => {}} onTeach={() => {}} />);
  expect(screen.getByText('You’re done.')).toBeTruthy();
  expect(screen.getByText('Nothing needs your attention.', { selector: '.next-body' })).toBeTruthy();
  expect(screen.getByText('Nothing needs your attention.', { selector: '.empty-title' })).toBeTruthy();
});

it('a block citation names the block instead of quoting an arbitrary line inside it', () => {
  const block = {
    ...CISCO,
    results: [{
      config_index: 0, control_id: 'MGMT-006', title: 'Session timeout', status: 'fail', assurance: 'parser', severity: 'medium',
      evidence: { line_numbers: [11, 12, 13], lines: ['line vty 0 4', ' transport input telnet ssh', ' exec-timeout 0 0'] },
    }],
  };
  const { container } = render(<Results scan={block} audit={audit({ plan: { devices: [] }, queue: { provisional: [], legacyPending: 0 } })} onOpen={() => {}} go={() => {}} onTeach={() => {}} />);
  expect(screen.getByText('line vty 0 4')).toBeTruthy();
  expect(container.textContent).toContain('3 lines cited');
  // the last line of the block is not the line that decided this control
  expect(container.querySelector('.problem-line')).toBeNull();
});
