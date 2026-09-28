// @vitest-environment jsdom
import { useState } from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

vi.mock('../api/client', () => ({
  apiClient: {
    getRemediationPlan: vi.fn(),
    getProvisionalResults: vi.fn(),
    getReviewQueue: vi.fn(),
    getUnresolvedControls: vi.fn(),
    getConfigLines: vi.fn(),
    getMeaningOptions: vi.fn(),
    getNormalizedFields: vi.fn(),
    draftRecognizer: vi.fn(),
    saveRecognizer: vi.fn(),
    rejectProvisionalLine: vi.fn(),
    askAI: vi.fn(),
  },
}));

import { apiClient } from '../api/client';
import { useAudit } from '../lib/useAudit';
import Teach from './Teach';

const SCAN = {
  scan_id: 'scan-1',
  devices: [{ hostname: 'CORE-GATE-07', vendor: 'unknown' }],
  vendor_identification: [{ config_index: 0, detected_vendor: 'unknown', status: 'unknown' }],
  posture: 27, coverage: 24, assessed_count: 3, unresolved_count: 2,
  results: [], findings: [], adaptive_configs: [],
};
// the re-evaluated scan the backend returns once a meaning is saved: one more check decided
const UPDATED = {
  ...SCAN, posture: 40, coverage: 32, assessed_count: 4, unresolved_count: 1,
  results: [{ config_index: 0, control_id: 'MGMT-001', status: 'fail', assurance: 'confirmed', reason: 'Telnet is allowed for remote management' }],
};

// The resolution queue: two checks the scan could not decide
const TELNET = {
  config_index: 0, control_id: 'MGMT-001', hostname: 'CORE-GATE-07',
  title: 'Telnet enabled', question: 'Is cleartext Telnet disabled for remote management?',
  severity: 'critical', category: 'management', status: 'unknown', action: 'teach',
  reason: 'No line of this configuration states whether Telnet is allowed',
  evidence_lines: [], evidence: [], needs: ['mgmt.remote_access.protocol_enabled'],
  suggested_lines: [{ line_number: 71, text: 'remote-console protocol telnet', scope_path: [], predicate: null, subject: null, value: null }],
};
const TIMEOUT = {
  config_index: 0, control_id: 'MGMT-006', hostname: 'CORE-GATE-07',
  title: 'Idle sessions', question: 'Do idle management sessions time out?',
  severity: 'medium', category: 'management', status: 'not_configured', action: 'teach',
  reason: 'No relevant setting was found in this configuration',
  evidence_lines: [], evidence: [], needs: ['mgmt.session.idle_timeout'],
  suggested_lines: [{ line_number: 38, text: 'operator inactivity-lock 600', scope_path: [], predicate: null, subject: null, value: null }],
};
const TELNET_MEANINGS = {
  control_id: 'MGMT-001', line_number: 71, text: 'remote-console protocol telnet',
  options: [
    { predicate: 'mgmt.remote_access.protocol_enabled', subject: 'telnet', value: true },
    { predicate: 'mgmt.remote_access.protocol_enabled', subject: 'telnet', value: false },
  ],
};
const TIMEOUT_MEANINGS = {
  control_id: 'MGMT-006', line_number: 38, text: 'operator inactivity-lock 600',
  options: [{ predicate: 'mgmt.session.idle_timeout', subject: null, value: null }],
};
const DRAFT = {
  draft: {
    concept: 'Telnet', predicate: 'mgmt.remote_access.protocol_enabled', subject: 'telnet',
    command_pattern: 'remote-console protocol {enum:protocol}', scope_template: null, value: '{"telnet": true, "*": false}',
    example_line: 'remote-console protocol telnet', negatives: [],
  },
  errors: [], configs_checked: 1,
  replay: [{ hostname: 'CORE-GATE-07', control_id: 'MGMT-001', before: 'unknown', after: 'fail (confirmed)' }],
};
// what the person's answer asks the backend to learn: the line, and the meaning they stated
const ASK = {
  config_index: 0, control_id: 'MGMT-001', line_number: 71,
  predicate: 'mgmt.remote_access.protocol_enabled', asserted_value: true, subject: 'telnet',
};

const queueOf = (...items) => ({ scan_id: 'scan-1', assessed_count: 3, unresolved_count: items.length, items });

function Harness({ scan0 = SCAN, onUpdated = () => {} }) {
  const [scan, setScan] = useState(scan0);
  const [revision, setRevision] = useState(1);
  const audit = useAudit(scan, revision);
  return (
    <Teach scan={scan} audit={audit}
           onScanUpdated={(next) => { onUpdated(next); setScan(next); setRevision((r) => r + 1); }} />
  );
}

beforeEach(() => {
  apiClient.getRemediationPlan.mockResolvedValue({ scan_id: 'scan-1', inputs: [], devices: [] });
  apiClient.getReviewQueue.mockResolvedValue({ items: [] });
  apiClient.getNormalizedFields.mockResolvedValue([]);
  apiClient.getProvisionalResults.mockResolvedValue({ items: [] });
  apiClient.getUnresolvedControls.mockResolvedValue(queueOf(TELNET, TIMEOUT));
  apiClient.getConfigLines.mockResolvedValue({
    config_index: 0, hostname: 'CORE-GATE-07', vendor: 'unknown',
    lines: [{ line_number: 71, text: 'remote-console protocol telnet', teachable: true }],
  });
  apiClient.getMeaningOptions.mockImplementation((_id, { controlId }) =>
    Promise.resolve(controlId === 'MGMT-001' ? TELNET_MEANINGS : TIMEOUT_MEANINGS));
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

// the two questions, in order: is this the right line? then what does it say?
// answers load over two requests: allow for a busy machine
const SLOW = { timeout: 4000 };
const yesLine = async () => fireEvent.click(await screen.findByRole('button', { name: 'Yes, that’s the line' }, SLOW));
const answer = async (name) => fireEvent.click(await screen.findByRole('button', { name: new RegExp(`^${name}`) }, SLOW));

it('asks is-this-the-line, then what it says, learns the answer and moves to the next check', async () => {
  apiClient.getUnresolvedControls.mockResolvedValueOnce(queueOf(TELNET, TIMEOUT)).mockResolvedValue(queueOf(TIMEOUT));
  apiClient.draftRecognizer.mockResolvedValue(DRAFT);
  apiClient.saveRecognizer.mockResolvedValue({ mapping: { id: 7, command_pattern: DRAFT.draft.command_pattern }, replay: DRAFT.replay, scan: UPDATED });
  const onUpdated = vi.fn();
  const { container } = render(<Harness onUpdated={onUpdated} />);

  expect(await screen.findByText('Is cleartext Telnet disabled for remote management?')).toBeTruthy();
  expect(screen.getByText('Check 1 of 2')).toBeTruthy();
  expect(screen.getByText('NetAuditAI thinks this line answers it:')).toBeTruthy();
  expect(screen.getByText('Is this the right line?')).toBeTruthy();
  // no internal machinery in the default view
  expect(container.textContent).not.toMatch(/recognizer|slot|JSON|predicate|provisional|heuristic|safety gate/i);
  // nothing is asked about meaning until the line is confirmed
  expect(screen.queryByText('What does this line say?')).toBeNull();

  await yesLine();
  expect(await screen.findByText('What does this line say?')).toBeTruthy();
  await answer('It turns on Telnet remote access');

  expect(await screen.findByText('NetAuditAI learned this')).toBeTruthy();
  expect(apiClient.draftRecognizer).toHaveBeenCalledWith('scan-1', ASK);
  expect(apiClient.saveRecognizer).toHaveBeenCalledWith('scan-1', ASK);
  expect(onUpdated).toHaveBeenCalledWith(UPDATED);

  // the check it could not decide is decided now, and the updated score is the backend's
  expect(screen.getByText('MGMT-001').closest('p').textContent).toMatch(/is now Failed/);
  expect(screen.getByText('40').closest('li').textContent).toContain('security posture (was 27)');
  expect(screen.getByText('32%').closest('li').textContent).toContain('checked (was 24%)');
  expect(screen.getByText('1').closest('li').textContent).toContain('still need input (was 2)');

  // the re-evaluated scan refreshes the queue: one check left
  fireEvent.click(await screen.findByRole('button', { name: 'Continue to the next check' }));
  expect(await screen.findByText('Do idle management sessions time out?')).toBeTruthy();
  expect(screen.getByText('Check 1 of 1')).toBeTruthy();
  await yesLine();
  expect(await screen.findByRole('button', { name: /^It sets how long an idle session may stay open/ })).toBeTruthy();
});

it('a saved meaning that still does not decide the check is never counted', async () => {
  apiClient.draftRecognizer.mockResolvedValue(DRAFT);
  apiClient.saveRecognizer.mockResolvedValue({ mapping: { id: 7 }, replay: [], scan: { ...SCAN, results: [] } });
  render(<Harness />);
  await yesLine();
  await answer('It turns on Telnet remote access');
  expect(await screen.findByText(/is still undecided/)).toBeTruthy();
  expect(screen.getByText(/Nothing was counted/)).toBeTruthy();
});

it('explains a failed safety check in plain English, saves nothing, and lets the person try again', async () => {
  apiClient.draftRecognizer.mockResolvedValue({ ...DRAFT, errors: ['This line holds a secret value: a recognizer would store it, so it cannot be drafted from this line'], replay: [] });
  const { container } = render(<Harness />);
  await yesLine();
  await answer('It turns on Telnet remote access');

  expect(await screen.findByText('NetAuditAI couldn’t safely save this.')).toBeTruthy();
  expect(screen.getByText(/contains a secret, such as a password or key/)).toBeTruthy();
  expect(screen.getByText(/never counted as passed or failed/)).toBeTruthy();
  expect(apiClient.saveRecognizer).not.toHaveBeenCalled();
  expect(container.textContent).not.toMatch(/recognizer would store it/);
  fireEvent.click(screen.getByRole('button', { name: 'Advanced details' }));
  expect(screen.getByText(/recognizer would store it/)).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Try another line' }));
  expect(await screen.findByText('Is this the right line?')).toBeTruthy();
});

it('treats a refused save the same way: nothing is claimed as learned', async () => {
  apiClient.draftRecognizer.mockResolvedValue(DRAFT);
  apiClient.saveRecognizer.mockRejectedValue(Object.assign(new Error('A recognizer already maps this template'), { status: 409 }));
  render(<Harness />);
  await yesLine();
  await answer('It turns on Telnet remote access');
  expect(await screen.findByText('NetAuditAI couldn’t safely save this.')).toBeTruthy();
  expect(screen.getByText(/already knows a different meaning/)).toBeTruthy();
  expect(screen.queryByText('NetAuditAI learned this')).toBeNull();
});

it('marks NetAuditAI’s own guess, and rejects a misread line', async () => {
  const read = { ...TELNET, suggested_lines: [{ ...TELNET.suggested_lines[0], predicate: 'mgmt.remote_access.protocol_enabled', subject: 'telnet', value: true }] };
  apiClient.getUnresolvedControls.mockResolvedValue(queueOf(read, TIMEOUT));
  apiClient.rejectProvisionalLine.mockResolvedValue(UPDATED);
  const onUpdated = vi.fn();
  render(<Harness onUpdated={onUpdated} />);
  expect(await screen.findByText(/We think it turns on Telnet remote access/)).toBeTruthy();
  await yesLine();
  expect(await screen.findByRole('button', { name: 'It turns on Telnet remote access (NetAuditAI’s guess)' })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Something else: NetAuditAI misread this line' }));
  expect(await screen.findByText('Got it.')).toBeTruthy();
  expect(apiClient.rejectProvisionalLine).toHaveBeenCalledWith('scan-1', { config_index: 0, control_id: 'MGMT-001', line_number: 71 });
  expect(onUpdated).toHaveBeenCalledWith(UPDATED);
  expect(apiClient.saveRecognizer).not.toHaveBeenCalled();
});

it('lets an expert edit the rule under Advanced details; the edit goes through the same checks', async () => {
  apiClient.draftRecognizer.mockResolvedValue(DRAFT);
  apiClient.saveRecognizer.mockResolvedValue({ mapping: { id: 8 }, replay: [], scan: UPDATED });
  render(<Harness />);
  await yesLine();
  fireEvent.click(await screen.findByRole('button', { name: 'Advanced details' }, SLOW));
  fireEvent.click(screen.getByRole('button', { name: 'Show the rule NetAuditAI would save' }));
  const template = await screen.findByLabelText('Template');
  expect(template.value).toBe('remote-console protocol {enum:protocol}');
  fireEvent.change(template, { target: { value: 'remote-console protocol {enum:proto}' } });

  await answer('It turns on Telnet remote access');
  expect(await screen.findByText('NetAuditAI learned this')).toBeTruthy();
  const edited = { ...ASK, command_pattern: 'remote-console protocol {enum:proto}', scope_template: '', value: '{"telnet": true, "*": false}', any_dialect: false };
  expect(apiClient.draftRecognizer).toHaveBeenLastCalledWith('scan-1', edited);
  expect(apiClient.saveRecognizer).toHaveBeenCalledWith('scan-1', edited);
});

it('"No, it’s a different line" opens the file, and the picked line is asked about', async () => {
  render(<Harness />);
  fireEvent.click(await screen.findByRole('button', { name: 'No, it’s a different line' }));
  expect(await screen.findByRole('list', { name: 'Uploaded configuration' })).toBeTruthy();
  expect(apiClient.getConfigLines).toHaveBeenCalledWith('scan-1', 0);
  fireEvent.click(screen.getByRole('button', { name: /71\s*remote-console protocol telnet/ }));
  expect(await screen.findByText('What does this line say?')).toBeTruthy();
});

it('without a suggestion it says so, and offers the file, the AI, or a skip', async () => {
  apiClient.getUnresolvedControls.mockResolvedValue(queueOf({ ...TELNET, suggested_lines: [] }, TIMEOUT));
  apiClient.askAI.mockResolvedValue({ found: false, note: 'The AI found no line in this configuration that answers this check' });
  render(<Harness />);
  // the check with a suggested line comes first; the one without is under "Everything else"
  expect(await screen.findByText('Do idle management sessions time out?')).toBeTruthy();
  fireEvent.click(screen.getByRole('tab', { name: /Everything else/ }));
  expect(await screen.findByText('NetAuditAI couldn’t find a line in your file that answers this.')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'I’ll show you the line' })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Ask AI to find the line' }));
  expect(await screen.findByText(/AI: The AI found no line/)).toBeTruthy();
  expect(apiClient.askAI).toHaveBeenCalledWith('scan-1', 0, 'MGMT-001');
  expect(apiClient.draftRecognizer).not.toHaveBeenCalled();
});

it('asks the checks NetAuditAI found a line for first, and keeps the rest one tab away', async () => {
  apiClient.getUnresolvedControls.mockResolvedValue(queueOf({ ...TELNET, suggested_lines: [] }, TIMEOUT));
  render(<Harness />);
  expect(await screen.findByRole('tab', { name: /Found in your file\s*1/ })).toBeTruthy();
  expect(screen.getByRole('tab', { name: /Everything else\s*1/ })).toBeTruthy();
  expect(screen.getByText('Check 1 of 1')).toBeTruthy();
  // once the found ones are answered or skipped, the page says what is left and does not bury it
  fireEvent.click(screen.getByRole('button', { name: 'My file doesn’t have this: skip' }));
  expect(await screen.findByText('Every line NetAuditAI found is answered.')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Look at everything else' }));
  expect(await screen.findByText('NetAuditAI couldn’t find a line in your file that answers this.')).toBeTruthy();
});

it('skips checks in one click, and says skipped checks are not counted', async () => {
  render(<Harness />);
  fireEvent.click(await screen.findByRole('button', { name: 'My file doesn’t have this: skip' }));
  expect(await screen.findByText('Do idle management sessions time out?')).toBeTruthy();
  expect(screen.getByText('Check 1 of 1')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'My file doesn’t have this: skip' }));
  expect(await screen.findByText('No more checks for now.')).toBeTruthy();
  expect(screen.getByText(/Skipped checks stay undecided and uncounted/)).toBeTruthy();
  expect(apiClient.draftRecognizer).not.toHaveBeenCalled();
});

it('has nothing to teach when a dedicated parser read the configuration', async () => {
  apiClient.getUnresolvedControls.mockResolvedValue(queueOf());
  render(<Harness scan0={{ ...SCAN, vendor_identification: [{ config_index: 0, detected_vendor: 'cisco_ios', status: 'confirmed' }] }} />);
  expect(await screen.findByText('Nothing is waiting for your input.')).toBeTruthy();
  expect(screen.getByText(/dedicated Cisco IOS parser/)).toBeTruthy();
});
