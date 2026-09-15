// @vitest-environment jsdom
import { useState } from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('../api/client', () => ({
  apiClient: {
    getRemediationPlan: vi.fn(),
    getProvisionalResults: vi.fn(),
    getReviewQueue: vi.fn(),
    getNormalizedFields: vi.fn(),
    draftRecognizer: vi.fn(),
    saveRecognizer: vi.fn(),
    rejectProvisionalLine: vi.fn(),
  },
}));

import { apiClient } from '../api/client';
import { useAudit } from '../lib/useAudit';
import Teach from './Teach';

const SCAN = {
  scan_id: 'scan-1',
  devices: [{ hostname: 'CORE-GATE-07', vendor: 'unknown' }],
  vendor_identification: [{ config_index: 0, detected_vendor: 'unknown', status: 'unknown' }],
  results: [], findings: [], adaptive_configs: [],
};
const UPDATED = { ...SCAN, posture: 91 };

const TELNET = {
  config_index: 0, control_id: 'MGMT-001', question: 'Is cleartext Telnet disabled for remote management?', status: 'fail', assurance: 'heuristic',
  reason: 'Telnet is allowed for remote management',
  lines: [{ line_number: 71, text: 'remote-console protocol telnet', predicate: 'mgmt.remote_access.protocol_enabled', subject: 'telnet', value: true }],
};
const TIMEOUT = {
  config_index: 0, control_id: 'MGMT-006', question: 'Do idle management sessions time out?', status: 'unknown', assurance: null,
  reason: 'The idle timeout of admin sessions is stated without a known unit',
  lines: [
    { line_number: 38, text: 'operator inactivity-lock 600', predicate: 'mgmt.session.idle_timeout', subject: null, value: 600 },
    { line_number: 39, text: 'operator inactivity-lock-console 900', predicate: 'mgmt.session.idle_timeout', subject: null, value: 900 },
  ],
};
const DRAFT = {
  draft: {
    concept: 'Telnet', predicate: 'mgmt.remote_access.protocol_enabled', subject: 'telnet',
    command_pattern: 'remote-console protocol {enum:protocol}', scope_template: null, value: '{"telnet": true, "*": false}',
    example_line: 'remote-console protocol telnet', negatives: [],
  },
  errors: [], configs_checked: 1,
  replay: [{ hostname: 'CORE-GATE-07', control_id: 'MGMT-001', before: 'fail (heuristic)', after: 'fail (confirmed)' }],
};
const ASK = { config_index: 0, control_id: 'MGMT-001', line_number: 71 };

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
  apiClient.getProvisionalResults.mockResolvedValue({ items: [TELNET, TIMEOUT] });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it('asks what an unfamiliar line does in plain words, learns the answer and moves to the next question', async () => {
  apiClient.getProvisionalResults.mockResolvedValueOnce({ items: [TELNET, TIMEOUT] }).mockResolvedValue({ items: [TIMEOUT] });
  apiClient.draftRecognizer.mockResolvedValue(DRAFT);
  apiClient.saveRecognizer.mockResolvedValue({ mapping: { id: 7, command_pattern: DRAFT.draft.command_pattern }, replay: DRAFT.replay, scan: UPDATED });
  const onUpdated = vi.fn();
  const { container } = render(<Harness onUpdated={onUpdated} />);

  expect(await screen.findByText('We don’t recognize this configuration yet')).toBeTruthy();
  expect(screen.getByText('Question 1 of 2')).toBeTruthy();
  expect(screen.getByText('We think this line turns on Telnet remote access.')).toBeTruthy();
  // no internal machinery in the default view
  expect(container.textContent).not.toMatch(/recognizer|template|slot|JSON|predicate|provisional|heuristic|safety gate/i);
  expect(screen.getByRole('button', { name: 'Continue' }).disabled).toBe(true);

  fireEvent.click(screen.getByLabelText('Yes — it turns on Telnet remote access'));
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

  expect(await screen.findByText('NetAuditAI learned this')).toBeTruthy();
  expect(screen.getByText('This configuration pattern will be recognized on future scans.')).toBeTruthy();
  expect(apiClient.draftRecognizer).toHaveBeenCalledWith('scan-1', ASK);
  expect(apiClient.saveRecognizer).toHaveBeenCalledWith('scan-1', ASK);
  expect(onUpdated).toHaveBeenCalledWith(UPDATED);

  // the re-evaluated scan refreshes the queue: one question left
  fireEvent.click(await screen.findByRole('button', { name: 'Continue to next issue' }));
  expect(await screen.findByText('Question 1 of 1')).toBeTruthy();
  expect(screen.getByText('We think this line sets an idle session timeout (600).')).toBeTruthy();
});

it('explains a failed safety check in plain English, saves nothing, and lets the person try again or cancel', async () => {
  apiClient.draftRecognizer.mockResolvedValue({ ...DRAFT, errors: ['This line holds a secret value: a recognizer would store it, so it cannot be drafted from this line'], replay: [] });
  const { container } = render(<Harness />);
  fireEvent.click(await screen.findByLabelText('Yes — it turns on Telnet remote access'));
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

  expect(await screen.findByText('NetAuditAI couldn’t safely save this rule.')).toBeTruthy();
  expect(screen.getByText(/contains a secret, such as a password or key/)).toBeTruthy();
  expect(apiClient.saveRecognizer).not.toHaveBeenCalled();
  expect(container.textContent).not.toMatch(/recognizer would store it/);
  fireEvent.click(screen.getByRole('button', { name: 'Advanced details' }));
  expect(screen.getByText(/recognizer would store it/)).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
  expect(screen.getByText('We don’t recognize this configuration yet')).toBeTruthy();
  expect(screen.getByLabelText('Yes — it turns on Telnet remote access').checked).toBe(true);
});

it('treats a refused save the same way: nothing is claimed as learned', async () => {
  apiClient.draftRecognizer.mockResolvedValue(DRAFT);
  apiClient.saveRecognizer.mockRejectedValue(Object.assign(new Error('A recognizer already maps this template'), { status: 409 }));
  render(<Harness />);
  fireEvent.click(await screen.findByLabelText('Yes — it turns on Telnet remote access'));
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  expect(await screen.findByText('NetAuditAI couldn’t safely save this rule.')).toBeTruthy();
  expect(screen.getByText(/already knows a different meaning/)).toBeTruthy();
  expect(screen.queryByText('NetAuditAI learned this')).toBeNull();
});

it('rejects a misread line and propagates the re-evaluated scan', async () => {
  apiClient.rejectProvisionalLine.mockResolvedValue(UPDATED);
  const onUpdated = vi.fn();
  render(<Harness onUpdated={onUpdated} />);
  fireEvent.click(await screen.findByLabelText('Something else — NetAuditAI misread this line'));
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  expect(await screen.findByText('Got it.')).toBeTruthy();
  expect(apiClient.rejectProvisionalLine).toHaveBeenCalledWith('scan-1', ASK);
  expect(onUpdated).toHaveBeenCalledWith(UPDATED);
  expect(apiClient.saveRecognizer).not.toHaveBeenCalled();
});

it('lets an expert edit the rule under Advanced details; the edit goes through the same checks', async () => {
  apiClient.draftRecognizer.mockResolvedValue(DRAFT);
  apiClient.saveRecognizer.mockResolvedValue({ mapping: { id: 8 }, replay: [], scan: UPDATED });
  render(<Harness />);
  fireEvent.click(await screen.findByRole('button', { name: 'Advanced details' }));
  fireEvent.click(screen.getByRole('button', { name: 'Show the rule NetAuditAI would save' }));
  const template = await screen.findByLabelText('Template');
  expect(template.value).toBe('remote-console protocol {enum:protocol}');
  fireEvent.change(template, { target: { value: 'remote-console protocol {enum:proto}' } });

  fireEvent.click(screen.getByLabelText('Yes — it turns on Telnet remote access'));
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  expect(await screen.findByText('NetAuditAI learned this')).toBeTruthy();
  const edited = { ...ASK, command_pattern: 'remote-console protocol {enum:proto}', scope_template: '', value: '{"telnet": true, "*": false}', any_dialect: false };
  expect(apiClient.draftRecognizer).toHaveBeenLastCalledWith('scan-1', edited);
  expect(apiClient.saveRecognizer).toHaveBeenCalledWith('scan-1', edited);
});

it('skips a question without answering it', async () => {
  render(<Harness />);
  fireEvent.click(await screen.findByLabelText('I’m not sure — skip for now'));
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  expect(await screen.findByText('We think this line sets an idle session timeout (600).')).toBeTruthy();
  expect(screen.getByText('Question 1 of 1')).toBeTruthy();
  fireEvent.click(screen.getByLabelText('I’m not sure — skip for now'));
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  // the same check's second line: still one question left, not a new one
  expect(await screen.findByText('We think this line sets an idle session timeout (900).')).toBeTruthy();
  expect(screen.getByText('Question 1 of 1')).toBeTruthy();
  fireEvent.click(screen.getByLabelText('I’m not sure — skip for now'));
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  expect(await screen.findByText('No more questions for now.')).toBeTruthy();
  expect(apiClient.draftRecognizer).not.toHaveBeenCalled();
});

it('has nothing to teach when a dedicated parser read the configuration', async () => {
  apiClient.getProvisionalResults.mockResolvedValue({ items: [] });
  render(<Harness scan0={{ ...SCAN, vendor_identification: [{ config_index: 0, detected_vendor: 'cisco_ios', status: 'confirmed' }] }} />);
  expect(await screen.findByText('Nothing needs your answer.')).toBeTruthy();
  expect(screen.getByText(/dedicated Cisco IOS parser/)).toBeTruthy();
});
