// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('../api/client', () => ({
  apiClient: {
    getProvisionalResults: vi.fn(),
    draftRecognizer: vi.fn(),
    saveRecognizer: vi.fn(),
    rejectProvisionalLine: vi.fn(),
  },
}));

import { apiClient } from '../api/client';
import RecognizerQueue from './RecognizerQueue';

const ITEM = {
  config_index: 0,
  control_id: 'MGMT-001',
  question: 'Is Telnet disabled for remote management?',
  status: 'fail',
  assurance: 'heuristic',
  reason: 'Telnet is allowed for remote management',
  lines: [{ line_number: 71, text: 'remote-console protocol telnet', predicate: 'mgmt.remote_access.protocol_enabled', subject: 'telnet', value: true }],
};

const DRAFT = {
  draft: {
    concept: 'Telnet',
    predicate: 'mgmt.remote_access.protocol_enabled',
    subject: 'telnet',
    command_pattern: 'remote-console protocol {enum:protocol}',
    scope_template: null,
    value: '{"telnet": true, "*": false}',
    example_line: 'remote-console protocol telnet',
  },
  errors: [],
  configs_checked: 1,
  replay: [{ hostname: 'unknown', control_id: 'MGMT-001', before: 'fail (heuristic)', after: 'fail (confirmed)' }],
};

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it('confirms a provisional line: draft, replay, save, rescan', async () => {
  apiClient.getProvisionalResults.mockResolvedValueOnce({ items: [ITEM] }).mockResolvedValue({ items: [] });
  apiClient.draftRecognizer.mockResolvedValue(DRAFT);
  apiClient.saveRecognizer.mockResolvedValue({ mapping: { id: 7 }, replay: DRAFT.replay, scan: { scan_id: 'scan-1' } });
  const onScanUpdated = vi.fn();
  render(<RecognizerQueue scanId="scan-1" onScanUpdated={onScanUpdated} />);

  fireEvent.click(await screen.findByLabelText('Confirm line 71 for MGMT-001'));
  expect(await screen.findByDisplayValue('remote-console protocol {enum:protocol}')).toBeTruthy();
  expect(screen.getByText(/fail \(heuristic\) → fail \(confirmed\)/)).toBeTruthy();
  expect(apiClient.draftRecognizer).toHaveBeenCalledWith('scan-1', { config_index: 0, control_id: 'MGMT-001', line_number: 71 });

  fireEvent.click(screen.getByText('Save Recognizer'));
  await waitFor(() => expect(onScanUpdated).toHaveBeenCalledWith({ scan_id: 'scan-1' }));
  expect(apiClient.saveRecognizer.mock.calls[0][1].command_pattern).toBe('remote-console protocol {enum:protocol}');
  expect(await screen.findByText(/Recognizer #7 saved/)).toBeTruthy();
});
