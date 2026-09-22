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
    downloadFixedConfigs: vi.fn(),
    draftRecognizer: vi.fn(),
    saveRecognizer: vi.fn(),
    rejectProvisionalLine: vi.fn(),
  },
}));

import { apiClient } from '../api/client';
import { useAudit } from '../lib/useAudit';
import Guide from './Guide';

const SCAN = {
  scan_id: 'scan-1',
  devices: [{ hostname: 'CORE-GATE-07', vendor: 'unknown' }],
  vendor_identification: [{ config_index: 0, detected_vendor: 'unknown', status: 'unknown' }],
  posture: 27, coverage: 24, assessed_count: 3, unresolved_count: 1,
  results: [{ config_index: 0, control_id: 'MGMT-002', title: 'HTTP server', question: 'Is the HTTP server disabled?',
              status: 'fail', assurance: 'parser', severity: 'high', reason: 'HTTP is enabled', device_hostname: 'CORE-GATE-07' }],
  findings: [], adaptive_configs: [],
};

const TELNET = {
  config_index: 0, control_id: 'MGMT-001', hostname: 'CORE-GATE-07',
  title: 'Telnet enabled', question: 'Is cleartext Telnet disabled for remote management?',
  severity: 'critical', category: 'management', status: 'unknown', action: 'teach',
  reason: 'No line of this configuration states whether Telnet is allowed',
  evidence_lines: [], evidence: [], needs: ['mgmt.remote_access.protocol_enabled'],
  suggested_lines: [{ line_number: 71, text: 'remote-console protocol telnet', scope_path: [], predicate: null, subject: null, value: null }],
};

// one problem the backend already fixed and re-verified, so a corrected file exists
const PLAN = {
  scan_id: 'scan-1', inputs: [],
  devices: [{
    config_index: 0, device_hostname: 'CORE-GATE-07', vendor_status: 'confirmed',
    fixed_config: 'no ip http server\n', fixed_controls: ['MGMT-002'], candidates: [],
    before: { posture: 27 }, after: { posture: 61 },
    remediations: [{ config_index: 0, rule_id: 'MGMT-002', status: 'fixed' }],
  }],
};

function Harness({ unresolved }) {
  const [scan, setScan] = useState(SCAN);
  const [revision, setRevision] = useState(1);
  const audit = useAudit(scan, revision);
  return <Guide scan={scan} audit={audit} base="/app/scan/scan-1"
                onScanUpdated={(next) => { setScan(next); setRevision((r) => r + 1); }} />;
}

beforeEach(() => {
  apiClient.getRemediationPlan.mockResolvedValue(PLAN);
  apiClient.getReviewQueue.mockResolvedValue({ items: [] });
  apiClient.getProvisionalResults.mockResolvedValue({ items: [] });
  apiClient.getConfigLines.mockResolvedValue({ config_index: 0, lines: [] });
  apiClient.getMeaningOptions.mockResolvedValue({ options: [] });
  apiClient.downloadFixedConfigs.mockResolvedValue(undefined);
});

afterEach(() => { cleanup(); vi.clearAllMocks(); });

const queueOf = (...items) => ({ scan_id: 'scan-1', assessed_count: 3, unresolved_count: items.length, items });

it('asks the open questions first, then skips straight to the fixed file', async () => {
  apiClient.getUnresolvedControls.mockResolvedValue(queueOf(TELNET));
  render(<Harness />);

  // step 2: the question, not a report
  expect(await screen.findByText('Is cleartext Telnet disabled for remote management?')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Skip to my fixed file' }));

  expect(await screen.findByText('Your fixed file is ready.')).toBeTruthy();
  const button = screen.getByRole('button', { name: 'Download my fixed file' });
  fireEvent.click(button);
  expect(await screen.findByText('Saved to your downloads.')).toBeTruthy();
  expect(apiClient.downloadFixedConfigs).toHaveBeenCalledWith('scan-1', {});
});

it('goes straight to the fixed file when nothing needs answering', async () => {
  apiClient.getUnresolvedControls.mockResolvedValue(queueOf());
  render(<Harness />);
  expect(await screen.findByText('Your fixed file is ready.')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Skip to my fixed file' })).toBe(null);
});
