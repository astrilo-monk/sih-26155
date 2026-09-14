// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('../api/client', () => ({ apiClient: { getRemediation: vi.fn() } }));

import { apiClient } from '../api/client';
import FindingDetail from './FindingDetail';

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const FINDING = {
  rule_id: 'MGMT-001', title: 'Telnet enabled', severity: 'critical', description: 'd', security_impact: 'i',
  recommendation: 'r', device_hostname: 'BRANCH-FGT-02', vendor: 'fortinet', config_index: 1, assurance: 'parser',
  evidence_lines: ['  21: set allowaccess ping https ssh http telnet'], line_numbers: [21], compliance: [],
};

it("remediates the finding's own upload, not the first config sharing its hostname", async () => {
  const remediation = { status: 'fixed' };
  apiClient.getRemediation.mockResolvedValue(remediation);
  const onRemediation = vi.fn();
  render(<FindingDetail finding={FINDING} scanId="scan-1" onClose={vi.fn()} onRemediation={onRemediation} />);

  fireEvent.click(screen.getByText('Generate Remediation'));
  await waitFor(() => expect(onRemediation).toHaveBeenCalledWith(remediation));
  expect(apiClient.getRemediation).toHaveBeenCalledWith('scan-1', 'MGMT-001', 'BRANCH-FGT-02', 1);
});
