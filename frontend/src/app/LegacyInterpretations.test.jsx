// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('../api/client', () => ({
  apiClient: {
    getReviewQueue: vi.fn(),
    getNormalizedFields: vi.fn(),
    acceptInterpretation: vi.fn(),
    editInterpretation: vi.fn(),
    rejectInterpretation: vi.fn(),
  },
}));

import { apiClient } from '../api/client';
import LegacyInterpretations from './LegacyInterpretations';

const ITEM = {
  item_id: '0-3', config_index: 0, hostname: 'EDGE-GW-01', vendor: 'unknown', line_number: 3,
  raw_line: 'secure-shell protocol-version 1', context_before: ['system-name EDGE-GW-01', 'uplink mtu 1500'],
  context_after: ['remote-console protocol telnet'], likely_vendor: 'generic', security_concept: 'ssh_protocol_version',
  normalized_field: 'management.ssh_version', extracted_value: '1', confidence: 0.78, confidence_tier: 'medium',
  reasoning: 'Declares the SSH protocol version', interpretation_status: 'interpreted', source: 'needs_review',
  reason: 'MEDIUM confidence — requires admin review before applying', review_status: 'pending', mapping_id: null, candidates: [],
};
const FIELDS = [
  { field: 'management.ssh_version', value_type: 'optional_int' },
  { field: 'management.telnet_enabled', value_type: 'bool' },
];
const SCAN = { scan_id: 'scan-1' };
const UPDATED = { ...SCAN, posture: 91 };

const renderIt = () => {
  const onScanUpdated = vi.fn();
  render(<LegacyInterpretations scan={SCAN} onScanUpdated={onScanUpdated} />);
  return onScanUpdated;
};

beforeEach(() => {
  apiClient.getReviewQueue.mockResolvedValue({ scan_id: 'scan-1', pending_count: 1, items: [ITEM] });
  apiClient.getNormalizedFields.mockResolvedValue(FIELDS);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it('renders nothing when there are no suggestions', async () => {
  apiClient.getReviewQueue.mockResolvedValue({ items: [] });
  const { container } = render(<LegacyInterpretations scan={SCAN} />);
  await waitFor(() => expect(apiClient.getReviewQueue).toHaveBeenCalled());
  expect(container.textContent).toBe('');
});

it('renders suggestion, confidence and context', async () => {
  renderIt();
  expect(await screen.findByText('secure-shell protocol-version 1')).toBeTruthy();
  expect(screen.getByText('management.ssh_version = 1')).toBeTruthy();
  expect(screen.getByText('78%')).toBeTruthy();
  fireEvent.click(screen.getByLabelText('Toggle details for line 3'));
  expect(screen.getByText('Declares the SSH protocol version')).toBeTruthy();
  expect(screen.getByText('uplink mtu 1500')).toBeTruthy();
});

it('accepts a suggestion and propagates the re-evaluated scan', async () => {
  apiClient.acceptInterpretation.mockResolvedValue({ item: ITEM, mapping: { id: 7 }, auto_resolved: [], scan: UPDATED });
  const onScanUpdated = renderIt();
  fireEvent.click(await screen.findByLabelText('Accept line 3'));
  await waitFor(() => expect(apiClient.acceptInterpretation).toHaveBeenCalledWith('scan-1', '0-3'));
  await waitFor(() => expect(onScanUpdated).toHaveBeenCalledWith(UPDATED));
  expect(await screen.findByText(/NetAuditAI learned line 3 \(rule #7\)/)).toBeTruthy();
});

it('submits an edited interpretation', async () => {
  apiClient.editInterpretation.mockResolvedValue({ item: ITEM, mapping: { id: 8 }, auto_resolved: [], scan: UPDATED });
  renderIt();
  fireEvent.click(await screen.findByLabelText('Edit line 3'));
  fireEvent.change(screen.getByLabelText('Extracted value'), { target: { value: '2' } });
  fireEvent.change(screen.getByLabelText('Command pattern'), { target: { value: 'secure-shell {any} {value}' } });
  fireEvent.click(screen.getByText('Save mapping'));
  await waitFor(() => expect(apiClient.editInterpretation).toHaveBeenCalledWith('scan-1', '0-3', {
    normalized_field: 'management.ssh_version', extracted_value: '2', command_pattern: 'secure-shell {any} {value}', concept: 'ssh_protocol_version',
  }));
});

it('rejects a suggestion', async () => {
  apiClient.rejectInterpretation.mockResolvedValue({ item: { ...ITEM, review_status: 'rejected' }, mapping: null, scan: SCAN });
  renderIt();
  fireEvent.click(await screen.findByLabelText('Reject line 3'));
  await waitFor(() => expect(apiClient.rejectInterpretation).toHaveBeenCalledWith('scan-1', '0-3'));
  expect(await screen.findByText(/will stop guessing about line 3/)).toBeTruthy();
});

it('blocks invalid edits before calling the API', async () => {
  renderIt();
  fireEvent.click(await screen.findByLabelText('Edit line 3'));
  fireEvent.change(screen.getByLabelText('Extracted value'), { target: { value: 'modern' } });
  fireEvent.click(screen.getByText('Save mapping'));
  expect(await screen.findByText('Must be a whole number')).toBeTruthy();

  fireEvent.change(screen.getByLabelText('Normalized field'), { target: { value: '' } });
  fireEvent.change(screen.getByLabelText('Extracted value'), { target: { value: '' } });
  fireEvent.click(screen.getByText('Save mapping'));
  expect(await screen.findByText('Choose a normalized field')).toBeTruthy();
  expect(screen.getByText('Extracted value is required')).toBeTruthy();
  expect(apiClient.editInterpretation).not.toHaveBeenCalled();
});

it('shows AI-unavailable lines as an outage, not as a confidence score', async () => {
  const unavailable = {
    ...ITEM, item_id: '0-4', line_number: 4, raw_line: 'remote-console protocol telnet', normalized_field: 'unknown',
    extracted_value: null, confidence: 0, confidence_tier: 'low', interpretation_status: 'ai_unavailable', source: 'needs_training',
    reasoning: 'AI interpretation unavailable — quota exhausted',
  };
  apiClient.getReviewQueue.mockResolvedValue({ scan_id: 'scan-1', pending_count: 1, items: [unavailable] });
  renderIt();
  expect(await screen.findByText('AI unavailable — map manually')).toBeTruthy();
  expect(screen.getByText('AI unavailable')).toBeTruthy();
  expect(screen.queryByText('0%')).toBeNull();
  expect(screen.getByLabelText('Accept line 4').disabled).toBe(true);
});

it('labels fields from the catalog and shows the block path', async () => {
  apiClient.getNormalizedFields.mockResolvedValue([
    { field: 'management.ssh_version', value_type: 'optional_int', label: 'SSH protocol version', value_rule: 'whole number, digits only' },
  ]);
  apiClient.getReviewQueue.mockResolvedValue({ scan_id: 'scan-1', pending_count: 1, items: [{ ...ITEM, structural_path: ['system', 'services'] }] });
  renderIt();
  fireEvent.click(await screen.findByLabelText('Edit line 3'));
  expect(screen.getByText('SSH protocol version — management.ssh_version (optional_int)')).toBeTruthy();
  expect(screen.getByText('Value: whole number, digits only')).toBeTruthy();
  expect(screen.getByText('system › services')).toBeTruthy();
});
