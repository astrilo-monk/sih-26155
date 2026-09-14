// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('../api/client', () => ({
  apiClient: {
    getReviewQueue: vi.fn(),
    getNormalizedFields: vi.fn(),
    listLearnedMappings: vi.fn(),
    acceptInterpretation: vi.fn(),
    editInterpretation: vi.fn(),
    rejectInterpretation: vi.fn(),
    getProvisionalResults: vi.fn(),
    draftRecognizer: vi.fn(),
    saveRecognizer: vi.fn(),
    rejectProvisionalLine: vi.fn(),
  },
}));

import { apiClient } from '../api/client';
import Review from './Review';

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

const SCAN = {
  scan_id: 'scan-1',
  devices: [{ hostname: 'EDGE-GW-01', vendor: 'unknown' }],
  vendor_identification: [{ config_index: 0, status: 'unknown' }],
  adaptive_configs: [{ ai_called: true, learned_matches: 0, provisional_reasons: ['1 line(s) awaiting review'] }],
};
const UPDATED_SCAN = { ...SCAN, posture: 91 };

const PROVISIONAL = {
  config_index: 0, control_id: 'MGMT-001', question: 'Is cleartext Telnet disabled for remote management?', status: 'fail', assurance: 'heuristic',
  reason: 'Telnet is allowed for remote management',
  lines: [{ line_number: 71, text: 'remote-console protocol telnet', predicate: 'mgmt.remote_access.protocol_enabled', subject: 'telnet', value: true }],
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

const renderReview = (props = {}) => {
  const onScanUpdated = vi.fn();
  render(<Review scan={SCAN} onScanUpdated={onScanUpdated} {...props} />);
  return onScanUpdated;
};

beforeEach(() => {
  apiClient.getReviewQueue.mockResolvedValue({ scan_id: 'scan-1', pending_count: 1, items: [ITEM] });
  apiClient.getNormalizedFields.mockResolvedValue(FIELDS);
  apiClient.listLearnedMappings.mockResolvedValue([]);
  apiClient.getProvisionalResults.mockResolvedValue({ items: [] });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('provisional readings → recognizers', () => {
  it('confirms a reading: draft, replay, save, re-evaluated scan, refreshed stored count', async () => {
    apiClient.getProvisionalResults.mockResolvedValueOnce({ items: [PROVISIONAL] }).mockResolvedValue({ items: [] });
    apiClient.listLearnedMappings.mockResolvedValueOnce([]).mockResolvedValue([{ id: 7 }]);
    apiClient.draftRecognizer.mockResolvedValue(DRAFT);
    apiClient.saveRecognizer.mockResolvedValue({ mapping: { id: 7 }, replay: DRAFT.replay, scan: UPDATED_SCAN });
    const onScanUpdated = renderReview();

    expect(await screen.findByText('2 to review')).toBeTruthy();
    expect(screen.getByText('Suspected fail · not counted')).toBeTruthy();
    expect(screen.getByText('Recognizers stored: 0', { exact: false })).toBeTruthy();

    fireEvent.click(screen.getByLabelText('Confirm line 71 for MGMT-001'));
    expect(await screen.findByDisplayValue('remote-console protocol {enum:protocol}')).toBeTruthy();
    expect(apiClient.draftRecognizer).toHaveBeenCalledWith('scan-1', { config_index: 0, control_id: 'MGMT-001', line_number: 71 });
    expect(screen.getByText(/CORE-GATE-07 · MGMT-001: fail \(heuristic\) → fail \(confirmed\)/)).toBeTruthy();
    expect(apiClient.saveRecognizer).not.toHaveBeenCalled();

    fireEvent.click(screen.getByText('Save recognizer'));
    await waitFor(() => expect(onScanUpdated).toHaveBeenCalledWith(UPDATED_SCAN));
    expect(apiClient.saveRecognizer.mock.calls[0][1].command_pattern).toBe('remote-console protocol {enum:protocol}');
    expect(await screen.findByText(/Recognizer #7 saved/)).toBeTruthy();
    expect(await screen.findByText('Recognizers stored: 1', { exact: false })).toBeTruthy();
    expect(await screen.findByText('1 to review')).toBeTruthy();
  });

  it('blocks saving when a safety gate fails', async () => {
    apiClient.getProvisionalResults.mockResolvedValue({ items: [PROVISIONAL] });
    apiClient.draftRecognizer.mockResolvedValue({ ...DRAFT, errors: ['This line holds a secret value'], replay: [] });
    renderReview();
    fireEvent.click(await screen.findByLabelText('Confirm line 71 for MGMT-001'));
    expect(await screen.findByText('This line holds a secret value')).toBeTruthy();
    expect(screen.getByText('Save recognizer').closest('button').disabled).toBe(true);
  });

  it('rejects a reading and propagates the re-evaluated scan', async () => {
    apiClient.getProvisionalResults.mockResolvedValueOnce({ items: [PROVISIONAL] }).mockResolvedValue({ items: [] });
    apiClient.rejectProvisionalLine.mockResolvedValue(UPDATED_SCAN);
    const onScanUpdated = renderReview();
    fireEvent.click(await screen.findByLabelText('Reject line 71 for MGMT-001'));
    await waitFor(() => expect(apiClient.rejectProvisionalLine).toHaveBeenCalledWith('scan-1', { config_index: 0, control_id: 'MGMT-001', line_number: 71 }));
    expect(onScanUpdated).toHaveBeenCalledWith(UPDATED_SCAN);
    expect(await screen.findByText(/heuristics and AI ignore it/)).toBeTruthy();
  });

  it('explains an empty queue for confirmed vendors', async () => {
    apiClient.getReviewQueue.mockResolvedValue({ scan_id: 'scan-1', pending_count: 0, items: [] });
    render(<Review scan={{ ...SCAN, vendor_identification: [{ config_index: 0, status: 'confirmed' }], adaptive_configs: [] }} />);
    expect(await screen.findByText('Nothing needs your input')).toBeTruthy();
    expect(screen.getByText(/read by its dedicated parser/)).toBeTruthy();
  });

  it('reports an expired scan to the app instead of showing errors', async () => {
    const expired = Object.assign(new Error('Scan not found'), { status: 404 });
    apiClient.getReviewQueue.mockRejectedValue(expired);
    apiClient.getProvisionalResults.mockRejectedValue(expired);
    const onScanExpired = vi.fn();
    renderReview({ onScanExpired });
    await waitFor(() => expect(onScanExpired).toHaveBeenCalledWith('scan-1'));
    expect(screen.queryByText(/Scan not found/)).toBeNull();
  });
});

describe('legacy line interpretations', () => {
  it('renders suggestion, confidence and context', async () => {
    renderReview();
    expect(await screen.findByText('secure-shell protocol-version 1')).toBeTruthy();
    expect(screen.getByText('management.ssh_version = 1')).toBeTruthy();
    expect(screen.getByText('78%')).toBeTruthy();
    expect(screen.getByText('Why results are provisional or not assessed')).toBeTruthy();

    fireEvent.click(screen.getByLabelText('Toggle details for line 3'));
    expect(screen.getByText('Declares the SSH protocol version')).toBeTruthy();
    expect(screen.getByText('uplink mtu 1500')).toBeTruthy();
  });

  it('accepts an interpretation and propagates the re-evaluated scan', async () => {
    apiClient.acceptInterpretation.mockResolvedValue({ item: ITEM, mapping: { id: 7 }, auto_resolved: [], scan: UPDATED_SCAN });
    const onScanUpdated = renderReview();
    fireEvent.click(await screen.findByLabelText('Accept line 3'));
    await waitFor(() => expect(apiClient.acceptInterpretation).toHaveBeenCalledWith('scan-1', '0-3'));
    await waitFor(() => expect(onScanUpdated).toHaveBeenCalledWith(UPDATED_SCAN));
    expect(await screen.findByText(/learned mapping #7 saved/)).toBeTruthy();
  });

  it('submits an edited interpretation', async () => {
    apiClient.editInterpretation.mockResolvedValue({ item: ITEM, mapping: { id: 8 }, auto_resolved: [], scan: UPDATED_SCAN });
    renderReview();
    fireEvent.click(await screen.findByLabelText('Edit line 3'));
    fireEvent.change(screen.getByLabelText('Extracted value'), { target: { value: '2' } });
    fireEvent.change(screen.getByLabelText('Command pattern'), { target: { value: 'secure-shell {any} {value}' } });
    fireEvent.click(screen.getByText('Save mapping'));
    await waitFor(() => expect(apiClient.editInterpretation).toHaveBeenCalledWith('scan-1', '0-3', {
      normalized_field: 'management.ssh_version', extracted_value: '2', command_pattern: 'secure-shell {any} {value}', concept: 'ssh_protocol_version',
    }));
  });

  it('rejects an interpretation', async () => {
    apiClient.rejectInterpretation.mockResolvedValue({ item: { ...ITEM, review_status: 'rejected' }, mapping: null, scan: SCAN });
    renderReview();
    fireEvent.click(await screen.findByLabelText('Reject line 3'));
    await waitFor(() => expect(apiClient.rejectInterpretation).toHaveBeenCalledWith('scan-1', '0-3'));
    expect(await screen.findByText(/will not be sent to AI again/)).toBeTruthy();
  });

  it('blocks invalid edits before calling the API', async () => {
    renderReview();
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
    render(<Review scan={{ ...SCAN, adaptive_configs: [{ ...SCAN.adaptive_configs[0], ai_unavailable_lines: 1 }] }} />);

    expect(await screen.findByText('AI unavailable — map manually')).toBeTruthy();
    expect(screen.getByText('AI unavailable')).toBeTruthy();
    expect(screen.getByText('AI unavailable for 1 line(s)')).toBeTruthy();
    expect(screen.queryByText('0%')).toBeNull();
    expect(screen.queryByText('No usable suggestion')).toBeNull();
    expect(screen.getByLabelText('Accept line 4').disabled).toBe(true);
  });

  it('labels fields from the catalog, reports vendor evidence and shows the block path', async () => {
    apiClient.getNormalizedFields.mockResolvedValue([
      { field: 'management.ssh_version', value_type: 'optional_int', label: 'SSH protocol version', value_rule: 'whole number, digits only' },
    ]);
    apiClient.getReviewQueue.mockResolvedValue({ scan_id: 'scan-1', pending_count: 1, items: [{ ...ITEM, structural_path: ['system', 'services'] }] });
    const evidence = { status: 'identified', likely_vendor: 'juniper_junos', supporting_lines: [3, 4], votes: {} };
    render(<Review scan={{ ...SCAN, adaptive_configs: [{ ...SCAN.adaptive_configs[0], vendor_evidence: evidence }] }} />);

    fireEvent.click(await screen.findByLabelText('Edit line 3'));
    expect(screen.getByText('SSH protocol version — management.ssh_version (optional_int)')).toBeTruthy();
    expect(screen.getByText('Value: whole number, digits only')).toBeTruthy();
    expect(screen.getByText('juniper_junos')).toBeTruthy();
    expect(screen.getByText('system › services')).toBeTruthy();
  });
});
