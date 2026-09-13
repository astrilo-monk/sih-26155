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
    disableLearnedMapping: vi.fn(),
    getProvisionalResults: vi.fn(),
  },
}));

import { apiClient } from '../api/client';
import AdaptiveTraining from './AdaptiveTraining';

const ITEM = {
  item_id: '0-3',
  config_index: 0,
  hostname: 'EDGE-GW-01',
  vendor: 'unknown',
  line_number: 3,
  raw_line: 'secure-shell protocol-version 1',
  context_before: ['system-name EDGE-GW-01', 'uplink mtu 1500'],
  context_after: ['remote-console protocol telnet'],
  likely_vendor: 'generic',
  security_concept: 'ssh_protocol_version',
  normalized_field: 'management.ssh_version',
  extracted_value: '1',
  confidence: 0.78,
  confidence_tier: 'medium',
  reasoning: 'Declares the SSH protocol version',
  interpretation_status: 'interpreted',
  source: 'needs_review',
  reason: 'MEDIUM confidence — requires admin review before applying',
  review_status: 'pending',
  mapping_id: null,
  candidates: [],
};

const FIELDS = [
  { field: 'management.ssh_version', value_type: 'optional_int' },
  { field: 'management.telnet_enabled', value_type: 'bool' },
];

const SCAN = {
  scan_id: 'scan-1',
  adaptive_configs: [{ ai_called: true, learned_matches: 0, provisional_reasons: ['1 line(s) awaiting review'] }],
};

const UPDATED_SCAN = { ...SCAN, score: 91 };

function renderComponent(onScanUpdated = vi.fn()) {
  render(<AdaptiveTraining scanResult={SCAN} onScanUpdated={onScanUpdated} />);
  return onScanUpdated;
}

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

describe('AdaptiveTraining', () => {
  it('renders the review queue with suggestion, confidence and context', async () => {
    renderComponent();

    expect(await screen.findByText('secure-shell protocol-version 1')).toBeTruthy();
    expect(screen.getByText('management.ssh_version = 1')).toBeTruthy();
    expect(screen.getByText('78%')).toBeTruthy();
    expect(screen.getByText('Score is provisional')).toBeTruthy();

    fireEvent.click(screen.getByLabelText('Toggle details for line 3'));
    expect(screen.getByText('Declares the SSH protocol version')).toBeTruthy();
    expect(screen.getByText('uplink mtu 1500')).toBeTruthy();
  });

  it('accepts an interpretation and propagates the re-evaluated scan', async () => {
    apiClient.acceptInterpretation.mockResolvedValue({ item: ITEM, mapping: { id: 7 }, auto_resolved: [], scan: UPDATED_SCAN });
    const onScanUpdated = renderComponent();

    fireEvent.click(await screen.findByLabelText('Accept line 3'));

    await waitFor(() => expect(apiClient.acceptInterpretation).toHaveBeenCalledWith('scan-1', '0-3'));
    await waitFor(() => expect(onScanUpdated).toHaveBeenCalledWith(UPDATED_SCAN));
    expect(await screen.findByText(/learned mapping #7 saved/)).toBeTruthy();
  });

  it('submits an edited interpretation', async () => {
    apiClient.editInterpretation.mockResolvedValue({ item: ITEM, mapping: { id: 8 }, auto_resolved: [], scan: UPDATED_SCAN });
    renderComponent();

    fireEvent.click(await screen.findByLabelText('Edit line 3'));
    fireEvent.change(screen.getByLabelText('Extracted value'), { target: { value: '2' } });
    fireEvent.change(screen.getByLabelText('Command pattern'), { target: { value: 'secure-shell {any} {value}' } });
    fireEvent.click(screen.getByText('Save Mapping'));

    await waitFor(() =>
      expect(apiClient.editInterpretation).toHaveBeenCalledWith('scan-1', '0-3', {
        normalized_field: 'management.ssh_version',
        extracted_value: '2',
        command_pattern: 'secure-shell {any} {value}',
        concept: 'ssh_protocol_version',
      }),
    );
  });

  it('rejects an interpretation', async () => {
    apiClient.rejectInterpretation.mockResolvedValue({ item: { ...ITEM, review_status: 'rejected' }, mapping: null, scan: SCAN });
    renderComponent();

    fireEvent.click(await screen.findByLabelText('Reject line 3'));

    await waitFor(() => expect(apiClient.rejectInterpretation).toHaveBeenCalledWith('scan-1', '0-3'));
    expect(await screen.findByText(/will not be sent to AI again/)).toBeTruthy();
  });

  it('blocks invalid edits before calling the API', async () => {
    renderComponent();

    fireEvent.click(await screen.findByLabelText('Edit line 3'));
    fireEvent.change(screen.getByLabelText('Extracted value'), { target: { value: 'modern' } });
    fireEvent.click(screen.getByText('Save Mapping'));
    expect(await screen.findByText('Must be a whole number')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Normalized field'), { target: { value: '' } });
    fireEvent.change(screen.getByLabelText('Extracted value'), { target: { value: '' } });
    fireEvent.click(screen.getByText('Save Mapping'));
    expect(await screen.findByText('Choose a normalized field')).toBeTruthy();
    expect(screen.getByText('Extracted value is required')).toBeTruthy();

    expect(apiClient.editInterpretation).not.toHaveBeenCalled();
  });

  it('shows AI-unavailable lines as an outage, not as a confidence score', async () => {
    const unavailable = {
      ...ITEM,
      item_id: '0-4',
      line_number: 4,
      raw_line: 'remote-console protocol telnet',
      normalized_field: 'unknown',
      extracted_value: null,
      confidence: 0,
      confidence_tier: 'low',
      interpretation_status: 'ai_unavailable',
      source: 'needs_training',
      reasoning: 'AI interpretation unavailable — quota exhausted',
    };
    apiClient.getReviewQueue.mockResolvedValue({ scan_id: 'scan-1', pending_count: 1, items: [unavailable] });
    const scan = { ...SCAN, adaptive_configs: [{ ...SCAN.adaptive_configs[0], ai_unavailable_lines: 1 }] };
    render(<AdaptiveTraining scanResult={scan} onScanUpdated={vi.fn()} />);

    expect(await screen.findByText('AI unavailable — map manually')).toBeTruthy();
    expect(screen.getByText('AI unavailable')).toBeTruthy();
    expect(screen.getByText('AI unavailable for 1 line(s)')).toBeTruthy();
    expect(screen.queryByText('0%')).toBeNull();
    expect(screen.queryByText('No usable suggestion')).toBeNull();
    expect(screen.getByLabelText('Accept line 4').disabled).toBe(true);
  });

  it('labels fields from the catalog and reports vendor evidence', async () => {
    apiClient.getNormalizedFields.mockResolvedValue([
      {
        field: 'management.ssh_version',
        value_type: 'optional_int',
        label: 'SSH protocol version',
        value_rule: 'whole number, digits only',
      },
    ]);
    const evidence = { status: 'identified', likely_vendor: 'juniper_junos', supporting_lines: [3, 4], votes: {} };
    const scan = { ...SCAN, adaptive_configs: [{ ...SCAN.adaptive_configs[0], vendor_evidence: evidence }] };
    render(<AdaptiveTraining scanResult={scan} onScanUpdated={vi.fn()} />);

    fireEvent.click(await screen.findByLabelText('Edit line 3'));
    expect(screen.getByText('SSH protocol version — management.ssh_version (optional_int)')).toBeTruthy();
    expect(screen.getByText('Value: whole number, digits only')).toBeTruthy();
    expect(screen.getByText('juniper_junos')).toBeTruthy();
  });

  it('shows the structural block path of a line', async () => {
    apiClient.getReviewQueue.mockResolvedValue({
      scan_id: 'scan-1',
      pending_count: 1,
      items: [{ ...ITEM, structural_path: ['system', 'services'] }],
    });
    renderComponent();

    fireEvent.click(await screen.findByLabelText('Toggle details for line 3'));
    expect(screen.getByText('system › services')).toBeTruthy();
  });
});
