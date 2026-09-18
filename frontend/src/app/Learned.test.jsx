// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

vi.mock('../api/client', () => ({
  apiClient: { listLearnedMappings: vi.fn(), disableLearnedMapping: vi.fn() },
}));

import { apiClient } from '../api/client';
import Learned from './Learned';

const mapping = (id, source, extra = {}) => ({
  id,
  source,
  concept: 'Telnet service',
  normalized_field: '',
  extraction_method: 'recognizer',
  expected_value_type: 'recognizer',
  command_pattern: `pattern-${id} {polarity}`,
  example_line: `example line ${id}`,
  constant_value: null,
  confidence: 1,
  confirmed: true,
  active: true,
  created_at: '2026-09-14T08:00:00Z',
  updated_at: '2026-09-14T08:00:00Z',
  predicate: 'mgmt.remote_access.protocol_enabled',
  subject: 'telnet',
  negatives: [],
  vendor: 'Huawei VRP',
  ...extra,
});

beforeEach(() => {
  apiClient.listLearnedMappings.mockResolvedValue([mapping(1, 'seed'), mapping(2, 'runtime')]);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it('tells shipped seed knowledge apart from what was taught on this deployment', async () => {
  render(<Learned />);

  expect(await screen.findByText(/shipped with NetAuditAI · Huawei VRP syntax/)).toBeTruthy();
  expect(screen.getByText(/taught here \d/)).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: /Shipped/ }));
  expect(screen.getByText('example line 1')).toBeTruthy();
  expect(screen.queryByText('example line 2')).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: /Taught here/ }));
  expect(screen.getByText('example line 2')).toBeTruthy();
  expect(screen.queryByText('example line 1')).toBeNull();
});
