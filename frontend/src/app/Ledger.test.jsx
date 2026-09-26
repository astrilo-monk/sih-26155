// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

vi.mock('../api/client', () => ({ apiClient: { getLedger: vi.fn(), verifyLedger: vi.fn(), verifyReport: vi.fn() } }));

import { apiClient } from '../api/client';
import Ledger from './Ledger';

const H = (c) => c.repeat(64);
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it('lists the chain, verifies it and tells a genuine report from an edited one', async () => {
  apiClient.getLedger.mockResolvedValue({ entries: [
    { seq: 2, at: '2026-09-27T10:00:00+00:00', kind: 'report', subject: 's1/0', hash: H('b'), prev_hash: H('a') },
    { seq: 1, at: '2026-09-27T09:59:00+00:00', kind: 'scan', subject: 's1', hash: H('a'), prev_hash: H('0') },
  ] });
  apiClient.verifyLedger.mockResolvedValue({ ok: false, entries: 2, broken_at: 1, reason: 'its content was changed after it was recorded' });
  apiClient.verifyReport.mockResolvedValueOnce({ match: true, entry: { seq: 2, at: '2026-09-27T10:00:00+00:00' } })
    .mockResolvedValueOnce({ match: false })
    .mockResolvedValueOnce({ match: true, files: [{ name: 'a.pdf', entry: { seq: 2 } }, { name: 'b.pdf', entry: { seq: 3 } }] })
    .mockResolvedValueOnce({ match: false, files: [{ name: 'a.pdf', entry: { seq: 2 } }, { name: 'b.pdf', entry: null }] });
  render(<Ledger />);

  await screen.findByText('PDF report');
  screen.getByText('Scan result');
  fireEvent.click(screen.getByRole('button', { name: 'Verify the ledger' }));
  expect((await screen.findByRole('alert')).textContent).toBe('Broken at entry #1: its content was changed after it was recorded.');

  const input = document.querySelector('input[type=file]');
  fireEvent.change(input, { target: { files: [new File(['%PDF'], 'r.pdf')] } });
  await screen.findByText(/Genuine: r.pdf is exactly the report recorded as entry #2/);
  fireEvent.change(input, { target: { files: [new File(['%PDF!'], 'edited.pdf')] } });
  await screen.findByText(/Not found: edited.pdf does not match any report/);

  // a multi-device scan downloads a .zip: every report in it must match
  fireEvent.change(input, { target: { files: [new File(['PK'], 'reports.zip')] } });
  await screen.findByText('Genuine: all 2 reports in reports.zip are exactly the ones recorded as entries #2, #3.');
  fireEvent.change(input, { target: { files: [new File(['PK!'], 'reports.zip')] } });
  await screen.findByText(/Not found: b.pdf in reports.zip does not match/);
});
