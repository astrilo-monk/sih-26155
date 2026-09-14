// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

vi.mock('./api/client', () => ({ apiClient: { isScanHeld: vi.fn().mockResolvedValue(true) } }));

import App from './App';

afterEach(cleanup);

it('explains every scan view when no scan is loaded instead of rendering a blank page', () => {
  render(<App />);
  for (const label of ['Overview', 'Devices', 'Findings', 'Frameworks', 'Remediation', 'Review & Recognizers']) {
    fireEvent.click(screen.getByRole('button', { name: label }));
    expect(screen.getByText('No scan loaded. Upload a configuration to begin.')).toBeTruthy();
  }
  fireEvent.click(screen.getByText('Upload a configuration'));
  expect(screen.getByText('Upload Network Configurations')).toBeTruthy();
});
