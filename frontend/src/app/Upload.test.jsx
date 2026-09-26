// @vitest-environment jsdom
import { cleanup, render, screen, fireEvent } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import Upload from './Upload';

function chooseFile(name = 'router.cfg') {
  const input = document.getElementById('config-files');
  const file = new File(['hostname R1\n'], name, { type: 'text/plain' });
  Object.defineProperty(input, 'files', { value: [file], configurable: true });
  fireEvent.change(input);
}

describe('Upload', () => {
  afterEach(cleanup);

  it('scans every framework when none is chosen', () => {
    const onScan = vi.fn();
    render(<Upload onScan={onScan} scanning={false} error={null} currentScan={null} />);
    chooseFile();
    fireEvent.click(screen.getByRole('button', { name: /start scan/i }));
    expect(onScan).toHaveBeenCalledWith(expect.any(Array), null, { criticality: '', internetFacing: false });
  });

  it('passes the framework the user chose', () => {
    const onScan = vi.fn();
    render(<Upload onScan={onScan} scanning={false} error={null} currentScan={null} />);
    chooseFile();
    fireEvent.change(screen.getByRole('combobox', { name: /^framework/i }), { target: { value: 'ISO_27001' } });
    fireEvent.click(screen.getByRole('button', { name: /start scan/i }));
    expect(onScan).toHaveBeenCalledWith(expect.any(Array), 'ISO_27001', { criticality: '', internetFacing: false });
  });
});

it('passes the asset context the user states', () => {
  const onScan = vi.fn();
  render(<Upload onScan={onScan} scanning={false} error={null} currentScan={null} />);
  chooseFile();
  fireEvent.change(screen.getByRole('combobox', { name: /how important/i }), { target: { value: 'critical' } });
  fireEvent.click(screen.getByRole('checkbox', { name: 'This device faces the internet' }));
  fireEvent.click(screen.getByRole('button', { name: /start scan/i }));
  expect(onScan).toHaveBeenCalledWith(expect.any(Array), null, { criticality: 'critical', internetFacing: true });
});

it('sends an organisation policy file with the scan, and refuses one that is not JSON', async () => {
  cleanup(); // the test above renders outside the describe's cleanup
  const onScan = vi.fn();
  render(<Upload onScan={onScan} scanning={false} error={null} currentScan={null} />);
  const input = screen.getByLabelText('Organisation policy');
  fireEvent.change(input, { target: { files: [new File(['{oops'], 'bad.json', { type: 'application/json' })] } });
  await screen.findByText('bad.json is not valid JSON.');

  const text = '{"name": "Acme", "idle_timeout_minutes": 10}';
  fireEvent.change(screen.getByLabelText('Organisation policy'), { target: { files: [new File([text], 'acme.json')] } });
  await screen.findByText('acme.json');
  chooseFile();
  fireEvent.click(screen.getByRole('button', { name: 'Start scan' }));
  expect(onScan.mock.calls[0][2]).toEqual({ criticality: '', internetFacing: false, policy: text });
});

it('adds a file chosen twice only once', () => {
  cleanup();
  render(<Upload onScan={vi.fn()} scanning={false} error={null} currentScan={null} />);
  const input = document.getElementById('config-files');
  const file = new File(['hostname R1\n'], 'r1.cfg', { type: 'text/plain', lastModified: 1 });
  for (let i = 0; i < 2; i += 1) {
    Object.defineProperty(input, 'files', { value: [file], configurable: true });
    fireEvent.change(input);
  }
  expect(screen.getAllByText('r1.cfg')).toHaveLength(1);
});
