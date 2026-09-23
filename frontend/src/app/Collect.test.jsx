// @vitest-environment jsdom
import { cleanup, render, screen, fireEvent, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import Collect from './Collect';

vi.mock('../api/client', () => ({
  apiClient: { getCollectCapabilities: vi.fn() },
}));

import { apiClient } from '../api/client';

const PLATFORMS = [
  { platform: 'cisco_ios', label: 'Cisco IOS / IOS-XE', command: 'show running-config',
    napalm_driver: 'ios', methods: ['napalm', 'netmiko'], available: true },
  { platform: 'fortinet', label: 'Fortinet FortiGate', command: 'show full-configuration',
    napalm_driver: null, methods: ['netmiko'], available: true },
];

const caps = (over = {}) => ({ enabled: true, methods: ['napalm', 'netmiko'], platforms: PLATFORMS, ...over });

async function fillDevice({ host = '10.0.0.1', password = 'hunter2' } = {}) {
  fireEvent.change(await screen.findByLabelText('Host'), { target: { value: host } });
  fireEvent.change(screen.getByLabelText(/^Platform/), { target: { value: 'cisco_ios' } });
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'auditor' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: password } });
}

describe('Collect', () => {
  afterEach(cleanup);

  it('says collection is off rather than offering a form that cannot work', async () => {
    apiClient.getCollectCapabilities.mockResolvedValue(caps({ enabled: false }));
    render(<Collect onCollect={vi.fn()} framework={null} currentScan={null} />);
    expect(await screen.findByText(/switched off on this backend/i)).toBeTruthy();
    expect(screen.queryByLabelText('Host')).toBeNull();
  });

  it('says which library is missing when collection is on but has no driver', async () => {
    apiClient.getCollectCapabilities.mockResolvedValue(
      caps({ methods: [], platforms: PLATFORMS.map((p) => ({ ...p, methods: [], available: false })) }));
    render(<Collect onCollect={vi.fn()} framework={null} currentScan={null} />);
    expect(await screen.findByText(/Neither Netmiko nor NAPALM is installed/i)).toBeTruthy();
  });

  it('sends the device and the chosen framework', async () => {
    apiClient.getCollectCapabilities.mockResolvedValue(caps());
    const onCollect = vi.fn().mockResolvedValue({ scan: { scan_id: 's1' }, collected: ['10.0.0.1'], failures: [] });
    render(<Collect onCollect={onCollect} framework="CIS" currentScan={null} />);
    await fillDevice();
    fireEvent.click(screen.getByRole('button', { name: /collect and scan/i }));

    await waitFor(() => expect(onCollect).toHaveBeenCalled());
    const [targets, framework] = onCollect.mock.calls[0];
    expect(framework).toBe('CIS');
    expect(targets).toEqual([expect.objectContaining({
      host: '10.0.0.1', platform: 'cisco_ios', username: 'auditor', password: 'hunter2', port: 22, method: 'auto',
    })]);
  });

  it('clears the credentials once the request is done', async () => {
    apiClient.getCollectCapabilities.mockResolvedValue(caps());
    const onCollect = vi.fn().mockResolvedValue({ scan: { scan_id: 's1' }, collected: ['10.0.0.1'], failures: [] });
    render(<Collect onCollect={onCollect} framework={null} currentScan={null} />);
    await fillDevice();
    fireEvent.click(screen.getByRole('button', { name: /collect and scan/i }));

    await waitFor(() => expect(screen.getByLabelText('Password').value).toBe(''));
    // the host is kept: only the secret is thrown away, so a retry does not mean retyping everything
    expect(screen.getByLabelText('Host').value).toBe('10.0.0.1');
  });

  it('names the devices that could not be read instead of implying they passed', async () => {
    apiClient.getCollectCapabilities.mockResolvedValue(caps());
    const onCollect = vi.fn().mockResolvedValue({
      scan: { scan_id: 's1' },
      collected: ['10.0.0.1'],
      failures: [{ host: '10.0.0.2', error: 'Could not collect from 10.0.0.2 over netmiko: TimeoutError' }],
    });
    render(<Collect onCollect={onCollect} framework={null} currentScan={null} />);
    await fillDevice();
    fireEvent.click(screen.getByRole('button', { name: /collect and scan/i }));

    expect(await screen.findByText(/TimeoutError/)).toBeTruthy();
    expect(screen.getByText(/absent from this audit rather than passing it/i)).toBeTruthy();
  });

  it('reports a total failure without leaving the form', async () => {
    apiClient.getCollectCapabilities.mockResolvedValue(caps());
    const onCollect = vi.fn().mockRejectedValue(new Error('No device could be collected from'));
    render(<Collect onCollect={onCollect} framework={null} currentScan={null} />);
    await fillDevice();
    fireEvent.click(screen.getByRole('button', { name: /collect and scan/i }));

    expect(await screen.findByText(/No device could be collected from/)).toBeTruthy();
    expect(screen.getByLabelText('Host')).toBeTruthy();
  });

  it('will not collect until a device has somewhere to connect and someone to connect as', async () => {
    apiClient.getCollectCapabilities.mockResolvedValue(caps());
    render(<Collect onCollect={vi.fn()} framework={null} currentScan={null} />);
    const button = await screen.findByRole('button', { name: /collect and scan/i });
    expect(button.disabled).toBe(true);
    await fillDevice();
    expect(button.disabled).toBe(false);
  });

  it('shows the command a platform will actually be read with', async () => {
    apiClient.getCollectCapabilities.mockResolvedValue(caps());
    render(<Collect onCollect={vi.fn()} framework={null} currentScan={null} />);
    fireEvent.change(await screen.findByLabelText(/^Platform/), { target: { value: 'fortinet' } });
    expect(screen.getByText(/show full-configuration/)).toBeTruthy();
  });
});
