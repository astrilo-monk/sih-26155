// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import AttackPaths, { AttackPathsPage } from './AttackPaths';

const PATH = {
  config_index: 0, path_id: 'remote-takeover', title: 'Remote takeover through the management plane',
  outcome: 'Full administrative control of the device', severity: 'critical',
  steps: [
    { title: 'Reach the login', how: 'open to all', controls: [{ control_id: 'MGMT-003', title: 'Unrestricted', lines: [{ number: 75, text: 'line vty 0 4' }] }] },
    { title: 'Capture the password', how: 'cleartext', controls: [{ control_id: 'MGMT-001', title: 'Telnet', lines: [] }] },
  ],
  break_with: ['MGMT-003'], break_step: 'Reach the login',
};

describe('AttackPaths', () => {
  it('shows nothing when no path is open', () => {
    const { container } = render(<AttackPaths paths={[]} labels={['r1']} />);
    expect(container.firstChild).toBeNull();
  });

  it('shows every step with its line, the outcome and the fix that breaks it', () => {
    const onFix = vi.fn();
    render(<AttackPaths paths={[PATH]} labels={['r1']} onFix={onFix} />);
    expect(screen.getByRole('heading', { name: 'Remote takeover through the management plane' })).toBeTruthy();
    expect(screen.getByText('line 75: line vty 0 4')).toBeTruthy();
    expect(screen.getByText('Full administrative control of the device')).toBeTruthy();
    expect(screen.getByText(/fix MGMT-003, the “Reach the login” step/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Go to fixes' }));
    expect(onFix).toHaveBeenCalled();
  });
});

it('has its own page, which says so when nothing chains', () => {
  cleanup();
  render(<AttackPathsPage scan={{ attack_paths: [] }} labels={['r1']} go={() => {}} />);
  screen.getByRole('heading', { name: 'How the problems add up' });
  screen.getByText(/No attack path: the confirmed problems on this device do not chain into one/);
});
