// @vitest-environment jsdom
import { cleanup, render, screen, fireEvent, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import Assistant from './Assistant';
import { DEFAULT_PANEL } from '../lib/panel';

vi.mock('../api/client', () => ({
  apiClient: { getAssistantStatus: vi.fn(), chat: vi.fn() },
}));

import { apiClient } from '../api/client';

const SCAN = { scan_id: 's1' };

const PANEL = { ...DEFAULT_PANEL };

function open(props = {}) {
  apiClient.getAssistantStatus.mockResolvedValue({ ai_available: true });
  return render(<Assistant scan={SCAN} open onToggle={vi.fn()}
                           panel={PANEL} onPanel={vi.fn()} {...props} />);
}

describe('Assistant', () => {
  afterEach(() => { cleanup(); vi.clearAllMocks(); });

  it('will not offer to answer before there is a scan to answer from', async () => {
    apiClient.getAssistantStatus.mockResolvedValue({ ai_available: true });
    render(<Assistant scan={null} open={false} onToggle={vi.fn()} panel={PANEL} onPanel={vi.fn()} />);
    expect((await screen.findByRole('button', { name: /ask about this scan/i })).disabled).toBe(true);
  });

  it('sends the question and shows the answer', async () => {
    apiClient.chat.mockResolvedValue({ response: 'Fix MGMT-001 first.' });
    open();
    fireEvent.change(await screen.findByLabelText(/ask about this scan/i), { target: { value: 'what first?' } });
    fireEvent.click(screen.getByRole('button', { name: /send/i }));

    expect(await screen.findByText('Fix MGMT-001 first.')).toBeTruthy();
    expect(apiClient.chat).toHaveBeenCalledWith('s1', 'what first?', []);
  });

  it('passes the earlier turns so a follow-up has something to refer to', async () => {
    apiClient.chat.mockResolvedValueOnce({ response: 'Telnet.' }).mockResolvedValueOnce({ response: 'Because it is plaintext.' });
    open();
    const box = await screen.findByLabelText(/ask about this scan/i);

    fireEvent.change(box, { target: { value: 'what first?' } });
    fireEvent.click(screen.getByRole('button', { name: /send/i }));
    await screen.findByText('Telnet.');

    fireEvent.change(box, { target: { value: 'why?' } });
    fireEvent.click(screen.getByRole('button', { name: /send/i }));
    await screen.findByText('Because it is plaintext.');

    expect(apiClient.chat).toHaveBeenLastCalledWith('s1', 'why?', [
      { role: 'you', content: 'what first?' },
      { role: 'assistant', content: 'Telnet.' },
    ]);
  });

  it('offers openers that the scan can actually answer, including the undecided one', async () => {
    apiClient.chat.mockResolvedValue({ response: 'Because the setting is absent.' });
    open();
    const opener = await screen.findByRole('button', { name: /why are some checks undecided/i });
    fireEvent.click(opener);
    await waitFor(() => expect(apiClient.chat).toHaveBeenCalledWith('s1', 'Why are some checks undecided?', []));
  });

  it('says when the backend has no AI configured instead of failing on send', async () => {
    apiClient.getAssistantStatus.mockResolvedValue({ ai_available: false });
    render(<Assistant scan={SCAN} open onToggle={vi.fn()} panel={PANEL} onPanel={vi.fn()} />);
    expect(await screen.findByText(/AI is not configured on this backend/i)).toBeTruthy();
  });

  it('shows a failed request as a failure rather than an answer', async () => {
    apiClient.chat.mockRejectedValue(new Error('API error: 500'));
    open();
    fireEvent.change(await screen.findByLabelText(/ask about this scan/i), { target: { value: 'hi' } });
    fireEvent.click(screen.getByRole('button', { name: /send/i }));

    expect(await screen.findByText('API error: 500')).toBeTruthy();
    expect(screen.getByText('Failed')).toBeTruthy();
  });

  it('pops out and docks again from the same control', async () => {
    const onPanel = vi.fn();
    open({ onPanel });
    fireEvent.click(await screen.findByRole('button', { name: /pop out/i }));
    expect(onPanel.mock.calls[0][0](PANEL).mode).toBe('floating');

    cleanup();
    open({ panel: { ...PANEL, mode: 'floating' }, onPanel });
    fireEvent.click(await screen.findByRole('button', { name: /^dock$/i }));
    expect(onPanel.mock.calls[1][0]({ ...PANEL, mode: 'floating' }).mode).toBe('docked');
  });

  it('places a floating panel where it was left', async () => {
    const { container } = open({ panel: { ...PANEL, mode: 'floating', x: 250, y: 130, w: 480, h: 400 } });
    await screen.findByText('Assistant');
    const box = container.querySelector('.chat-float');
    expect(box.style.left).toBe('250px');
    expect(box.style.top).toBe('130px');
    expect(box.style.width).toBe('480px');
  });

  it('the docked rail can be resized from the keyboard, not only by dragging', async () => {
    const onPanel = vi.fn();
    open({ onPanel });
    const handle = await screen.findByRole('separator', { name: /resize assistant panel/i });
    fireEvent.keyDown(handle, { key: 'ArrowRight' });
    expect(onPanel.mock.calls[0][0](PANEL).width).toBeGreaterThan(PANEL.width);
    fireEvent.keyDown(handle, { key: 'ArrowLeft' });
    expect(onPanel.mock.calls[1][0](PANEL).width).toBeLessThan(PANEL.width);
  });

  it('renders an answer as structure rather than raw markdown', async () => {
    apiClient.chat.mockResolvedValue({ response: '**MGMT-001** is critical.' });
    const { container } = open();
    fireEvent.change(await screen.findByLabelText(/ask about this scan/i), { target: { value: 'hi' } });
    fireEvent.click(screen.getByRole('button', { name: /send/i }));

    await screen.findByText('MGMT-001');
    expect(container.querySelector('.chat-assistant strong')).toBeTruthy();
    expect(document.body.textContent).not.toContain('**MGMT-001**');
  });

  it('starts a new conversation when the scan changes', async () => {
    apiClient.chat.mockResolvedValue({ response: 'Telnet.' });
    const { rerender } = open();
    fireEvent.change(await screen.findByLabelText(/ask about this scan/i), { target: { value: 'what first?' } });
    fireEvent.click(screen.getByRole('button', { name: /send/i }));
    await screen.findByText('Telnet.');

    rerender(<Assistant scan={{ scan_id: 's2' }} open onToggle={vi.fn()} panel={PANEL} onPanel={vi.fn()} />);
    // the previous scan's answers are not carried into a conversation about a different device
    expect(screen.queryByText('Telnet.')).toBeNull();
  });
});
