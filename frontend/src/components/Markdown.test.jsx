// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import Markdown, { parseBlocks } from './Markdown';

// What the assistant actually sent back, trimmed: bold, a table, a rule, bullets
const ANSWER = `**Critical findings on BRANCH-FGT-02**

| Control ID | Rule | Verdict |
|------------|------|---------|
| **MGMT-001** | Telnet Enabled | **Fail - parser** |
| **BOUNDARY-001** | Any-to-any policy | **Fail - parser** |

---

### What these mean
- **Management exposure** gives a direct path to the control plane.
- Set \`set telnet disable\` on the device.`;

describe('Markdown', () => {
  afterEach(cleanup);

  it('shows emphasis as emphasis instead of asterisks', () => {
    render(<Markdown text={ANSWER} />);
    expect(screen.getByText('Critical findings on BRANCH-FGT-02').tagName).toBe('STRONG');
    expect(document.body.textContent).not.toContain('**');
  });

  it('renders a table as a table, not a row of pipes', () => {
    const { container } = render(<Markdown text={ANSWER} />);
    const table = container.querySelector('table');
    expect(table).toBeTruthy();
    expect(table.querySelectorAll('thead th')).toHaveLength(3);
    expect(table.querySelectorAll('tbody tr')).toHaveLength(2);
    expect(document.body.textContent).not.toContain('|---');
  });

  it('turns a horizontal rule into a rule rather than three dashes', () => {
    const { container } = render(<Markdown text={ANSWER} />);
    expect(container.querySelector('hr')).toBeTruthy();
    expect(document.body.textContent).not.toContain('---');
  });

  it('renders headings, bullets and inline code', () => {
    const { container } = render(<Markdown text={ANSWER} />);
    expect(screen.getByText('What these mean').tagName).toMatch(/^H\d$/);
    expect(container.querySelectorAll('ul li')).toHaveLength(2);
    expect(screen.getByText('set telnet disable').tagName).toBe('CODE');
  });

  it('never builds HTML from the answer, so a model cannot inject markup', () => {
    const { container } = render(<Markdown text={'<img src=x onerror=alert(1)> and <b>bold</b>'} />);
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('b')).toBeNull();
    // the text survives, visible and inert
    expect(document.body.textContent).toContain('<img src=x onerror=alert(1)>');
  });

  it('keeps text it does not understand rather than dropping it', () => {
    render(<Markdown text={'plain line\n\n~~~ odd ~~~\n> quoted'} />);
    expect(document.body.textContent).toContain('plain line');
    expect(document.body.textContent).toContain('~~~ odd ~~~');
    expect(document.body.textContent).toContain('> quoted');
  });

  it('treats a lone line of pipes as text, because a table needs its divider', () => {
    const blocks = parseBlocks('| not | a table |');
    expect(blocks.map((b) => b.type)).toEqual(['paragraph']);
  });

  it('handles empty and missing text without throwing', () => {
    expect(parseBlocks('')).toEqual([]);
    expect(parseBlocks(undefined)).toEqual([]);
    render(<Markdown text={null} />);
  });
});
