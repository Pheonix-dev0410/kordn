import { describe, expect, it } from 'vitest';
import { formatUsd, parseCount, parseUsd } from '../src/admin/forms.js';
import { escapeHtml, html } from '../src/admin/html.js';

describe('admin html', () => {
  it('escapes every HTML-significant character', () => {
    expect(escapeHtml(`<img src=x onerror="alert('1')">&`)).toBe(
      '&lt;img src=x onerror=&quot;alert(&#39;1&#39;)&quot;&gt;&amp;',
    );
  });

  it('escapes interpolations but keeps nested html fragments', () => {
    const inner = html`<b>${'<i>'}</b>`;
    expect(html`<p title="${'"x"'}">${inner}${['<a>', 1, null, undefined]}</p>`.value).toBe(
      '<p title="&quot;x&quot;"><b>&lt;i&gt;</b>&lt;a&gt;1</p>',
    );
  });
});

describe('admin form parsing', () => {
  it('parses dollars to integer minor units exactly', () => {
    expect(parseUsd('75.01')).toBe(7501);
    expect(parseUsd('75')).toBe(7500);
    expect(parseUsd('75.1')).toBe(7510);
    expect(parseUsd('0.29')).toBe(29);
    expect(parseUsd('1.15')).toBe(115);
    expect(parseUsd(' 100.00 ')).toBe(10000);
    expect(parseUsd('0')).toBe(0);
    expect(parseUsd('9999999999999.99')).toBe(999999999999999);
  });

  it('rejects anything that is not plain dollars with at most two decimals', () => {
    for (const bad of ['1e3', '-5', '75.001', '', ' ', '.5', '5.', '0x10', '1,000', '$5', '+5', '075', 'Infinity', 'NaN', '٣', '1 000', '99999999999999']) {
      expect(parseUsd(bad), bad).toBeNull();
    }
  });

  it('formats minor units as dollars', () => {
    expect(formatUsd(7501)).toBe('75.01');
    expect(formatUsd(7500)).toBe('75.00');
    expect(formatUsd(5)).toBe('0.05');
    expect(formatUsd(0)).toBe('0.00');
  });

  it('parses non-negative integer counts', () => {
    expect(parseCount('5')).toBe(5);
    expect(parseCount('0')).toBe(0);
    for (const bad of ['-1', '1.5', '1e3', '', '05', '9999999999', 'x']) expect(parseCount(bad), bad).toBeNull();
  });
});
