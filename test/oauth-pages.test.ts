import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { consentCsp, consentPage, oauthErrorPage } from '../src/oauth/pages.js';

const view = {
  clientName: '<script>x</script>',
  redirectHost: 'chatgpt.com',
  requestId: 'req-123',
  csrf: 'csrf-456',
};

describe('consent page', () => {
  it('escapes the untrusted client name and has no script', () => {
    const page = consentPage(view).value;
    expect(page).toContain('&lt;script&gt;');
    expect(page).not.toContain('<script');
  });

  it('shows the redirect host, hidden fields and both decisions', () => {
    const page = consentPage(view).value;
    expect(page).toContain('An app wants to use kordn');
    expect(page).toContain('chatgpt.com');
    expect(page).toContain('name="request" value="req-123"');
    expect(page).toContain('name="csrf" value="csrf-456"');
    expect(page).toContain('name="owner_token"');
    expect(page).toContain('type="password"');
    expect(page).toContain('name="decision" value="approve"');
    expect(page).toContain('name="decision" value="deny"');
    expect(page).toContain('name="viewport"');
  });

  it('renders errors escaped', () => {
    const page = consentPage({ ...view, errors: ['Wrong KORDN_TOKEN.', '<b>'] }).value;
    expect(page).toContain('Wrong KORDN_TOKEN.');
    expect(page).toContain('&lt;b&gt;');
  });

  it('error page shows its message escaped', () => {
    expect(oauthErrorPage('Bad <request>').value).toContain('Bad &lt;request&gt;');
  });
});

describe('consent CSP', () => {
  it('locks framing and allows the redirect origin as a form target', () => {
    const csp = consentCsp('https://chatgpt.com');
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("form-action 'self' https://chatgpt.com");
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("base-uri 'none'");
  });

  it('is self only without an origin or with an unsafe one', () => {
    expect(consentCsp()).toContain("form-action 'self';");
    for (const bad of ['https://a.com; script-src *', 'https://a.com b', 'javascript:alert(1)', 'https://a.com/path', '']) {
      expect(consentCsp(bad)).toContain("form-action 'self';");
      expect(consentCsp(bad)).not.toContain('script-src');
    }
  });

  it('hash matches the inline style bytes on both pages', () => {
    for (const page of [consentPage(view).value, oauthErrorPage('x').value]) {
      const css = /<style>([\s\S]*?)<\/style>/.exec(page)![1]!;
      const hash = createHash('sha256').update(css).digest('base64');
      expect(consentCsp()).toContain(`style-src 'sha256-${hash}'`);
    }
  });
});
