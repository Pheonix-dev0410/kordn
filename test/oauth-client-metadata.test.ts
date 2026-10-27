import { describe, expect, it } from 'vitest';
import { cleanName, isAllowedRedirectUri, parseClientMetadata } from '../src/oauth/client-metadata.js';

describe('isAllowedRedirectUri', () => {
  it('accepts https and loopback http', () => {
    for (const u of ['https://chatgpt.com/connector_platform_oauth_redirect', 'http://localhost:6274/oauth/callback', 'http://127.0.0.1:9/cb']) {
      expect(isAllowedRedirectUri(u), u).toBe(true);
    }
  });

  it('rejects everything else', () => {
    for (const u of ['http://example.com/cb', 'https://a/cb#x', 'javascript:alert(1)', 'https://u:p@a/cb', 'http://localhost.evil.com/cb', 'nonsense']) {
      expect(isAllowedRedirectUri(u), u).toBe(false);
    }
  });
});

describe('parseClientMetadata', () => {
  const uri = 'https://a.example/cb';

  it('rejects bad redirect_uris', () => {
    for (const body of [{}, { redirect_uris: [] }, { redirect_uris: Array(6).fill(uri) }, { redirect_uris: ['http://example.com/x'] }, { redirect_uris: ['https://a.example/c\tb'] }, { redirect_uris: ['https://a.example/c b'] }, { redirect_uris: [uri, 5] }, null, 'x']) {
      expect(parseClientMetadata(body)).toMatchObject({ ok: false, error: 'invalid_redirect_uri' });
    }
  });

  it('rejects a redirect URI over 2048 characters', () => {
    expect(parseClientMetadata({ redirect_uris: [`https://a.example/${'x'.repeat(2048)}`] })).toMatchObject({ ok: false, error: 'invalid_redirect_uri' });
  });

  it('rejects grant and response types without the code flow, and auth methods it lacks', () => {
    for (const extra of [
      { grant_types: ['client_credentials'] },
      { grant_types: ['refresh_token'] },
      { grant_types: [] },
      { grant_types: 'authorization_code' },
      { response_types: ['token'] },
      { response_types: 'code' },
      { token_endpoint_auth_method: 'private_key_jwt' },
    ]) {
      expect(parseClientMetadata({ redirect_uris: [uri], ...extra }), JSON.stringify(extra)).toMatchObject({ ok: false, error: 'invalid_client_metadata' });
    }
  });

  it('drops grant and response types it does not support, keeping the supported ones', () => {
    // VS Code asks for the device flow too.
    const result = parseClientMetadata({
      redirect_uris: [uri],
      grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code', 7],
      response_types: ['code', 'token'],
    });
    expect(result).toMatchObject({ ok: true, grantTypes: ['authorization_code', 'refresh_token'], responseTypes: ['code'] });
  });

  it('defaults to a public client and ignores unknown fields', () => {
    expect(parseClientMetadata({ redirect_uris: [uri], logo_uri: 'x' })).toEqual({
      ok: true,
      value: { name: 'Unnamed app', redirectUris: [uri], authMethod: 'none' },
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
    });
    expect(parseClientMetadata({ redirect_uris: [uri], grant_types: ['authorization_code'] })).toMatchObject({ grantTypes: ['authorization_code'] });
  });

  it('cleans the client name', () => {
    const result = parseClientMetadata({ redirect_uris: [uri], client_name: '<b>x</b>‮'.padEnd(500, 'y') });
    if (!result.ok) throw new Error('expected ok');
    expect(Array.from(result.value.name)).toHaveLength(100);
    expect(result.value.name).not.toContain('‮');
  });
});

describe('cleanName', () => {
  it('falls back when empty and never splits a surrogate pair', () => {
    expect(cleanName(' ‮ ')).toBe('Unnamed app');
    expect(cleanName('😀'.repeat(150))).toBe('😀'.repeat(100));
  });
});
