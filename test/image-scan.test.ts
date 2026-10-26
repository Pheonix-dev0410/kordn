import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync, zstdCompressSync } from 'node:zlib';
import { afterEach, describe, expect, it } from 'vitest';
import { checkConfig, checkPath, checkText, createTextScanner, isSecretName, parseHistory, scanImageArchive } from './image-scan.js';

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

// ---- minimal tar writer for fixtures ----

function header(name: string, size: number, type: string): Buffer {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0);
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124);
  h.write('00000000000\0', 136);
  h.write('        ', 148);
  h.write(type, 156);
  h.write('ustar\0', 257);
  h.write('00', 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
  return h;
}

function entry(name: string, data: string | Buffer, type = '0'): Buffer {
  const body = typeof data === 'string' ? Buffer.from(data) : data;
  return Buffer.concat([header(name, body.length, type), body, Buffer.alloc((512 - (body.length % 512)) % 512)]);
}

function paxPath(path: string): Buffer {
  const rest = ` path=${path}\n`;
  let len = rest.length + 2;
  if (String(len).length + rest.length !== len) len = String(len + 1).length + rest.length;
  return entry('PaxHeader', `${len}${rest}`, 'x');
}

const tar = (...entries: Buffer[]) => Buffer.concat([...entries, Buffer.alloc(1024)]);

function archive(...entries: Buffer[]): string {
  const dir = mkdtempSync(join(tmpdir(), 'kordn-test-'));
  dirs.push(dir);
  const file = join(dir, 'image.tar');
  writeFileSync(file, tar(...entries));
  return file;
}

const KEY = ['-----BEGIN OPENSSH', 'PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n'].join(' ');
const GH_TOKEN = `ghp_${'a1B2c3D4e5'.repeat(4)}`;

describe('checkPath', () => {
  it('flags env files, keys, VCS dirs, credentials and databases', () => {
    for (const p of [
      'app/.env',
      'app/.env.local',
      '.envrc',
      'root/.npmrc',
      'home/x/.netrc',
      'app/.git/config',
      'home/nonroot/.ssh/known_hosts',
      'root/.aws/credentials',
      'root/.docker/config.json',
      'app/id_ed25519',
      'app/id_rsa.pub',
      'app/server.key',
      'app/cert.pem',
      'app/store.p12',
      'app/kordn.sqlite',
      'app/kordn.sqlite-wal',
    ]) {
      expect(checkPath(p), p).not.toBeNull();
    }
  });

  it('allows ordinary files and the system CA bundle', () => {
    for (const p of [
      'app/dist/index.js',
      'app/node_modules/zod/package.json',
      'etc/ssl/certs/ca-certificates.crt',
      'etc/ssl/certs/Some_Root_CA.pem',
      'usr/share/ca-certificates/mozilla/Some_Root_CA.crt',
      'app/environment.js',
      'app/keys.js',
    ]) {
      expect(checkPath(p), p).toBeNull();
    }
  });
});

describe('checkText', () => {
  it('flags private keys and well-known token formats', () => {
    expect(checkText(KEY)).toEqual(['private key']);
    expect(checkText(`token: ${GH_TOKEN}`)).toEqual(['GitHub token']);
    expect(checkText('AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP')).toEqual(['AWS access key']);
    expect(checkText(`x-api-key: sk-ant-api03-${'x'.repeat(40)}`)).toEqual(['Anthropic API key']);
    expect(checkText('//registry.npmjs.org/:_authToken=abc')).toEqual(['npm auth token']);
  });

  it('passes ordinary code', () => {
    expect(checkText('export function hardenedRunFlags() { return ["--read-only"]; }')).toEqual([]);
  });
});

describe('checkConfig', () => {
  it('flags secret-looking env vars, SSH agent sockets and build args in history', () => {
    expect(checkConfig({ env: ['PATH=/usr/bin', 'NPM_TOKEN=abc'], labels: {}, history: [] })).toHaveLength(1);
    expect(checkConfig({ env: ['SSH_AUTH_SOCK=/tmp/agent.sock'], labels: {}, history: [] })).toHaveLength(1);
    expect(checkConfig({ env: [], labels: {}, history: ['RUN |1 GITHUB_TOKEN=xyz /bin/sh -c npm ci'] })).toHaveLength(1);
    expect(checkConfig({ env: [], labels: { note: GH_TOKEN }, history: [] })).toHaveLength(1);
  });

  it('passes the base image config', () => {
    expect(
      checkConfig({
        env: ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt', 'NODE_ENV=production'],
        labels: {},
        history: ['COPY /app/dist ./dist # buildkit', 'USER 65532:65532', 'CMD ["/app/sandbox/agent.mjs"]'],
      }),
    ).toEqual([]);
  });
});

describe('scanImageArchive', () => {
  it('reads every layer, compressed or not, including files deleted by a later layer', async () => {
    const clean = tar(entry('app/', '', '5'), entry('app/dist/index.js', 'console.log(1)'));
    const leaky = tar(paxPath(`app/${'deep/'.repeat(30)}.env`), entry('ignored-by-pax', 'SECRET=1'));
    const keyed = tar(entry('app/notes.txt', KEY), entry('app/.wh.notes.txt', ''));
    const file = archive(
      entry('oci-layout', '{"imageLayoutVersion":"1.0.0"}'),
      entry('blobs/sha256/aaa', clean),
      entry('blobs/sha256/bbb', gzipSync(leaky)),
      entry('blobs/sha256/ccc', zstdCompressSync(keyed)),
      entry('blobs/sha256/ddd', `{"config":{"Env":["T=${GH_TOKEN}"]}}`),
    );
    const scan = await scanImageArchive(file);
    expect(scan.layers).toBe(3);
    expect(scan.entries).toBe(5);
    expect(scan.findings).toEqual([
      { where: `blobs/sha256/bbb:app/${'deep/'.repeat(30)}.env`, reason: 'env file' },
      { where: 'blobs/sha256/ccc:app/notes.txt', reason: 'private key' },
      { where: 'blobs/sha256/ddd', reason: 'GitHub token' },
    ]);
  });

  it('finds nothing in a clean image', async () => {
    const file = archive(entry('blobs/sha256/aaa', tar(entry('app/dist/index.js', 'console.log(1)'))), entry('index.json', '{}'));
    expect((await scanImageArchive(file)).findings).toEqual([]);
  });

  it('fails on a corrupt archive instead of reporting it clean', async () => {
    const good = tar(entry('app/a.js', 'x'));
    good[148] = '9'.charCodeAt(0);
    const file = archive(entry('blobs/sha256/aaa', good));
    await expect(scanImageArchive(file)).rejects.toThrow(/checksum/);
  });
});

describe('secret names and URL credentials', () => {
  const env = (...e: string[]) => checkConfig({ env: e, labels: {}, history: [] });

  it('flags a secret-looking env name whatever its value', () => {
    for (const e of ['API_KEY=', 'API_KEY= abc', 'API_KEY=\nabc', 'API_KEY=\tabc', 'DB_PASS=x', 'PASSWORD=x', 'MY_PASSWD=', 'AWS_ACCESS_KEY=x', 'GITHUB_TOKEN']) {
      expect(env(e), JSON.stringify(e)).not.toEqual([]);
    }
  });

  it('flags credentials in a *_URL value', () => {
    expect(env('DATABASE_URL=postgres://kordn:hunter2@db:5432/kordn')).toEqual([{ where: 'env DATABASE_URL', reason: 'credentials in a URL' }]);
    expect(env('DATABASE_URL=postgres://db:5432/kordn', 'PROXY_URL=http://proxy:3128')).toEqual([]);
    expect(checkText('export REDIS_URL="redis://default:s3cret@cache:6379"')).toEqual(['credentials in a URL']);
  });

  it('passes ordinary names', () => {
    expect(env('PATH=/usr/bin', 'NODE_ENV=production', 'SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt', 'HOME=/', 'PASSAGE=1')).toEqual([]);
  });
});

describe('parseHistory', () => {
  it('keeps a multi-line history entry whole, so a secret value stays with its name', () => {
    const stdout = `${JSON.stringify('ENV API_TOKEN=\\\n  abc123')}\n${JSON.stringify('CMD ["/app/sandbox/agent.mjs"]')}\n`;
    const history = parseHistory(stdout);
    expect(history).toEqual(['ENV API_TOKEN=\\\n  abc123', 'CMD ["/app/sandbox/agent.mjs"]']);
    expect(checkConfig({ env: [], labels: {}, history })).toEqual([{ where: 'history[0]', reason: 'secret-named assignment' }]);
  });

  it('rejects output that is not one JSON string per line', () => {
    expect(() => parseHistory('ENV A=1\n')).toThrow(/history/);
    expect(() => parseHistory('{"a":1}\n')).toThrow(/history/);
  });
});

describe('createTextScanner', () => {
  it('finds a pattern split across two chunks', () => {
    const s = createTextScanner();
    const text = `${'x'.repeat(100)} ${GH_TOKEN} ${'y'.repeat(100)}`;
    const cut = text.indexOf('ghp_') + 10;
    s.write(Buffer.from(text.slice(0, cut), 'latin1'));
    s.write(Buffer.from(text.slice(cut), 'latin1'));
    expect(s.reasons()).toEqual(['GitHub token']);
  });

  it('reports each reason once', () => {
    const s = createTextScanner();
    for (let i = 0; i < 5; i++) s.write(Buffer.from(`${GH_TOKEN}\n`));
    expect(s.reasons()).toEqual(['GitHub token']);
  });
});

describe('scanImageArchive limits', () => {
  it('scans the content of files over 4 MiB', async () => {
    const big = Buffer.concat([Buffer.alloc(5 * 1024 * 1024, 'a'), Buffer.from(`\n${GH_TOKEN}\n`)]);
    const file = archive(entry('blobs/sha256/aaa', gzipSync(tar(entry('app/bundle.js', big)))));
    expect((await scanImageArchive(file)).findings).toEqual([{ where: 'blobs/sha256/aaa:app/bundle.js', reason: 'GitHub token' }]);
  });

  it('name-checks links and directories too', async () => {
    const layer = tar(entry('app/kordn.sqlite', '', '1'), entry('app/.env', '', '2'), entry('root/.ssh/', '', '5'));
    const scan = await scanImageArchive(archive(entry('blobs/sha256/aaa', layer)));
    expect(scan.findings).toEqual([
      { where: 'blobs/sha256/aaa:app/kordn.sqlite', reason: 'database file' },
      { where: 'blobs/sha256/aaa:app/.env', reason: 'env file' },
      { where: 'blobs/sha256/aaa:root/.ssh/', reason: 'credentials or VCS directory' },
    ]);
  });

  it('refuses an unrecognised blob over the size limit instead of skipping it', async () => {
    const file = archive(entry('blobs/sha256/aaa', Buffer.alloc(4 * 1024 * 1024 + 1, 'z')));
    await expect(scanImageArchive(file)).rejects.toThrow(/unrecognised blob/);
  });
});

describe('isSecretName', () => {
  it('flags secret words however the name is written', () => {
    for (const n of [
      'PGPASSWORD',
      'SECRETS',
      'TOKENS',
      'MYTOKEN',
      'GITHUBTOKEN',
      'githubToken',
      'authToken',
      'dbPassword',
      'DB_PASS',
      'API_KEY',
      'APIKEY',
      'AWS_SECRET_ACCESS_KEY',
      'STRIPE_KEY',
      'SIGNING_KEY',
      'GPG_PASSPHRASE',
      'GOOGLE_AUTH',
      'DB_PW',
      'Token2',
      'OAUTH2_TOKEN',
      'stripeKey',
      'dbPw',
    ]) {
      expect(isSecretName(n), n).toBe(true);
    }
  });

  it('leaves ordinary names alone', () => {
    for (const n of ['TOKENIZER_PATH', 'PASSPORT', 'BYPASS', 'PATH', 'HOME', 'NODE_ENV', 'SSL_CERT_FILE', 'KEYBOARD', 'MONKEY', 'AUTHOR', 'PWD', 'HOSTNAME']) {
      expect(isSecretName(n), n).toBe(false);
    }
  });
});

describe('checkConfig: embedded assignments and URL credentials', () => {
  const env = (...e: string[]) => checkConfig({ env: e, labels: {}, history: [] });

  it('finds a secret assignment embedded in another variable', () => {
    expect(env('FOO=bar GITHUB_TOKEN=abc')).toEqual([{ where: 'env FOO', reason: 'secret-named assignment' }]);
  });

  it('flags URL credentials with an empty user, other suffixes and any case', () => {
    for (const e of [
      'REDIS_URL=redis://:pw@cache:6379',
      'DATABASE_URI=postgres://u:p@db/x',
      'SENTRY_DSN=https://k:s@sentry.example/1',
      'DB_CONNECTION_STRING=mysql://u:p@db/x',
      'database_url=postgres://u:p@db/x',
    ]) {
      expect(env(e), e).toEqual([{ where: `env ${e.split('=')[0]}`, reason: 'credentials in a URL' }]);
    }
  });
});

describe('checkConfig on huge single-word values', () => {
  // A long run of word characters with no '=' made the unanchored assignment regex quadratic.
  it('scans a 1 MB word in an env value, env name, history line or label in well under a second', () => {
    const word = 'a'.repeat(1024 * 1024);
    for (const config of [
      { env: [`F=${word}`], labels: {}, history: [] },
      { env: [word], labels: {}, history: [] },
      { env: [], labels: {}, history: [word] },
      { env: [], labels: { note: word }, history: [] },
      { env: [`F=${'x_'.repeat(512 * 1024)}`], labels: {}, history: [] },
    ]) {
      const started = performance.now();
      expect(checkConfig(config)).toEqual([]);
      expect(performance.now() - started).toBeLessThan(500);
    }
  });

  it('still finds a secret assignment after a long word', () => {
    expect(checkConfig({ env: [`F=${'a'.repeat(100_000)} GITHUB_TOKEN=x`], labels: {}, history: [] })).toEqual([
      { where: 'env F', reason: 'secret-named assignment' },
    ]);
  });
});
