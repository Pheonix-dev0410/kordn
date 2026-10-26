import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { adminFileDir, writeAdminFile } from '../src/admin/runtime-file.js';

// Where kordn --admin leaves its URL and login token for the user to find.

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});
const tempDir = () => {
  const dir = mkdtempSync(join(tmpdir(), 'kordn-test-'));
  dirs.push(dir);
  return dir;
};
const uid = process.getuid!();
const contents = { url: 'http://127.0.0.1:4321/', token: 't'.repeat(43), pid: 1234, agentId: 'sandbox-demo-01' };

describe('adminFileDir', () => {
  it('uses $XDG_RUNTIME_DIR/kordn', () => {
    expect(adminFileDir({ env: { XDG_RUNTIME_DIR: '/run/user/1000' }, tmp: '/tmp', uid: 1000 })).toBe('/run/user/1000/kordn');
  });

  it.each([
    ['unset', {}],
    ['empty', { XDG_RUNTIME_DIR: '' }],
    ['relative', { XDG_RUNTIME_DIR: 'run/user/1000' }],
  ])('falls back to a per-uid directory in the temp dir when XDG_RUNTIME_DIR is %s', (_name, env) => {
    expect(adminFileDir({ env, tmp: '/tmp', uid: 1000 })).toBe('/tmp/kordn-1000');
  });
});

describe('writeAdminFile', () => {
  it('writes the URL and token to a 0600 file in a 0700 directory, and removes it', () => {
    const dir = join(tempDir(), 'kordn');
    const file = writeAdminFile(contents, dir);
    expect(file.path).toBe(join(dir, 'admin-1234.json'));
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    expect(statSync(file.path).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(file.path, 'utf8'))).toEqual(contents);
    file.remove();
    expect(existsSync(file.path)).toBe(false);
    file.remove();
  });

  it('reuses an existing private directory and replaces a stale file of the same pid', () => {
    const dir = join(tempDir(), 'kordn');
    writeAdminFile({ ...contents, token: 'old' }, dir);
    const file = writeAdminFile(contents, dir);
    expect(JSON.parse(readFileSync(file.path, 'utf8')).token).toBe(contents.token);
  });

  it('refuses a directory other users can reach', () => {
    const dir = join(tempDir(), 'kordn');
    mkdirSync(dir);
    chmodSync(dir, 0o755);
    expect(() => writeAdminFile(contents, dir)).toThrow(/refusing to use .*: mode 755/);
  });

  it('refuses a symlink in place of the directory', () => {
    const root = tempDir();
    const target = join(root, 'elsewhere');
    mkdirSync(target, { mode: 0o700 });
    symlinkSync(target, join(root, 'kordn'));
    expect(() => writeAdminFile(contents, join(root, 'kordn'))).toThrow(/refusing to use .*: not a directory/);
  });

  it('names the admin file and its directory when XDG_RUNTIME_DIR is missing or unusable', () => {
    const missing = join(tempDir(), 'gone', 'kordn');
    expect(() => writeAdminFile(contents, missing)).toThrow(
      `could not write the admin file ${join(missing, 'admin-1234.json')} (directory ${missing}): ENOENT`,
    );
    const notADir = join(tempDir(), 'file');
    writeFileSync(notADir, '');
    expect(() => writeAdminFile(contents, join(notADir, 'kordn'))).toThrow(/could not write the admin file .*admin-1234\.json \(directory .*\): ENOTDIR/);
  });

  it('refuses a directory owned by another user', () => {
    const dir = join(tempDir(), 'kordn');
    expect(() => writeAdminFile(contents, dir, { uid: uid + 1 })).toThrow(/refusing to use .*: owned by uid/);
  });
});
