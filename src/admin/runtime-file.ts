import { chmodSync, closeSync, fchmodSync, lstatSync, mkdirSync, openSync, rmSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';

// kordn --admin prints the admin UI's URL and login token to stderr, but an AI client that
// spawned kordn usually hides stderr. So they also go in a file only this user can read:
// $XDG_RUNTIME_DIR/kordn/admin-<pid>.json, deleted when kordn exits.

export interface AdminFileContents {
  url: string;
  token: string;
  pid: number;
  agentId: string;
}

export interface AdminFile {
  path: string;
  /** Deletes the file. Safe to call more than once, and synchronous, so it works in an 'exit' handler. */
  remove(): void;
}

/** $XDG_RUNTIME_DIR/kordn, or a per-uid directory in the temp dir when that isn't set. */
export function adminFileDir(o: { env?: NodeJS.ProcessEnv; tmp?: string; uid?: number } = {}): string {
  const runtime = (o.env ?? process.env).XDG_RUNTIME_DIR;
  if (runtime && isAbsolute(runtime)) return join(runtime, 'kordn');
  return join(o.tmp ?? tmpdir(), `kordn-${o.uid ?? process.getuid?.() ?? 0}`);
}

/**
 * Writes the file into `dir`, creating it 0700 if needed. An existing `dir` must be a real
 * directory owned by this user with no group or other access: the fallback lives in a shared
 * temp dir, where another user could have made it first.
 */
export function writeAdminFile(contents: AdminFileContents, dir = adminFileDir(), o: { uid?: number } = {}): AdminFile {
  const path = join(dir, `admin-${contents.pid}.json`);
  try {
    return writeIn(contents, dir, path, o.uid ?? process.getuid?.() ?? 0);
  } catch (e) {
    // A file system error (e.g. XDG_RUNTIME_DIR set but missing) says which file it was for.
    if (typeof (e as NodeJS.ErrnoException).code !== 'string') throw e;
    throw new Error(`could not write the admin file ${path} (directory ${dir}): ${(e as Error).message}`);
  }
}

function writeIn(contents: AdminFileContents, dir: string, path: string, uid: number): AdminFile {
  try {
    mkdirSync(dir, { mode: 0o700 });
    // mkdir's mode is filtered through the umask.
    chmodSync(dir, 0o700);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
  }
  const stat = lstatSync(dir);
  const refuse = (why: string) => new Error(`refusing to use ${dir} for the admin file: ${why}`);
  if (!stat.isDirectory()) throw refuse('not a directory');
  if (stat.uid !== uid) throw refuse(`owned by uid ${stat.uid}`);
  if ((stat.mode & 0o077) !== 0) throw refuse(`mode ${(stat.mode & 0o777).toString(8)}, other users can reach it`);

  // Left over from an earlier process with the same pid. The directory is ours alone.
  rmSync(path, { force: true });
  const fd = openSync(path, 'wx', 0o600);
  try {
    fchmodSync(fd, 0o600);
    writeSync(fd, `${JSON.stringify(contents)}\n`);
  } finally {
    closeSync(fd);
  }
  return { path, remove: () => rmSync(path, { force: true }) };
}
