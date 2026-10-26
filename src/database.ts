import { closeSync, constants, fchmodSync, fstatSync, openSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

/** Protect policy, approval nonces, and SQLite's neighbouring WAL files. */
export function openPrivateDatabase(path: string): DatabaseSync {
  if (typeof path !== 'string' || !path) throw new Error('an explicit database path is required');
  if (path !== ':memory:') {
    const directory = statSync(dirname(resolve(path)));
    if (!directory.isDirectory() || (directory.mode & 0o077) !== 0) throw new Error('database needs a private directory');
    const fd = openSync(path, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
    try {
      const file = fstatSync(fd);
      if (!file.isFile() || file.nlink !== 1) throw new Error('database must be a regular file without hard links');
      fchmodSync(fd, 0o600);
    } finally { closeSync(fd); }
  }
  return new DatabaseSync(path);
}
