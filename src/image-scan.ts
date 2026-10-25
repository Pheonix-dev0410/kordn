import { execFile, spawn } from 'node:child_process';
import { closeSync, createReadStream, createWriteStream, mkdtempSync, openSync, readSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { promisify } from 'node:util';
import { createGunzip, createZstdDecompress } from 'node:zlib';

// Checks that the sandbox image carries no secrets. It reads every layer of `docker save`
// (a file deleted in a later layer still ships in the earlier one), plus the image env,
// labels and build history. Heuristic: it catches the obvious mistakes, it can't prove
// absence. A corrupt, truncated or unrecognised archive is an error, never a clean result.

export interface Finding {
  where: string;
  reason: string;
}

export interface ImageScan {
  layers: number;
  /** Layer entries checked: files, links and directories. */
  entries: number;
  findings: Finding[];
}

/** Largest non-layer blob (config, manifest, index) we accept. */
const MAX_BLOB_BYTES = 4 * 1024 * 1024;
/** Longest secret pattern we need to see whole across two chunks. */
const OVERLAP = 4096;
const MAX_META_BYTES = 1024 * 1024;

const CA_DIRS = /^(etc\/ssl\/certs|usr\/share\/ca-certificates|usr\/local\/share\/ca-certificates)\//;

const PATH_RULES: [RegExp, string][] = [
  [/(^|\/)\.env(\.[^/]*)?$|(^|\/)\.envrc$/, 'env file'],
  [/(^|\/)\.(npmrc|netrc|pgpass|git-credentials|bash_history)$/, 'credentials file'],
  [/(^|\/)\.(git|ssh|aws|gnupg|docker|kube)(\/|$)/, 'credentials or VCS directory'],
  [/(^|\/)id_(rsa|dsa|ecdsa|ed25519)[^/]*$/, 'SSH key'],
  [/\.(pem|key|p12|pfx|jks|keystore)$/, 'key or certificate file'],
  [/\.sqlite[^/]*$/, 'database file'],
];

const TEXT_RULES: [RegExp, string][] = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'private key'],
  [/\bAKIA[0-9A-Z]{16}\b/, 'AWS access key'],
  [/\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/, 'GitHub token'],
  [/\bsk-ant-[A-Za-z0-9_-]{20,}/, 'Anthropic API key'],
  [/\bsk-(proj-)?[A-Za-z0-9]{32,}/, 'OpenAI API key'],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/, 'Slack token'],
  [/\bglpat-[A-Za-z0-9_-]{20,}/, 'GitLab token'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/, 'Google API key'],
  [/\bnpm_[A-Za-z0-9]{36}\b|_authToken\s*=/, 'npm auth token'],
  // A *_URL variable whose value carries user and password before the host.
  [/\b[A-Za-z][A-Za-z0-9_]*_URL\s*[=:]\s*["']?[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s:@/"']+:[^\s@/"']+@/, 'credentials in a URL'],
];

/** A variable name made of _-separated words, one of which says it holds a secret. */
const SECRET_NAME = /(^|_)(TOKEN|SECRET|PASS|PASSWORD|PASSWD|CREDENTIALS?|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)(_|$)/i;
const ASSIGNED_NAMES = /([A-Za-z_][A-Za-z0-9_]*)=/g;

export function checkPath(path: string): string | null {
  const p = path.replace(/^\.?\//, '');
  if (CA_DIRS.test(p)) return null;
  for (const [rule, reason] of PATH_RULES) if (rule.test(p)) return reason;
  return null;
}

export function checkText(text: string): string[] {
  return TEXT_RULES.filter(([rule]) => rule.test(text)).map(([, reason]) => reason);
}

/** Scans a stream of chunks, keeping an overlap so a match split across chunks is found. */
export function createTextScanner(): { write(chunk: Buffer): void; reasons(): string[] } {
  let tail = '';
  const found = new Set<string>();
  return {
    write(chunk) {
      const text = tail + chunk.toString('latin1');
      for (const reason of checkText(text)) found.add(reason);
      tail = text.slice(-OVERLAP);
    },
    reasons: () => [...found],
  };
}

export function checkConfig(config: { env: string[]; labels: Record<string, string>; history: string[] }): Finding[] {
  const findings: Finding[] = [];
  const check = (where: string, text: string) => {
    for (const reason of checkText(text)) findings.push({ where, reason });
    const names = [...text.matchAll(ASSIGNED_NAMES)].map((m) => m[1] ?? '');
    if (names.some((n) => SECRET_NAME.test(n))) findings.push({ where, reason: 'secret-named assignment' });
  };
  for (const e of config.env) {
    // The name alone decides: an empty, blank or newline-led value is still a secret slot.
    const name = e.split('=')[0] ?? '';
    if (name === 'SSH_AUTH_SOCK') {
      findings.push({ where: 'env SSH_AUTH_SOCK', reason: 'SSH agent socket' });
      continue;
    }
    if (SECRET_NAME.test(name)) findings.push({ where: `env ${name}`, reason: 'secret-named variable' });
    for (const reason of checkText(e)) findings.push({ where: `env ${name}`, reason });
  }
  for (const [k, v] of Object.entries(config.labels)) check(`label ${k}`, `${k}=${v}`);
  config.history.forEach((line, i) => check(`history[${i}]`, line));
  return findings;
}

/** `docker history --format '{{json .CreatedBy}}'`: one JSON string per line, even for multi-line commands. */
export function parseHistory(stdout: string): string[] {
  return stdout
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((line) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        parsed = undefined;
      }
      if (typeof parsed !== 'string') throw new Error(`unexpected docker history line: ${line.slice(0, 80)}`);
      return parsed;
    });
}

// ---- tar reading ----

interface TarHeader {
  path: string;
  type: string;
  size: number;
}

/** Parses a 512-byte ustar header; null for the all-zero end-of-archive block. */
function parseHeader(block: Buffer): TarHeader | null {
  if (block.every((b) => b === 0)) return null;
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 0x20 : (block[i] ?? 0);
  const stored = parseInt(block.toString('latin1', 148, 156).replace(/\0.*$/, '').trim(), 8);
  if (stored !== sum) throw new Error('tar header checksum mismatch: corrupt archive');
  const str = (from: number, to: number) => block.toString('utf8', from, to).replace(/\0.*$/s, '');
  const sizeField = block.subarray(124, 136);
  // GNU base-256 encoding for files over 8 GiB.
  const size = (sizeField[0] ?? 0) & 0x80 ? Number(sizeField.readBigUInt64BE(4)) : parseInt(str(124, 136).trim() || '0', 8);
  const prefix = str(257, 263).startsWith('ustar') ? str(345, 500) : '';
  return { path: prefix ? `${prefix}/${str(0, 100)}` : str(0, 100), type: str(156, 157) || '0', size };
}

function paxPath(data: Buffer): string | null {
  for (const record of data.toString('utf8').split('\n')) {
    const m = /^\d+ path=(.*)$/s.exec(record);
    if (m?.[1] !== undefined) return m[1];
  }
  return null;
}

/** pax extended header (x), pax global (g), GNU long name (L) and long link name (K). */
const META_TYPES = new Set(['x', 'g', 'L', 'K']);
const isRegular = (type: string) => type === '0' || type === '7';

/** Streaming tar reader for one layer. Calls onEntry for every entry with any content findings. */
class TarReader {
  private buffered: Buffer = Buffer.alloc(0);
  private current: TarHeader | null = null;
  private remaining = 0;
  private padding = 0;
  private meta: Buffer[] = [];
  private scanner: ReturnType<typeof createTextScanner> | null = null;
  private nextPath: string | null = null;
  private ended = false;

  constructor(private readonly onEntry: (path: string, contentReasons: string[]) => void) {}

  write(chunk: Buffer): void {
    this.buffered = this.buffered.length ? Buffer.concat([this.buffered, chunk]) : chunk;
    while (!this.ended) {
      if (this.current) {
        if (this.remaining > 0) {
          if (this.buffered.length === 0) return;
          const take = Math.min(this.remaining, this.buffered.length);
          const data = this.buffered.subarray(0, take);
          if (META_TYPES.has(this.current.type)) this.meta.push(data);
          else this.scanner?.write(data);
          this.buffered = this.buffered.subarray(take);
          this.remaining -= take;
          if (this.remaining > 0) return;
        }
        if (this.buffered.length < this.padding) return;
        this.buffered = this.buffered.subarray(this.padding);
        this.finish(this.current);
        this.current = null;
        continue;
      }
      if (this.buffered.length < 512) return;
      const header = parseHeader(this.buffered.subarray(0, 512));
      this.buffered = this.buffered.subarray(512);
      if (!header) {
        this.ended = true;
        return;
      }
      if (META_TYPES.has(header.type) && header.size > MAX_META_BYTES) throw new Error('oversized tar metadata entry');
      this.current = header;
      this.remaining = header.size;
      this.padding = (512 - (header.size % 512)) % 512;
      this.meta = [];
      this.scanner = isRegular(header.type) ? createTextScanner() : null;
    }
  }

  end(): void {
    if (this.current || (!this.ended && this.buffered.length > 0)) throw new Error('truncated tar archive');
  }

  private finish(h: TarHeader): void {
    if (h.type === 'x' || h.type === 'L') {
      const data = Buffer.concat(this.meta);
      this.nextPath = h.type === 'x' ? paxPath(data) : data.toString('utf8').replace(/\0.*$/s, '');
      return;
    }
    if (META_TYPES.has(h.type)) return;
    const path = this.nextPath ?? h.path;
    this.nextPath = null;
    this.onEntry(path, this.scanner?.reasons() ?? []);
    this.scanner = null;
  }
}

/** Scans a `docker save` archive (OCI layout or legacy): each blob is a layer tar or small JSON. */
export async function scanImageArchive(archivePath: string): Promise<ImageScan> {
  const scan: ImageScan = { layers: 0, entries: 0, findings: [] };
  const fd = openSync(archivePath, 'r');
  try {
    let offset = 0;
    let nextPath: string | null = null;
    const block = Buffer.alloc(512);
    for (;;) {
      if (readSync(fd, block, 0, 512, offset) !== 512) throw new Error('truncated image archive');
      const header = parseHeader(block);
      if (!header) break;
      const dataStart = offset + 512;
      offset = dataStart + header.size + ((512 - (header.size % 512)) % 512);
      if (header.type === 'x' || header.type === 'L') {
        if (header.size > MAX_META_BYTES) throw new Error('oversized tar metadata entry');
        const data = Buffer.alloc(header.size);
        readSync(fd, data, 0, header.size, dataStart);
        nextPath = header.type === 'x' ? paxPath(data) : data.toString('utf8').replace(/\0.*$/s, '');
        continue;
      }
      const name = nextPath ?? header.path;
      nextPath = null;
      if (!isRegular(header.type) || header.size === 0) continue;
      await scanBlob(archivePath, name, dataStart, header.size, scan);
    }
  } finally {
    closeSync(fd);
  }
  return scan;
}

async function scanBlob(archivePath: string, name: string, start: number, size: number, scan: ImageScan): Promise<void> {
  const magic = Buffer.alloc(Math.min(size, 263));
  const fd = openSync(archivePath, 'r');
  try {
    readSync(fd, magic, 0, magic.length, start);
  } finally {
    closeSync(fd);
  }
  const range = () => createReadStream(archivePath, { start, end: start + size - 1 });
  const gzip = magic[0] === 0x1f && magic[1] === 0x8b;
  const zstd = magic.length >= 4 && magic.readUInt32LE(0) === 0xfd2fb528;
  const plainTar = magic.toString('latin1', 257, 262) === 'ustar';

  if (!gzip && !zstd && !plainTar) {
    // Config, manifest or index JSON: search the text (it includes env and history).
    if (size > MAX_BLOB_BYTES) throw new Error(`unrecognised blob ${name} (${size} bytes): not a layer, too big to be config`);
    const scanner = createTextScanner();
    for await (const c of range()) scanner.write(c as Buffer);
    for (const reason of scanner.reasons()) scan.findings.push({ where: name, reason });
    return;
  }

  scan.layers++;
  const reader = new TarReader((path, contentReasons) => {
    scan.entries++;
    const where = `${name}:${path}`;
    const byName = checkPath(path);
    if (byName) scan.findings.push({ where, reason: byName });
    for (const reason of contentReasons) scan.findings.push({ where, reason });
  });
  const sink = new Writable({
    write(chunk: Buffer, _enc, cb) {
      try {
        reader.write(chunk);
        cb();
      } catch (e) {
        cb(e as Error);
      }
    },
    final(cb) {
      try {
        reader.end();
        cb();
      } catch (e) {
        cb(e as Error);
      }
    },
  });
  if (gzip) await pipeline(range(), createGunzip(), sink);
  else if (zstd) await pipeline(range(), createZstdDecompress(), sink);
  else await pipeline(range(), sink);
}

// ---- docker ----

const run = promisify(execFile);

/** Saves the image to a private temp dir, scans layers, env, labels and history, then deletes it. */
export async function scanImage(image: string, docker = 'docker'): Promise<ImageScan> {
  const { stdout: inspectOut } = await run(docker, ['image', 'inspect', '--format', '{{json .Config}}', '--', image]);
  const config = JSON.parse(inspectOut) as { Env?: string[] | null; Labels?: Record<string, string> | null };
  const { stdout: historyOut } = await run(docker, ['history', '--no-trunc', '--format', '{{json .CreatedBy}}', '--', image], {
    maxBuffer: 16 * 1024 * 1024,
  });

  const dir = mkdtempSync(join(tmpdir(), 'kordn-image-scan-'));
  try {
    const archive = join(dir, `${basename(image).replace(/[^A-Za-z0-9_.-]/g, '_')}.tar`);
    const save = spawn(docker, ['save', '--', image], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    save.stderr.setEncoding('utf8').on('data', (d: string) => (stderr += d));
    const exited = new Promise<number | null>((resolve, reject) => {
      save.on('error', reject);
      save.on('close', resolve);
    });
    await pipeline(save.stdout, createWriteStream(archive));
    const code = await exited;
    if (code !== 0) throw new Error(`docker save failed (${code}): ${stderr.trim()}`);

    const scan = await scanImageArchive(archive);
    if (scan.layers === 0) throw new Error('docker save produced no layers');
    scan.findings.push(...checkConfig({ env: config.Env ?? [], labels: config.Labels ?? {}, history: parseHistory(historyOut) }));
    return scan;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
