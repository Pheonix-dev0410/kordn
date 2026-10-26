import { z } from 'zod';

// Runtime facts gathered from inside the sandbox. The launcher pipes probeScript() into
// `node -` in the container, so isolationProbe must be self-contained: no imports or
// outer variables, only process.getBuiltinModule. It reports env var names, never values.
// Its output comes from inside the untrusted boundary: parse it strictly and treat any
// missing or odd field as a failed check.

export interface ProbeParams {
  /** Socket path inside the container. Connect only, unless `call` is given. */
  socketPath: string;
  /** One guardian call to make through the socket (tests only: a call counts against quota). */
  call?: { tool: string; args: unknown };
  /** Directories to try creating a file in. */
  writeTargets: string[];
  /** Paths that should not exist. */
  absentPaths: string[];
  /** TCP endpoints to try. */
  connect: { host: string; port: number }[];
  timeoutMs: number;
}

const Outcome = z.string().max(200);
const Lines = z.array(z.string().max(4096)).max(10_000).nullable();

export const ProbeResult = z.strictObject({
  uid: z.number().int(),
  gid: z.number().int(),
  groups: z.array(z.number().int()),
  /** Selected /proc/self/status fields: Cap*, NoNewPrivs, Seccomp. */
  status: z.record(z.string(), z.string()),
  interfaces: Lines,
  /** Interface name of every IPv4 / IPv6 route. */
  ipv4Routes: Lines,
  ipv6Routes: Lines,
  /** From /proc/self/mountinfo. `root` is the path within the source filesystem (not "/" for a bind of a subdirectory). */
  mounts: z
    .array(z.strictObject({ mountPoint: z.string(), root: z.string(), fsType: z.string(), source: z.string(), options: z.string() }))
    .nullable(),
  writes: z.array(z.strictObject({ path: z.string(), result: Outcome })),
  paths: z.array(z.strictObject({ path: z.string(), result: Outcome })),
  connects: z.array(z.strictObject({ host: z.string(), port: z.number().int(), result: Outcome })),
  env: z.array(z.string()),
  pidsMax: Outcome,
  memoryMax: Outcome,
  pid1: Lines,
  /** readlink of /proc/self/ns/<kind>, e.g. "net:[4026531833]", or "error:<code>". */
  namespaces: z.record(z.string(), Outcome),
  socket: z.strictObject({ connected: z.boolean(), error: Outcome.nullable(), response: z.unknown() }),
});
export type ProbeResult = z.infer<typeof ProbeResult>;

export function probeScript(params: ProbeParams): string {
  return `(${isolationProbe.toString()})(${JSON.stringify(params)}).then((r) => process.stdout.write(JSON.stringify(r)));\n`;
}

export function parseProbeOutput(stdout: string): ProbeResult | null {
  try {
    const parsed = ProbeResult.safeParse(JSON.parse(stdout));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export async function isolationProbe(params: ProbeParams): Promise<ProbeResult> {
  const fs = process.getBuiltinModule('node:fs');
  const net = process.getBuiltinModule('node:net');
  const path = process.getBuiltinModule('node:path');
  const crypto = process.getBuiltinModule('node:crypto');

  const code = (e: unknown): string => {
    const c = (e as { code?: unknown } | null)?.code;
    return typeof c === 'string' ? c : String((e as Error)?.message ?? e).slice(0, 200);
  };
  const read = (file: string): string | null => {
    try {
      return fs.readFileSync(file, 'utf8');
    } catch {
      return null;
    }
  };
  const lines = (text: string | null): string[] => (text ?? '').split('\n').filter((l) => l.trim() !== '');
  const orError = (file: string): string => {
    try {
      return fs.readFileSync(file, 'utf8').trim();
    } catch (e) {
      return `error:${code(e)}`;
    }
  };

  const status: Record<string, string> = {};
  for (const line of lines(read('/proc/self/status'))) {
    const m = /^(Cap\w+|NoNewPrivs|Seccomp):\s*(\S+)/.exec(line);
    if (m?.[1] && m[2]) status[m[1]] = m[2];
  }

  let interfaces: string[] | null;
  try {
    interfaces = fs.readdirSync('/sys/class/net').sort();
  } catch {
    interfaces = null;
  }
  const route4 = read('/proc/net/route');
  const ipv4Routes = route4 === null ? null : lines(route4).slice(1).map((l) => l.split(/\s+/)[0] ?? '');
  const route6 = read('/proc/net/ipv6_route');
  // A kernel without IPv6 has no ipv6_route, which also means no IPv6 routes.
  const ipv6Routes =
    route6 === null && !fs.existsSync('/proc/net/if_inet6') ? [] : route6 === null ? null : lines(route6).map((l) => l.trim().split(/\s+/).at(-1) ?? '');

  const unescape = (s: string) => s.replace(/\\([0-7]{3})/g, (_, o: string) => String.fromCharCode(parseInt(o, 8)));
  const mountinfo = read('/proc/self/mountinfo');
  const mounts =
    mountinfo === null
      ? null
      : lines(mountinfo).map((l) => {
          const [left = '', right = ''] = l.split(' - ');
          const f = left.split(' ');
          const r = right.split(' ');
          return { mountPoint: unescape(f[4] ?? ''), root: unescape(f[3] ?? ''), options: f[5] ?? '', fsType: r[0] ?? '', source: unescape(r[1] ?? '') };
        });

  const writes = params.writeTargets.map((dir) => {
    const file = path.join(dir, `.kordn-probe-${crypto.randomBytes(6).toString('hex')}`);
    try {
      fs.writeFileSync(file, '', { flag: 'wx' });
      fs.rmSync(file, { force: true });
      return { path: dir, result: 'ok' };
    } catch (e) {
      return { path: dir, result: code(e) };
    }
  });

  const paths = params.absentPaths.map((p) => {
    try {
      fs.lstatSync(p);
      return { path: p, result: 'present' };
    } catch (e) {
      return { path: p, result: code(e) };
    }
  });

  const connects = await Promise.all(
    params.connect.map(
      ({ host, port }) =>
        new Promise<{ host: string; port: number; result: string }>((resolve) => {
          const done = (result: string) => {
            sock.destroy();
            resolve({ host, port, result });
          };
          const sock = net.connect({ host, port, timeout: params.timeoutMs });
          sock.on('connect', () => done('connected'));
          sock.on('timeout', () => done('timeout'));
          sock.on('error', (e) => done(code(e)));
        }),
    ),
  );

  const socket = await new Promise<{ connected: boolean; error: string | null; response: unknown }>((resolve) => {
    let connected = false;
    let buffered = '';
    const sock = net.connect(params.socketPath);
    const done = (error: string | null, response: unknown = null) => {
      clearTimeout(timer);
      sock.destroy();
      resolve({ connected, error, response });
    };
    const timer = setTimeout(() => done('timeout'), params.timeoutMs);
    sock.setEncoding('utf8');
    sock.on('connect', () => {
      connected = true;
      if (!params.call) return done(null);
      sock.write(`${JSON.stringify({ v: 1, id: 'probe-1', tool: params.call.tool, args: params.call.args })}\n`);
    });
    sock.on('data', (d: string) => {
      buffered += d;
      const nl = buffered.indexOf('\n');
      if (nl === -1) return;
      try {
        done(null, JSON.parse(buffered.slice(0, nl)));
      } catch {
        done('bad response');
      }
    });
    sock.on('close', () => done(connected ? 'closed' : 'not connected'));
    sock.on('error', (e) => done(code(e)));
  });

  const pid1 = read('/proc/1/cmdline');
  const namespaces: Record<string, string> = {};
  for (const ns of ['cgroup', 'ipc', 'mnt', 'net', 'pid', 'user', 'uts']) {
    try {
      namespaces[ns] = fs.readlinkSync(`/proc/self/ns/${ns}`);
    } catch (e) {
      namespaces[ns] = `error:${code(e)}`;
    }
  }

  return {
    uid: process.getuid?.() ?? -1,
    gid: process.getgid?.() ?? -1,
    groups: process.getgroups?.() ?? [],
    status,
    interfaces,
    ipv4Routes,
    ipv6Routes,
    mounts,
    writes,
    paths,
    connects,
    env: Object.keys(process.env).sort(),
    pidsMax: orError('/sys/fs/cgroup/pids.max'),
    memoryMax: orError('/sys/fs/cgroup/memory.max'),
    pid1: pid1 === null ? null : pid1.split('\0').filter((a) => a !== ''),
    namespaces,
    socket,
  };
}
