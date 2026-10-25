import { z } from 'zod';
import { type ProbeParams, type ProbeResult, SANDBOX_SOCKET } from './sandbox-probe.js';

// Launcher checks for Contain mode (design doc §9.3). Pure functions over `docker info`,
// `docker inspect` and the in-container probe, so every unsafe setting can be tested
// without Docker. A check passes only when the configuration AND the runtime evidence
// agree; anything missing or unreadable is a failure.

export interface IsolationExpectations {
  /** Host path of the guardian socket. */
  socketPath: string;
  /** Expected /proc/1/cmdline of the idle container. */
  idleCommand: string[];
  hostHome: string;
  sshAuthSock?: string;
  /** Host loopback port of the launcher's canary listener. */
  canaryPort: number;
  adminPort?: number;
  dbPath?: string;
  /** Non-loopback addresses of the host. */
  hostAddresses: string[];
  /** The image's own Env (KEY=value). Anything beyond it was injected at run time. */
  imageEnv: string[];
}

const OUTBOUND_FIXED = [
  { host: '1.1.1.1', port: 443 },
  { host: '8.8.8.8', port: 53 },
  { host: '2606:4700:4700::1111', port: 443 },
  // Default docker bridge gateway, i.e. the host.
  { host: '172.17.0.1', port: 80 },
  { host: '169.254.169.254', port: 80 },
];

const WRITE_TARGETS = ['/', '/etc', '/usr', '/var', '/app', '/run'];

export function outboundTargets(e: IsolationExpectations): { host: string; port: number }[] {
  return [...OUTBOUND_FIXED, ...e.hostAddresses.map((host) => ({ host, port: 80 }))];
}

export function loopbackTargets(e: IsolationExpectations): { host: string; port: number }[] {
  const ports = e.adminPort === undefined ? [e.canaryPort] : [e.canaryPort, e.adminPort];
  return ports.flatMap((port) => [
    { host: '127.0.0.1', port },
    { host: '::1', port },
  ]);
}

export function absentPaths(e: IsolationExpectations): string[] {
  return [
    '/var/run/docker.sock',
    '/run/docker.sock',
    '/run/host-services/ssh-auth.sock',
    e.hostHome,
    ...(e.sshAuthSock ? [e.sshAuthSock] : []),
    ...(e.dbPath ? [e.dbPath] : []),
  ];
}

/** What the probe must test. The checks later require a result for every one of these. */
export function probeTargets(e: IsolationExpectations): ProbeParams {
  return {
    socketPath: SANDBOX_SOCKET,
    writeTargets: WRITE_TARGETS,
    absentPaths: absentPaths(e),
    connect: [...outboundTargets(e), ...loopbackTargets(e)],
    timeoutMs: 2000,
  };
}

// ---- evaluation ----

export const CHECK_IDS = [
  'rootless',
  'network',
  'readOnlyRootfs',
  'onlyGuardianSocket',
  'noHostEnv',
  'nonRoot',
  'capabilities',
  'noNewPrivileges',
  'seccomp',
  'namespaces',
  'resourceLimits',
  'hostServicesUnreachable',
  'guardianSocket',
] as const;
export type CheckId = (typeof CHECK_IDS)[number];

export interface IsolationCheck {
  id: CheckId;
  pass: boolean;
  detail: string;
}

export interface IsolationFacts {
  expectations: IsolationExpectations;
  /** `docker info` (only SecurityOptions is read). */
  info: unknown;
  /** `docker inspect` of the container, object or one-element array. */
  inspect: unknown;
  probe: ProbeResult | null;
  /** Connections the host-side loopback canary received. */
  canaryHits: number;
}

export interface IsolationResult {
  /** 'contain' only if every check ran and passed. */
  mode: 'contain' | 'guard';
  imageId: string | null;
  checks: IsolationCheck[];
}

const MAX_PIDS = 64;
const MAX_MEMORY = 512 * 1024 * 1024;
const MAX_NANO_CPUS = 1_000_000_000;
const NO_ROUTE = new Set(['ENETUNREACH', 'EHOSTUNREACH']);
const ZERO_CAPS = /^0+$/;

const Info = z.object({ SecurityOptions: z.array(z.string()) });

const Inspect = z.object({
  Id: z.string(),
  Image: z.string(),
  Config: z.object({ User: z.string(), Env: z.array(z.string()).nullable() }),
  HostConfig: z.object({
    NetworkMode: z.string(),
    ReadonlyRootfs: z.boolean(),
    CapDrop: z.array(z.string()).nullable(),
    CapAdd: z.array(z.string()).nullable(),
    Privileged: z.boolean(),
    SecurityOpt: z.array(z.string()).nullable(),
    PidsLimit: z.number().nullable(),
    Memory: z.number(),
    MemorySwap: z.number(),
    NanoCpus: z.number(),
    Tmpfs: z.record(z.string(), z.string()).nullable().optional(),
    Devices: z.array(z.unknown()).nullable(),
    PidMode: z.string(),
    IpcMode: z.string(),
    UTSMode: z.string(),
    UsernsMode: z.string(),
    CgroupnsMode: z.string().optional(),
  }),
  Mounts: z.array(z.object({ Type: z.string(), Source: z.string(), Destination: z.string(), RW: z.boolean() })),
  NetworkSettings: z.object({ Networks: z.record(z.string(), z.unknown()).nullable() }),
});
type Inspect = z.infer<typeof Inspect>;

/** Mount points docker itself creates in every container, with the filesystem expected there. */
const DOCKER_MOUNTS: Record<string, string[] | null> = {
  '/': null,
  '/proc': ['proc'],
  '/dev': ['tmpfs'],
  '/dev/pts': ['devpts'],
  '/dev/mqueue': ['mqueue'],
  '/dev/shm': ['tmpfs'],
  '/sys': ['sysfs'],
  '/sys/fs/cgroup': ['cgroup2', 'cgroup'],
  '/tmp': ['tmpfs'],
};
const DOCKER_FILES = ['/etc/hostname', '/etc/hosts', '/etc/resolv.conf'];

interface Ctx {
  e: IsolationExpectations;
  info: z.infer<typeof Info> | null;
  c: Inspect | null;
  p: ProbeResult | null;
  canaryHits: number;
}

type Problems = string[];

const key = (t: { host: string; port: number }) => `${t.host.includes(':') ? `[${t.host}]` : t.host}:${t.port}`;

/** Every target must have at least one result, and every result for it must be acceptable. */
function requireResults<T extends { result: string }>(
  entries: T[],
  match: (entry: T) => boolean,
  ok: (result: string) => boolean,
  label: string,
): Problems {
  const found = entries.filter(match);
  if (found.length === 0) return [`${label}: not probed`];
  const bad = found.filter((f) => !ok(f.result));
  return bad.length ? [`${label}: ${bad.map((b) => b.result).join(', ')}`] : [];
}

function configOrMissing(ctx: Ctx, check: (c: Inspect) => Problems): Problems {
  return ctx.c ? check(ctx.c) : ['docker inspect unreadable'];
}

function probeOrMissing(ctx: Ctx, check: (p: ProbeResult) => Problems): Problems {
  return ctx.p ? check(ctx.p) : ['no probe output from inside the container'];
}

const names = (env: string[]) => env.map((v) => v.split('=')[0] ?? '');

type CheckFn = (ctx: Ctx) => { problems: Problems; ok: string };

const CHECKS: Record<CheckId, CheckFn> = {
  rootless: ({ info }) => ({
    problems: !info
      ? ['docker info unreadable']
      : info.SecurityOptions.includes('name=rootless')
        ? []
        : ['Docker daemon is rootful (no name=rootless in docker info): container root is host root'],
    ok: 'Docker daemon is rootless',
  }),

  network: (ctx) => {
    const outbound = outboundTargets(ctx.e);
    return {
      problems: [
        ...configOrMissing(ctx, (c) => [
          ...(c.HostConfig.NetworkMode === 'none' ? [] : [`network mode is ${c.HostConfig.NetworkMode}`]),
          ...Object.keys(c.NetworkSettings.Networks ?? {})
            .filter((n) => n !== 'none')
            .map((n) => `attached to network ${n}`),
        ]),
        ...probeOrMissing(ctx, (p) => [
          ...(p.interfaces === null ? ['interfaces unreadable'] : p.interfaces.join() === 'lo' ? [] : [`interfaces: ${p.interfaces.join(', ')}`]),
          ...(p.ipv4Routes === null ? ['IPv4 routes unreadable'] : p.ipv4Routes.length ? [`IPv4 routes via ${p.ipv4Routes.join(', ')}`] : []),
          ...(p.ipv6Routes === null
            ? ['IPv6 routes unreadable']
            : p.ipv6Routes.some((i) => i !== 'lo')
              ? [`IPv6 routes via ${p.ipv6Routes.filter((i) => i !== 'lo').join(', ')}`]
              : []),
          ...outbound.flatMap((t) =>
            requireResults(p.connects, (c) => c.host === t.host && c.port === t.port, (r) => NO_ROUTE.has(r), `connect ${key(t)}`),
          ),
        ]),
      ],
      ok: `no network: only lo, no routes, ${outbound.length} outside addresses unreachable`,
    };
  },

  readOnlyRootfs: (ctx) => ({
    problems: [
      ...configOrMissing(ctx, (c) => [
        ...(c.HostConfig.ReadonlyRootfs ? [] : ['root filesystem is writable (no --read-only)']),
        ...Object.entries(c.HostConfig.Tmpfs ?? {}).flatMap(([path, opts]) => {
          if (path !== '/tmp') return [`extra tmpfs at ${path}`];
          const missing = ['nosuid', 'nodev', 'noexec'].filter((o) => !opts.split(',').includes(o));
          return missing.length ? [`/tmp tmpfs lacks ${missing.join(', ')}`] : [];
        }),
      ]),
      ...probeOrMissing(ctx, (p) => {
        if (!p.mounts) return ['mounts unreadable'];
        const root = p.mounts.filter((m) => m.mountPoint === '/');
        return [
          ...(root.length === 1 && root[0]?.options.split(',').includes('ro') ? [] : ['/ is not mounted read-only']),
          // EROFS proves the filesystem refused. EACCES only means this user lacks permission,
          // which is also what a writable root looks like to a non-root user.
          ...probeTargets(ctx.e).writeTargets.flatMap((dir) =>
            requireResults(p.writes, (w) => w.path === dir, (r) => r === 'EROFS', `write in ${dir}`),
          ),
        ];
      }),
    ],
    ok: 'root filesystem is read-only (writes fail with EROFS); /tmp is a noexec tmpfs',
  }),

  onlyGuardianSocket: (ctx) => {
    const guarded = absentPaths({ ...ctx.e, dbPath: undefined });
    return {
      problems: [
        ...configOrMissing(ctx, (c) => {
          const socket = c.Mounts.filter(
            (m) => m.Type === 'bind' && m.Source === ctx.e.socketPath && m.Destination === SANDBOX_SOCKET && !m.RW,
          );
          return [
            ...(socket.length === 1 ? [] : ['guardian socket is not mounted read-only bind exactly once']),
            ...c.Mounts.filter((m) => !socket.includes(m)).map((m) => `extra mount ${m.Source || m.Type} -> ${m.Destination}`),
            ...(c.HostConfig.Devices?.length ? [`${c.HostConfig.Devices.length} device(s) passed through`] : []),
          ];
        }),
        ...probeOrMissing(ctx, (p) => [
          ...guarded.flatMap((path) => requireResults(p.paths, (x) => x.path === path, (r) => r === 'ENOENT', path)),
          ...(p.mounts ? unexpectedMounts(p.mounts, ctx) : ['mounts unreadable']),
        ]),
      ],
      ok: `only the guardian socket is mounted; no docker socket, home dir or SSH agent inside`,
    };
  },

  noHostEnv: (ctx) => {
    const imageNames = new Set(names(ctx.e.imageEnv));
    const allowed = new Set([...imageNames, 'HOSTNAME', 'HOME']);
    return {
      problems: [
        ...configOrMissing(ctx, (c) => {
          const injected = (c.Config.Env ?? []).filter((v) => !ctx.e.imageEnv.includes(v));
          return injected.length ? [`variables set at run time: ${names(injected).join(', ')}`] : [];
        }),
        ...probeOrMissing(ctx, (p) => {
          const extra = p.env.filter((n) => !allowed.has(n));
          return extra.length ? [`unexpected variables inside: ${extra.join(', ')}`] : [];
        }),
      ],
      ok: 'no environment passed from the host',
    };
  },

  nonRoot: (ctx) => ({
    problems: [
      ...configOrMissing(ctx, (c) => {
        const m = /^([0-9]+)(?::([0-9]+))?$/.exec(c.Config.User);
        if (!m) return [c.Config.User ? `user ${JSON.stringify(c.Config.User)} is not numeric` : 'no user set'];
        return Number(m[1]) === 0 || (m[2] !== undefined && Number(m[2]) === 0) ? [`user ${c.Config.User} is root`] : [];
      }),
      ...probeOrMissing(ctx, (p) => [
        ...(p.uid === 0 ? ['runs as uid 0'] : []),
        ...(p.gid === 0 ? ['runs as gid 0'] : []),
        ...(p.groups.includes(0) ? ['member of group 0'] : []),
      ]),
    ],
    ok: `runs as non-root ${ctx.p ? `${ctx.p.uid}:${ctx.p.gid}` : ''}`.trim(),
  }),

  capabilities: (ctx) => ({
    problems: [
      ...configOrMissing(ctx, (c) => [
        ...((c.HostConfig.CapDrop ?? []).some((x) => x.toUpperCase() === 'ALL') ? [] : ['capabilities not dropped (no --cap-drop ALL)']),
        ...(c.HostConfig.CapAdd?.length ? [`capabilities added: ${c.HostConfig.CapAdd.join(', ')}`] : []),
        ...(c.HostConfig.Privileged ? ['privileged'] : []),
      ]),
      ...probeOrMissing(ctx, (p) =>
        ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'].flatMap((cap) => {
          const v = p.status[cap];
          return v === undefined ? [`${cap} unreadable`] : ZERO_CAPS.test(v) ? [] : [`${cap}=${v}`];
        }),
      ),
    ],
    ok: 'all capability sets are empty',
  }),

  noNewPrivileges: (ctx) => ({
    problems: [
      ...configOrMissing(ctx, (c) => {
        const opts = (c.HostConfig.SecurityOpt ?? []).filter((o) => /^no-new-privileges([:=](true|false))?$/.test(o));
        const last = opts.at(-1);
        return last && !/false$/.test(last) ? [] : ['no-new-privileges not set'];
      }),
      ...probeOrMissing(ctx, (p) => (p.status.NoNewPrivs === '1' ? [] : [`NoNewPrivs=${p.status.NoNewPrivs ?? 'unreadable'}`])),
    ],
    ok: 'no-new-privileges is set',
  }),

  seccomp: (ctx) => ({
    problems: [
      ...configOrMissing(ctx, (c) => [
        ...((c.HostConfig.SecurityOpt ?? []).some((o) => /^seccomp[:=]unconfined$/.test(o)) ? ['seccomp=unconfined'] : []),
        ...(c.HostConfig.Privileged ? ['privileged disables seccomp'] : []),
      ]),
      ...probeOrMissing(ctx, (p) => (p.status.Seccomp === '2' ? [] : [`Seccomp=${p.status.Seccomp ?? 'unreadable'}`])),
    ],
    ok: 'seccomp filter active',
  }),

  namespaces: (ctx) => ({
    problems: [
      ...configOrMissing(ctx, (c) => {
        const modes = {
          pid: c.HostConfig.PidMode,
          ipc: c.HostConfig.IpcMode,
          uts: c.HostConfig.UTSMode,
          userns: c.HostConfig.UsernsMode,
          cgroupns: c.HostConfig.CgroupnsMode,
        };
        return Object.entries(modes).flatMap(([ns, mode]) =>
          mode === undefined ? [`${ns} namespace mode unknown`] : mode === 'host' || mode.startsWith('container:') ? [`${ns} namespace shared: ${mode}`] : [],
        );
      }),
      ...probeOrMissing(ctx, (p) =>
        p.pid1 !== null && p.pid1.join('\0') === ctx.e.idleCommand.join('\0') ? [] : ['PID 1 is not the sandbox process (host PID namespace?)'],
      ),
    ],
    ok: 'own pid, ipc, uts, user and cgroup namespaces',
  }),

  resourceLimits: (ctx) => {
    const bounded = (v: string, max: number) => /^[0-9]+$/.test(v) && Number(v) > 0 && Number(v) <= max;
    return {
      problems: [
        ...configOrMissing(ctx, (c) => {
          const h = c.HostConfig;
          return [
            ...(h.PidsLimit !== null && h.PidsLimit > 0 && h.PidsLimit <= MAX_PIDS ? [] : [`pids limit ${h.PidsLimit ?? 'unset'}`]),
            ...(h.Memory > 0 && h.Memory <= MAX_MEMORY ? [] : [`memory limit ${h.Memory || 'unset'}`]),
            ...(h.MemorySwap === h.Memory ? [] : [`swap allowed (memory-swap ${h.MemorySwap})`]),
            ...(h.NanoCpus > 0 && h.NanoCpus <= MAX_NANO_CPUS ? [] : [`cpu limit ${h.NanoCpus || 'unset'}`]),
          ];
        }),
        ...probeOrMissing(ctx, (p) => [
          ...(bounded(p.pidsMax, MAX_PIDS) ? [] : [`pids.max=${p.pidsMax}`]),
          ...(bounded(p.memoryMax, MAX_MEMORY) ? [] : [`memory.max=${p.memoryMax}`]),
        ]),
      ],
      ok: `pids <= ${MAX_PIDS}, memory <= 512m with no swap, cpus <= 1`,
    };
  },

  hostServicesUnreachable: (ctx) => {
    const { e } = ctx;
    return {
      problems: [
        ...(ctx.canaryHits > 0 ? [`host loopback canary received ${ctx.canaryHits} connection(s)`] : []),
        ...probeOrMissing(ctx, (p) => [
          ...loopbackTargets(e).flatMap((t) =>
            requireResults(p.connects, (c) => c.host === t.host && c.port === t.port, (r) => r !== 'connected', `connect ${key(t)}`),
          ),
          ...(e.dbPath ? requireResults(p.paths, (x) => x.path === e.dbPath, (r) => r === 'ENOENT', `guardian DB ${e.dbPath}`) : []),
        ]),
      ],
      ok: [
        `host loopback unreachable (canary port ${e.canaryPort}${e.adminPort === undefined ? ', no admin UI port given' : `, admin UI port ${e.adminPort}`})`,
        e.dbPath ? 'guardian DB not visible' : 'no guardian database configured',
      ].join('; '),
    };
  },

  guardianSocket: (ctx) => ({
    problems: probeOrMissing(ctx, (p) =>
      p.socket.connected && p.socket.error === null ? [] : [`cannot connect to ${SANDBOX_SOCKET}: ${p.socket.error ?? 'unknown'}`],
    ),
    ok: `guardian reachable at ${SANDBOX_SOCKET}`,
  }),
};

function unexpectedMounts(mounts: NonNullable<ProbeResult['mounts']>, ctx: Ctx): Problems {
  const problems: Problems = [];
  let socketMounts = 0;
  for (const m of mounts) {
    const where = `${m.mountPoint} (${m.fsType} ${m.root})`;
    if (m.mountPoint in DOCKER_MOUNTS) {
      const types = DOCKER_MOUNTS[m.mountPoint];
      if (types && !types.includes(m.fsType)) problems.push(`unexpected mount ${where}`);
    } else if (DOCKER_FILES.includes(m.mountPoint)) {
      // Docker writes these per container under .../containers/<id>/.
      const file = m.mountPoint.slice('/etc/'.length);
      if (!ctx.c || !m.root.endsWith(`/containers/${ctx.c.Id}/${file}`)) problems.push(`unexpected mount ${where}`);
    } else if (m.mountPoint === SANDBOX_SOCKET) {
      if (m.root.endsWith(ctx.e.socketPath)) socketMounts++;
      else problems.push(`unexpected mount ${where}`);
    } else if (m.mountPoint.startsWith('/proc/') || m.mountPoint.startsWith('/sys/')) {
      // Docker masks these with read-only proc/sysfs rebinds or empty tmpfs (or its /dev/null).
      const masked = m.fsType === 'proc' || m.fsType === 'sysfs' || (m.fsType === 'tmpfs' && (m.root === '/' || m.root === '/null'));
      if (!masked) problems.push(`unexpected mount ${where}`);
    } else {
      problems.push(`unexpected mount ${where}`);
    }
  }
  if (socketMounts !== 1) problems.push(`guardian socket mounted ${socketMounts} times inside`);
  return problems;
}

function unwrapInspect(inspect: unknown): unknown {
  return Array.isArray(inspect) && inspect.length === 1 ? inspect[0] : inspect;
}

export function evaluateIsolation(facts: IsolationFacts): IsolationResult {
  const info = Info.safeParse(facts.info);
  const inspect = Inspect.safeParse(unwrapInspect(facts.inspect));
  const ctx: Ctx = {
    e: facts.expectations,
    info: info.success ? info.data : null,
    c: inspect.success ? inspect.data : null,
    p: facts.probe,
    canaryHits: facts.canaryHits,
  };
  const checks = CHECK_IDS.map((id): IsolationCheck => {
    const { problems, ok } = CHECKS[id](ctx);
    return problems.length ? { id, pass: false, detail: problems.join('; ') } : { id, pass: true, detail: ok };
  });
  const contain = checks.length === CHECK_IDS.length && checks.every((c) => c.pass);
  return { mode: contain ? 'contain' : 'guard', imageId: ctx.c?.Image ?? null, checks };
}
