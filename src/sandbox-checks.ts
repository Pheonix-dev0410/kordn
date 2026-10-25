import { z } from 'zod';
import { ALLOWED_RUNTIMES, SANDBOX_SOCKET, SECURITY_OPTS, TMP_TMPFS_OPTIONS } from './sandbox-contract.js';
import type { ProbeParams, ProbeResult } from './sandbox-probe.js';

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
  /** The launcher's own /proc/self/ns/<kind> links. The sandbox must share none of them. */
  hostNamespaces: Record<string, string>;
  /** Host paths of Docker daemon sockets (hostDockerSocketPaths). */
  dockerSockets: string[];
}

/** Namespaces the sandbox must have its own of. */
export const NAMESPACE_KINDS = ['cgroup', 'ipc', 'mnt', 'net', 'pid', 'user', 'uts'] as const;

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
    ...e.dockerSockets,
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
  'hardening',
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
const DAEMON_SECCOMP = 'name=seccomp,profile=builtin';

/** Docker's default masked and read-only paths (moby oci defaults), minus the per-CPU ones. */
const DEFAULT_MASKED_PATHS = [
  '/proc/acpi',
  '/proc/asound',
  '/proc/interrupts',
  '/proc/kcore',
  '/proc/keys',
  '/proc/latency_stats',
  '/proc/sched_debug',
  '/proc/scsi',
  '/proc/timer_list',
  '/proc/timer_stats',
  '/sys/devices/virtual/powercap',
  '/sys/firmware',
];
const DEFAULT_READONLY_PATHS = ['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'];

/**
 * Fixed inode numbers of the kernel's initial namespaces (include/linux/proc_ns.h). Comparing
 * against these as well as the launcher's own namespaces still works when the launcher itself
 * runs inside separate namespaces (a sandboxed shell).
 */
const INITIAL_NAMESPACE_INODES: Record<string, number> = {
  ipc: 0xefffffff,
  uts: 0xeffffffe,
  user: 0xeffffffd,
  pid: 0xeffffffc,
  cgroup: 0xeffffffb,
  net: 0xeffffff9,
  mnt: 0xeffffff8,
};

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
    Runtime: z.string(),
    MaskedPaths: z.array(z.string()).nullable(),
    ReadonlyPaths: z.array(z.string()).nullable(),
    PidsLimit: z.number().nullable(),
    Memory: z.number(),
    MemorySwap: z.number(),
    NanoCpus: z.number(),
    Tmpfs: z.record(z.string(), z.string()).nullable().optional(),
    Devices: z.array(z.unknown()).nullable(),
    DeviceCgroupRules: z.array(z.unknown()).nullable(),
    DeviceRequests: z.array(z.unknown()).nullable(),
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
type Mount = NonNullable<ProbeResult['mounts']>[number];

/** Mount points docker itself creates in every container, with the filesystem expected there. */
const DOCKER_MOUNTS: Record<string, string[] | null> = {
  '/': null,
  '/proc': ['proc'],
  '/dev': ['tmpfs'],
  '/dev/pts': ['devpts'],
  '/dev/mqueue': ['mqueue'],
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
const options = (m: Mount | undefined) => (m ? m.options.split(',') : []);
const mountAt = (p: ProbeResult, point: string) => p.mounts?.filter((m) => m.mountPoint === point) ?? [];
const names = (env: string[]) => env.map((v) => v.split('=')[0] ?? '');
const isShared = (mode: string) => mode === 'host' || mode.startsWith('container:');
const sameList = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

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

function interfaceProblems(p: ProbeResult): Problems {
  if (p.interfaces === null) return ['interfaces unreadable'];
  return p.interfaces.join() === 'lo' ? [] : [`interfaces: ${p.interfaces.join(', ')}`];
}

function routeProblems(p: ProbeResult): Problems {
  const problems: Problems = [];
  if (p.ipv4Routes === null) problems.push('IPv4 routes unreadable');
  else if (p.ipv4Routes.length > 0) problems.push(`IPv4 routes via ${p.ipv4Routes.join(', ')}`);
  if (p.ipv6Routes === null) problems.push('IPv6 routes unreadable');
  else {
    const offLoopback = p.ipv6Routes.filter((i) => i !== 'lo');
    if (offLoopback.length > 0) problems.push(`IPv6 routes via ${offLoopback.join(', ')}`);
  }
  return problems;
}

/** The namespace link must be readable, of the right kind, and neither the launcher's nor the host's initial one. */
function namespaceProblems(kind: string, link: string | undefined, launcher: string | undefined): Problems {
  const m = link === undefined ? null : /^(\w+):\[(\d+)\]$/.exec(link);
  if (!m || m[1] !== kind) return [`${kind} namespace unreadable (${link ?? 'missing'})`];
  if (launcher === undefined || !/^\w+:\[\d+\]$/.test(launcher)) return [`${kind} namespace of the launcher unknown`];
  if (link === launcher) return [`shares the launcher's ${kind} namespace`];
  if (Number(m[2]) === INITIAL_NAMESPACE_INODES[kind]) return [`in the host's initial ${kind} namespace`];
  return [];
}

type CheckFn = (ctx: Ctx) => { problems: Problems; ok: string };

const CHECKS: Record<CheckId, CheckFn> = {
  rootless: ({ info }) => {
    let problems: Problems = [];
    if (!info) problems = ['docker info unreadable'];
    else if (!info.SecurityOptions.includes('name=rootless')) {
      problems = ['Docker daemon is rootful (no name=rootless in docker info): container root is host root'];
    }
    return { problems, ok: 'Docker daemon is rootless' };
  },

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
          ...interfaceProblems(p),
          ...routeProblems(p),
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
      ...configOrMissing(ctx, (c) => {
        const tmpfs = c.HostConfig.Tmpfs ?? {};
        const problems: Problems = c.HostConfig.ReadonlyRootfs ? [] : ['root filesystem is writable (no --read-only)'];
        for (const path of Object.keys(tmpfs).filter((p) => p !== '/tmp')) problems.push(`extra tmpfs at ${path}`);
        // Exact match: docker applies later options, so "noexec,...,exec" would pass a token test.
        if (tmpfs['/tmp'] !== TMP_TMPFS_OPTIONS) problems.push(`/tmp tmpfs options are ${JSON.stringify(tmpfs['/tmp'] ?? null)}, not ${TMP_TMPFS_OPTIONS}`);
        return problems;
      }),
      ...probeOrMissing(ctx, (p) => {
        if (!p.mounts) return ['mounts unreadable'];
        const root = mountAt(p, '/');
        const tmp = mountAt(p, '/tmp');
        const tmpMissing = ['nosuid', 'nodev', 'noexec'].filter((o) => !options(tmp[0]).includes(o));
        return [
          ...(root.length === 1 && options(root[0]).includes('ro') ? [] : ['/ is not mounted read-only']),
          ...(tmp.length === 1 && tmpMissing.length === 0 ? [] : [`/tmp is not mounted nosuid,nodev,noexec (${tmp[0]?.options ?? 'missing'})`]),
          // EROFS proves the filesystem refused. EACCES only means this user lacks permission,
          // which is also what a writable root looks like to a non-root user.
          ...probeTargets(ctx.e).writeTargets.flatMap((dir) =>
            requireResults(p.writes, (w) => w.path === dir, (r) => r === 'EROFS', `write in ${dir}`),
          ),
        ];
      }),
    ],
    ok: 'root filesystem is read-only (writes fail with EROFS); /tmp is a nosuid,nodev,noexec tmpfs',
  }),

  onlyGuardianSocket: (ctx) => {
    const guarded = absentPaths({ ...ctx.e, dbPath: undefined });
    return {
      problems: [
        ...configOrMissing(ctx, (c) => {
          const socket = c.Mounts.filter(
            (m) => m.Type === 'bind' && m.Source === ctx.e.socketPath && m.Destination === SANDBOX_SOCKET && !m.RW,
          );
          const h = c.HostConfig;
          return [
            ...(socket.length === 1 ? [] : ['guardian socket is not mounted read-only bind exactly once']),
            ...c.Mounts.filter((m) => !socket.includes(m)).map((m) => `extra mount ${m.Source || m.Type} -> ${m.Destination}`),
            ...(h.Devices?.length ? [`${h.Devices.length} device(s) passed through`] : []),
            ...(h.DeviceCgroupRules?.length ? [`${h.DeviceCgroupRules.length} device cgroup rule(s)`] : []),
            ...(h.DeviceRequests?.length ? [`${h.DeviceRequests.length} device request(s)`] : []),
          ];
        }),
        ...probeOrMissing(ctx, (p) => [
          ...guarded.flatMap((path) => requireResults(p.paths, (x) => x.path === path, (r) => r === 'ENOENT', path)),
          ...(p.mounts ? unexpectedMounts(p.mounts, ctx) : ['mounts unreadable']),
        ]),
      ],
      ok: 'only the guardian socket is mounted; no docker socket, home dir, SSH agent or devices inside',
    };
  },

  noHostEnv: (ctx) => {
    const allowed = new Set([...names(ctx.e.imageEnv), 'HOSTNAME', 'HOME']);
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
        const user = c.Config.User;
        const m = /^([0-9]+)(?::([0-9]+))?$/.exec(user);
        if (!m) return [user ? `user ${JSON.stringify(user)} is not numeric` : 'no user set'];
        const rootUid = Number(m[1]) === 0;
        const rootGid = m[2] !== undefined && Number(m[2]) === 0;
        return rootUid || rootGid ? [`user ${user} is root`] : [];
      }),
      ...probeOrMissing(ctx, (p) => [
        ...(p.uid === 0 ? ['runs as uid 0'] : []),
        ...(p.gid === 0 ? ['runs as gid 0'] : []),
        ...(p.groups.includes(0) ? ['member of group 0'] : []),
      ]),
    ],
    ok: ctx.p ? `runs as non-root ${ctx.p.uid}:${ctx.p.gid}` : 'runs as non-root',
  }),

  capabilities: (ctx) => ({
    problems: [
      ...configOrMissing(ctx, (c) => {
        const h = c.HostConfig;
        const dropsAll = (h.CapDrop ?? []).some((x) => x.toUpperCase() === 'ALL');
        return [
          ...(dropsAll ? [] : ['capabilities not dropped (no --cap-drop ALL)']),
          ...(h.CapAdd?.length ? [`capabilities added: ${h.CapAdd.join(', ')}`] : []),
          ...(h.Privileged ? ['privileged'] : []),
        ];
      }),
      ...probeOrMissing(ctx, (p) =>
        ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'].flatMap((cap) => {
          const v = p.status[cap];
          if (v === undefined) return [`${cap} unreadable`];
          return ZERO_CAPS.test(v) ? [] : [`${cap}=${v}`];
        }),
      ),
    ],
    ok: 'all capability sets are empty',
  }),

  noNewPrivileges: (ctx) => ({
    problems: [
      ...configOrMissing(ctx, (c) => ((c.HostConfig.SecurityOpt ?? []).includes('no-new-privileges') ? [] : ['no-new-privileges not set'])),
      ...probeOrMissing(ctx, (p) => (p.status.NoNewPrivs === '1' ? [] : [`NoNewPrivs=${p.status.NoNewPrivs ?? 'unreadable'}`])),
    ],
    ok: 'no-new-privileges is set',
  }),

  seccomp: (ctx) => ({
    problems: [
      // A daemon-wide custom profile can be as permissive as allow-all: only Docker's own counts.
      ...(ctx.info?.SecurityOptions.includes(DAEMON_SECCOMP) ? [] : [`daemon seccomp profile is not Docker's builtin (${DAEMON_SECCOMP})`]),
      ...configOrMissing(ctx, (c) => [
        ...(c.HostConfig.SecurityOpt ?? []).filter((o) => /^seccomp[:=]/.test(o)).map((o) => `container seccomp override ${o.slice(0, 40)}`),
        ...(c.HostConfig.Privileged ? ['privileged disables seccomp'] : []),
      ]),
      ...probeOrMissing(ctx, (p) => (p.status.Seccomp === '2' ? [] : [`Seccomp=${p.status.Seccomp ?? 'unreadable'}`])),
    ],
    ok: "Docker's builtin seccomp profile is active",
  }),

  hardening: (ctx) => ({
    problems: [
      ...configOrMissing(ctx, (c) => {
        const h = c.HostConfig;
        const securityOpt = h.SecurityOpt ?? [];
        const masked = new Set(h.MaskedPaths ?? []);
        const readonly = new Set(h.ReadonlyPaths ?? []);
        const unmasked = DEFAULT_MASKED_PATHS.filter((x) => !masked.has(x));
        const writable = DEFAULT_READONLY_PATHS.filter((x) => !readonly.has(x));
        return [
          // Deny by default: an LSM opt-out, systempaths=unconfined or a profile all land here.
          ...(sameList(securityOpt, SECURITY_OPTS) ? [] : [`security options are ${JSON.stringify(securityOpt)}, not ${JSON.stringify(SECURITY_OPTS)}`]),
          ...(unmasked.length ? [`not masked: ${unmasked.join(', ')}`] : []),
          ...(writable.length ? [`not read-only: ${writable.join(', ')}`] : []),
          ...(ALLOWED_RUNTIMES.includes(h.Runtime) ? [] : [`runtime ${h.Runtime} is not one of ${ALLOWED_RUNTIMES.join(', ')}`]),
        ];
      }),
      ...probeOrMissing(ctx, (p) => {
        if (!p.mounts) return ['mounts unreadable'];
        const sys = mountAt(p, '/proc/sys');
        return [
          ...(sys.length > 0 && sys.every((m) => options(m).includes('ro')) ? [] : ['/proc/sys is not mounted read-only']),
          ...(mountAt(p, '/proc/kcore').length > 0 ? [] : ['/proc/kcore is not masked']),
        ];
      }),
    ],
    ok: `only ${SECURITY_OPTS.join(', ')}; Docker's /proc and /sys masks in place; runtime ${ctx.c?.HostConfig.Runtime ?? ''}`.trim(),
  }),

  namespaces: (ctx) => ({
    problems: [
      ...configOrMissing(ctx, (c) => {
        const h = c.HostConfig;
        const shared = Object.entries({ pid: h.PidMode, uts: h.UTSMode, userns: h.UsernsMode, cgroupns: h.CgroupnsMode }).flatMap(([ns, mode]) => {
          if (mode === undefined) return [`${ns} namespace mode unknown`];
          return isShared(mode) ? [`${ns} namespace shared: ${mode}`] : [];
        });
        return [...shared, ...(h.IpcMode === 'none' ? [] : [`ipc mode is ${h.IpcMode}, not none`])];
      }),
      ...probeOrMissing(ctx, (p) => [
        ...(p.pid1 !== null && sameList(p.pid1, ctx.e.idleCommand) ? [] : ['PID 1 is not the sandbox process (host PID namespace?)']),
        ...(mountAt(p, '/dev/shm').length === 0 ? [] : ['/dev/shm is mounted (shared memory available)']),
        ...NAMESPACE_KINDS.flatMap((kind) => namespaceProblems(kind, p.namespaces[kind], ctx.e.hostNamespaces[kind])),
      ]),
    ],
    ok: `own ${NAMESPACE_KINDS.join(', ')} namespaces; no IPC (no /dev/shm)`,
  }),

  resourceLimits: (ctx) => {
    const bounded = (v: string, max: number) => /^[0-9]+$/.test(v) && Number(v) > 0 && Number(v) <= max;
    return {
      problems: [
        ...configOrMissing(ctx, (c) => {
          const h = c.HostConfig;
          const pidsOk = h.PidsLimit !== null && h.PidsLimit > 0 && h.PidsLimit <= MAX_PIDS;
          const memoryOk = h.Memory > 0 && h.Memory <= MAX_MEMORY;
          const cpusOk = h.NanoCpus > 0 && h.NanoCpus <= MAX_NANO_CPUS;
          return [
            ...(pidsOk ? [] : [`pids limit ${h.PidsLimit ?? 'unset'}`]),
            ...(memoryOk ? [] : [`memory limit ${h.Memory || 'unset'}`]),
            ...(h.MemorySwap === h.Memory ? [] : [`swap allowed (memory-swap ${h.MemorySwap})`]),
            ...(cpusOk ? [] : [`cpu limit ${h.NanoCpus || 'unset'}`]),
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
    const admin = e.adminPort === undefined ? 'no admin UI port given' : `admin UI port ${e.adminPort}`;
    const db = e.dbPath ? 'guardian DB not visible' : 'no guardian database configured';
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
      ok: `host loopback unreachable (canary port ${e.canaryPort}, ${admin}); ${db}`,
    };
  },

  guardianSocket: (ctx) => ({
    problems: probeOrMissing(ctx, (p) =>
      p.socket.connected && p.socket.error === null ? [] : [`cannot connect to ${SANDBOX_SOCKET}: ${p.socket.error ?? 'unknown'}`],
    ),
    ok: `guardian reachable at ${SANDBOX_SOCKET}`,
  }),
};

/** Is this mount one Docker makes in every container (or the guardian socket)? */
function expectedMount(m: Mount, ctx: Ctx): boolean {
  if (Object.hasOwn(DOCKER_MOUNTS, m.mountPoint)) {
    const types = DOCKER_MOUNTS[m.mountPoint];
    return !types || types.includes(m.fsType);
  }
  if (DOCKER_FILES.includes(m.mountPoint)) {
    // Docker writes these per container under .../containers/<id>/.
    const file = m.mountPoint.slice('/etc/'.length);
    return ctx.c !== null && m.root.endsWith(`/containers/${ctx.c.Id}/${file}`);
  }
  if (m.mountPoint.startsWith('/proc/') || m.mountPoint.startsWith('/sys/')) {
    // Docker masks these with read-only proc/sysfs rebinds or empty tmpfs (or its /dev/null).
    return m.fsType === 'proc' || m.fsType === 'sysfs' || (m.fsType === 'tmpfs' && (m.root === '/' || m.root === '/null'));
  }
  return false;
}

function unexpectedMounts(mounts: Mount[], ctx: Ctx): Problems {
  const problems: Problems = [];
  let socketMounts = 0;
  for (const m of mounts) {
    if (m.mountPoint === SANDBOX_SOCKET && m.root.endsWith(ctx.e.socketPath)) socketMounts++;
    else if (!expectedMount(m, ctx)) problems.push(`unexpected mount ${m.mountPoint} (${m.fsType} ${m.root})`);
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
