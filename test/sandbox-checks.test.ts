import { describe, expect, it } from 'vitest';
import {
  CHECK_IDS,
  type CheckId,
  evaluateIsolation,
  type IsolationExpectations,
  type IsolationFacts,
  probeTargets,
} from '../src/sandbox-checks.js';
import type { ProbeResult } from '../src/sandbox-probe.js';
import fixture from './fixtures/contain/hardened.json' with { type: 'json' };

// fixtures/contain/hardened.json was captured from a real container started with
// hardenedRunFlags on a rootful Docker host (host specifics replaced). Each case below
// mutates it into one unsafe setting and asserts exactly which checks fail.

const expectations: IsolationExpectations = {
  socketPath: '/tmp/kordn-test-x/guardian.sock',
  idleCommand: ['/nodejs/bin/node', '-e', 'setInterval(() => {}, 1 << 30)'],
  hostHome: '/home/alice',
  sshAuthSock: '/run/user/1000/ssh-agent.sock',
  canaryPort: 41000,
  adminPort: 3333,
  dbPath: '/home/alice/.kordn/kordn.sqlite',
  hostAddresses: ['192.168.1.20'],
  imageEnv: ['PATH=/usr/bin', 'NODE_ENV=production'],
  hostNamespaces: { net: 'net:[1]' },
  dockerSockets: ['/var/run/docker.sock', '/run/docker.sock', '/run/user/1000/docker.sock'],
};

describe('probeTargets', () => {
  const params = probeTargets(expectations);

  it('only connects to the guardian socket, never sends a call', () => {
    expect(params.socketPath).toBe('/run/kordn.sock');
    expect(params.call).toBeUndefined();
  });

  it('tries the internet, the docker gateway, cloud metadata and every host address', () => {
    expect(params.connect).toEqual(
      expect.arrayContaining([
        { host: '1.1.1.1', port: 443 },
        { host: '2606:4700:4700::1111', port: 443 },
        { host: '172.17.0.1', port: 80 },
        { host: '169.254.169.254', port: 80 },
        { host: '192.168.1.20', port: 80 },
      ]),
    );
  });

  it("tries the canary and the admin UI on the host's loopback addresses", () => {
    expect(params.connect).toEqual(
      expect.arrayContaining([
        { host: '127.0.0.1', port: 41000 },
        { host: '::1', port: 41000 },
        { host: '127.0.0.1', port: 3333 },
        { host: '::1', port: 3333 },
      ]),
    );
  });

  it('looks for every docker socket, the home dir, the SSH agent and the guardian DB', () => {
    expect(params.absentPaths).toEqual(
      expect.arrayContaining([
        '/var/run/docker.sock',
        '/run/docker.sock',
        '/run/user/1000/docker.sock',
        '/home/alice',
        '/run/user/1000/ssh-agent.sock',
        '/home/alice/.kordn/kordn.sqlite',
      ]),
    );
  });

  it('tries writing to root-owned directories of the image', () => {
    expect(params.writeTargets).toEqual(['/', '/etc', '/usr', '/var', '/app', '/run']);
  });
});

// ---- evaluateIsolation ----

type Facts = IsolationFacts & {
  inspect: typeof fixture.inspect;
  probe: ProbeResult;
  info: { SecurityOptions: string[] };
};

/** The captured container as a rootless daemon would run it: the daemon reports rootless and
 * the container gets its own user namespace. Every check passes. */
function safe(): Facts {
  const f = structuredClone(fixture) as unknown as Facts;
  f.info.SecurityOptions.push('name=rootless');
  f.probe.namespaces.user = 'user:[4026599999]';
  return f;
}

function failing(f: IsolationFacts): CheckId[] {
  return evaluateIsolation(f)
    .checks.filter((c) => !c.pass)
    .map((c) => c.id);
}

const setConnect = (f: Facts, pred: (c: { host: string }) => boolean, result: string) => {
  for (const c of f.probe.connects) if (pred(c)) c.result = result;
};
const isLoopback = (c: { host: string }) => c.host === '127.0.0.1' || c.host === '::1';
const setPath = (f: Facts, path: string, result: string) => {
  const entry = f.probe.paths.find((p) => p.path === path);
  if (entry) entry.result = result;
  else f.probe.paths.push({ path, result });
};
const addMount = (f: Facts, mountPoint: string, root: string, fsType: string) =>
  f.probe.mounts?.push({ mountPoint, root, fsType, source: '/dev/x', options: 'rw,relatime' });
const bind = (src: string, dst: string) => ({ Type: 'bind', Source: src, Destination: dst, Mode: '', RW: true, Propagation: 'rprivate' });

const cases: [string, (f: Facts) => void, CheckId[]][] = [
  ['the daemon is not rootless', (f) => f.info.SecurityOptions.pop(), ['rootless']],

  [
    'bridge network',
    (f) => {
      f.inspect.HostConfig.NetworkMode = 'bridge';
      f.inspect.NetworkSettings.Networks = { bridge: {} } as never;
      f.probe.interfaces = ['eth0', 'lo'];
      f.probe.ipv4Routes = ['eth0', 'eth0'];
      setConnect(f, (c) => !isLoopback(c), 'ECONNREFUSED');
    },
    ['network'],
  ],
  ['bridge network in the config only', (f) => void (f.inspect.HostConfig.NetworkMode = 'bridge'), ['network']],
  ['an extra network attached', (f) => void (f.inspect.NetworkSettings.Networks = { none: {}, kordn: {} } as never), ['network']],
  ['an interface besides lo at runtime only', (f) => void (f.probe.interfaces = ['eth0', 'lo']), ['network']],
  ['an IPv4 route at runtime only', (f) => void (f.probe.ipv4Routes = ['eth0']), ['network']],
  ['an IPv6 route off loopback', (f) => void f.probe.ipv6Routes?.push('eth0'), ['network']],
  ['an outbound connect that times out instead of having no route', (f) => setConnect(f, (c) => c.host === '1.1.1.1', 'timeout'), ['network']],
  ['an outbound connect that is refused (the host answered)', (f) => setConnect(f, (c) => c.host === '172.17.0.1', 'ECONNREFUSED'), ['network']],
  [
    'host network: the host loopback canary is reached',
    (f) => {
      f.inspect.HostConfig.NetworkMode = 'host';
      f.inspect.NetworkSettings.Networks = { host: {} } as never;
      f.probe.interfaces = ['docker0', 'eth0', 'lo'];
      f.probe.ipv4Routes = ['eth0'];
      setConnect(f, isLoopback, 'connected');
      f.canaryHits = 2;
    },
    ['network', 'hostServicesUnreachable'],
  ],
  ['the canary saw a connection the probe did not report', (f) => void (f.canaryHits = 1), ['hostServicesUnreachable']],
  ['the probe reached the canary port', (f) => setConnect(f, (c) => c.host === '::1', 'connected'), ['hostServicesUnreachable']],
  [
    'the admin UI port is reachable',
    (f) => {
      f.expectations.adminPort = 3333;
      f.probe.connects.push({ host: '127.0.0.1', port: 3333, result: 'connected' }, { host: '::1', port: 3333, result: 'ECONNREFUSED' });
    },
    ['hostServicesUnreachable'],
  ],
  ['the admin UI port was never probed', (f) => void (f.expectations.adminPort = 3333), ['hostServicesUnreachable']],
  [
    'the guardian DB is visible inside',
    (f) => {
      f.expectations.dbPath = '/home/alice/.kordn/kordn.sqlite';
      setPath(f, '/home/alice/.kordn/kordn.sqlite', 'present');
    },
    ['hostServicesUnreachable'],
  ],
  ['the guardian DB path was never probed', (f) => void (f.expectations.dbPath = '/home/alice/.kordn/kordn.sqlite'), ['hostServicesUnreachable']],

  [
    'writable rootfs, written as non-root (EACCES, not EROFS)',
    (f) => {
      f.inspect.HostConfig.ReadonlyRootfs = false;
      for (const w of f.probe.writes) w.result = 'EACCES';
      const root = f.probe.mounts?.find((m) => m.mountPoint === '/');
      if (root) root.options = 'rw,relatime';
    },
    ['readOnlyRootfs'],
  ],
  ['writable rootfs in the config only', (f) => void (f.inspect.HostConfig.ReadonlyRootfs = false), ['readOnlyRootfs']],
  ['writes fail with EACCES although the config says read-only', (f) => f.probe.writes.forEach((w) => (w.result = 'EACCES')), ['readOnlyRootfs']],
  ['one write succeeded', (f) => void ((f.probe.writes[4] as { result: string }).result = 'ok'), ['readOnlyRootfs']],
  ['/ mounted rw at runtime only', (f) => void ((f.probe.mounts?.find((m) => m.mountPoint === '/') as { options: string }).options = 'rw'), ['readOnlyRootfs']],
  ['/tmp tmpfs without noexec', (f) => void (f.inspect.HostConfig.Tmpfs = { '/tmp': 'rw,size=64m' }), ['readOnlyRootfs']],
  [
    'an extra writable tmpfs',
    (f) => {
      f.inspect.HostConfig.Tmpfs = { '/tmp': 'rw,nosuid,nodev,noexec,size=64m', '/data': 'rw' } as never;
      addMount(f, '/data', '/', 'tmpfs');
    },
    ['readOnlyRootfs', 'onlyGuardianSocket'],
  ],

  [
    'docker.sock mounted',
    (f) => {
      f.inspect.Mounts.push(bind('/var/run/docker.sock', '/var/run/docker.sock') as never);
      setPath(f, '/var/run/docker.sock', 'present');
      addMount(f, '/var/run/docker.sock', '/docker.sock', 'tmpfs');
    },
    ['onlyGuardianSocket'],
  ],
  [
    'home dir mounted',
    (f) => {
      f.inspect.Mounts.push(bind('/home/alice', '/home/alice') as never);
      setPath(f, '/home/alice', 'present');
      addMount(f, '/home/alice', '/@/home/alice', 'btrfs');
    },
    ['onlyGuardianSocket'],
  ],
  ['an extra mount in the config only', (f) => void f.inspect.Mounts.push(bind('/srv', '/srv') as never), ['onlyGuardianSocket']],
  ['an unexplained mount at runtime only', (f) => addMount(f, '/opt/data', '/@/home/alice', 'btrfs'), ['onlyGuardianSocket']],
  ['a host dir hidden under /proc', (f) => addMount(f, '/proc/x', '/@/home/alice', 'btrfs'), ['onlyGuardianSocket']],
  ['a host tmpfs subdir bound under /sys', (f) => addMount(f, '/sys/x', '/user/1000', 'tmpfs'), ['onlyGuardianSocket']],
  ['/etc/hosts from somewhere else', (f) => void ((f.probe.mounts?.find((m) => m.mountPoint === '/etc/hosts') as { root: string }).root = '/@/etc/hosts'), ['onlyGuardianSocket']],
  ['the socket mounted from another host path', (f) => void ((f.inspect.Mounts[0] as { Source: string }).Source = '/tmp/other.sock'), ['onlyGuardianSocket']],
  ['the socket mounted read-write', (f) => void ((f.inspect.Mounts[0] as { RW: boolean }).RW = true), ['onlyGuardianSocket']],
  ['the socket mount missing', (f) => void f.inspect.Mounts.pop(), ['onlyGuardianSocket']],
  ['a device passed through', (f) => void (f.inspect.HostConfig.Devices = [{ PathOnHost: '/dev/sda' }] as never), ['onlyGuardianSocket']],
  ['docker.sock visible at runtime only', (f) => setPath(f, '/run/docker.sock', 'present'), ['onlyGuardianSocket']],
  ['a probe path answered with EACCES rather than ENOENT', (f) => setPath(f, '/home/alice', 'EACCES'), ['onlyGuardianSocket']],
  [
    'the SSH agent forwarded',
    (f) => {
      f.expectations.sshAuthSock = '/run/user/1000/ssh-agent.sock';
      f.inspect.Config.Env.push('SSH_AUTH_SOCK=/ssh-agent');
      f.inspect.Mounts.push(bind('/run/user/1000/ssh-agent.sock', '/ssh-agent') as never);
      addMount(f, '/ssh-agent', '/user/1000/ssh-agent.sock', 'tmpfs');
      f.probe.env.push('SSH_AUTH_SOCK');
      setPath(f, '/run/user/1000/ssh-agent.sock', 'ENOENT');
    },
    ['onlyGuardianSocket', 'noHostEnv'],
  ],
  [
    'a variable injected with -e',
    (f) => {
      f.inspect.Config.Env.push('API_TOKEN=s3cret-value');
      f.probe.env.push('API_TOKEN');
    },
    ['noHostEnv'],
  ],
  ['an image variable overridden with -e', (f) => void (f.inspect.Config.Env[0] = 'PATH=/tmp'), ['noHostEnv']],
  ['an extra variable at runtime only', (f) => void f.probe.env.push('AWS_SECRET_ACCESS_KEY'), ['noHostEnv']],

  [
    'root user',
    (f) => {
      f.inspect.Config.User = '0:0';
      f.probe.uid = 0;
      f.probe.gid = 0;
      f.probe.groups = [0];
    },
    ['nonRoot'],
  ],
  ['no user set (image default could be root)', (f) => void (f.inspect.Config.User = ''), ['nonRoot']],
  ['a named user', (f) => void (f.inspect.Config.User = 'node'), ['nonRoot']],
  ['root at runtime only', (f) => void (f.probe.uid = 0), ['nonRoot']],
  ['root group at runtime only', (f) => void f.probe.groups.push(0), ['nonRoot']],

  [
    'no cap-drop',
    (f) => {
      f.inspect.HostConfig.CapDrop = null as never;
      f.probe.status.CapBnd = '00000000a80425fb';
    },
    ['capabilities'],
  ],
  ['no cap-drop in the config only', (f) => void (f.inspect.HostConfig.CapDrop = [] as never), ['capabilities']],
  ['a capability added back', (f) => void (f.inspect.HostConfig.CapAdd = ['NET_RAW'] as never), ['capabilities']],
  ['a bounding-set capability at runtime only', (f) => void (f.probe.status.CapBnd = '0000000000002000'), ['capabilities']],
  ['capabilities missing from the probe', (f) => void delete f.probe.status.CapEff, ['capabilities']],
  [
    'privileged',
    (f) => {
      f.inspect.HostConfig.Privileged = true;
      f.probe.status.Seccomp = '0';
    },
    ['capabilities', 'seccomp'],
  ],

  [
    'no no-new-privileges',
    (f) => {
      f.inspect.HostConfig.SecurityOpt = [];
      f.probe.status.NoNewPrivs = '0';
    },
    ['noNewPrivileges', 'hardening'],
  ],
  ['no-new-privileges:false', (f) => void (f.inspect.HostConfig.SecurityOpt = ['no-new-privileges:false']), ['noNewPrivileges', 'hardening']],
  ['NoNewPrivs off at runtime only', (f) => void (f.probe.status.NoNewPrivs = '0'), ['noNewPrivileges']],

  [
    'seccomp unconfined',
    (f) => {
      f.inspect.HostConfig.SecurityOpt.push('seccomp=unconfined');
      f.probe.status.Seccomp = '0';
    },
    ['seccomp', 'hardening'],
  ],
  ['seccomp:unconfined in the config only', (f) => void f.inspect.HostConfig.SecurityOpt.push('seccomp:unconfined'), ['seccomp', 'hardening']],
  ['no seccomp filter at runtime only', (f) => void (f.probe.status.Seccomp = '0'), ['seccomp']],

  [
    '--pid host',
    (f) => {
      f.inspect.HostConfig.PidMode = 'host';
      f.probe.pid1 = ['/run/current-system/systemd/lib/systemd/systemd'];
    },
    ['namespaces'],
  ],
  ['--ipc host', (f) => void (f.inspect.HostConfig.IpcMode = 'host'), ['namespaces']],
  ['--uts host', (f) => void (f.inspect.HostConfig.UTSMode = 'host'), ['namespaces']],
  ['--userns host', (f) => void (f.inspect.HostConfig.UsernsMode = 'host'), ['namespaces']],
  ['--cgroupns host', (f) => void (f.inspect.HostConfig.CgroupnsMode = 'host'), ['namespaces']],
  ['sharing another container pid namespace', (f) => void (f.inspect.HostConfig.PidMode = 'container:abc'), ['namespaces']],
  ['an unexpected PID 1 at runtime only', (f) => void (f.probe.pid1 = ['/bin/sh']), ['namespaces']],

  [
    'no pids or memory limits',
    (f) => {
      f.inspect.HostConfig.PidsLimit = null as never;
      f.inspect.HostConfig.Memory = 0;
      f.inspect.HostConfig.MemorySwap = 0;
      f.inspect.HostConfig.NanoCpus = 0;
      f.probe.pidsMax = 'max';
      f.probe.memoryMax = 'max';
    },
    ['resourceLimits'],
  ],
  ['a pids limit above 64', (f) => void (f.inspect.HostConfig.PidsLimit = 4096), ['resourceLimits']],
  ['unlimited swap', (f) => void (f.inspect.HostConfig.MemorySwap = -1), ['resourceLimits']],
  ['no cpu limit', (f) => void (f.inspect.HostConfig.NanoCpus = 0), ['resourceLimits']],
  ['pids unlimited at runtime only', (f) => void (f.probe.pidsMax = 'max'), ['resourceLimits']],
  ['cgroup files unreadable', (f) => void (f.probe.memoryMax = 'error:ENOENT'), ['resourceLimits']],

  // ---- review round 1: settings that used to pass ----
  ['a permissive custom seccomp profile on the container', (f) => void f.inspect.HostConfig.SecurityOpt.push('seccomp={"defaultAction":"SCMP_ACT_ALLOW"}'), ['seccomp', 'hardening']],
  [
    'a custom seccomp profile set daemon-wide',
    (f) => void (f.info.SecurityOptions = f.info.SecurityOptions.map((o) => (o.startsWith('name=seccomp') ? 'name=seccomp,profile=/etc/docker/seccomp.json' : o))),
    ['seccomp'],
  ],
  ['a daemon without seccomp', (f) => void (f.info.SecurityOptions = f.info.SecurityOptions.filter((o) => !o.startsWith('name=seccomp'))), ['seccomp']],
  [
    'systempaths=unconfined: /proc and /sys unmasked',
    (f) => {
      f.inspect.HostConfig.SecurityOpt.push('systempaths=unconfined');
      f.inspect.HostConfig.MaskedPaths = [];
      f.inspect.HostConfig.ReadonlyPaths = [];
      f.probe.mounts = (f.probe.mounts ?? []).filter((m) => !/^\/(proc|sys)\/./.test(m.mountPoint) || m.mountPoint === '/sys/fs/cgroup');
    },
    ['hardening'],
  ],
  ['a default masked path dropped from the config', (f) => void (f.inspect.HostConfig.MaskedPaths = f.inspect.HostConfig.MaskedPaths.filter((p) => p !== '/proc/kcore')), ['hardening']],
  ['a default read-only path dropped from the config', (f) => void (f.inspect.HostConfig.ReadonlyPaths = f.inspect.HostConfig.ReadonlyPaths.filter((p) => p !== '/proc/sys')), ['hardening']],
  ['/proc/sys writable at runtime', (f) => void ((f.probe.mounts?.find((m) => m.mountPoint === '/proc/sys') as { options: string }).options = 'rw,nosuid'), ['hardening']],
  ['/proc/kcore not masked at runtime', (f) => void (f.probe.mounts = (f.probe.mounts ?? []).filter((m) => m.mountPoint !== '/proc/kcore')), ['hardening']],
  ['apparmor=unconfined', (f) => void f.inspect.HostConfig.SecurityOpt.push('apparmor=unconfined'), ['hardening']],
  ['label=disable', (f) => void f.inspect.HostConfig.SecurityOpt.push('label=disable'), ['hardening']],
  ['another OCI runtime', (f) => void (f.inspect.HostConfig.Runtime = 'runsc'), ['hardening']],
  ['a device cgroup rule', (f) => void (f.inspect.HostConfig.DeviceCgroupRules = ['a *:* rwm'] as never), ['onlyGuardianSocket']],
  ['a device request (--gpus)', (f) => void (f.inspect.HostConfig.DeviceRequests = [{ Driver: 'nvidia', Count: -1 }] as never), ['onlyGuardianSocket']],
  [
    'a /tmp tmpfs whose later options re-enable exec, suid and dev',
    (f) => {
      f.inspect.HostConfig.Tmpfs = { '/tmp': 'rw,nosuid,nodev,noexec,size=64m,exec,suid,dev' };
      (f.probe.mounts?.find((m) => m.mountPoint === '/tmp') as { options: string }).options = 'rw,relatime';
    },
    ['readOnlyRootfs'],
  ],
  ['/tmp mounted exec at runtime only', (f) => void ((f.probe.mounts?.find((m) => m.mountPoint === '/tmp') as { options: string }).options = 'rw,nosuid,nodev,relatime'), ['readOnlyRootfs']],
  ['a different /tmp size', (f) => void (f.inspect.HostConfig.Tmpfs = { '/tmp': 'rw,nosuid,nodev,noexec,size=4g' }), ['readOnlyRootfs']],
  ['a private IPC namespace instead of none', (f) => void (f.inspect.HostConfig.IpcMode = 'private'), ['namespaces']],
  ['/dev/shm mounted at runtime', (f) => addMount(f, '/dev/shm', '/', 'tmpfs'), ['onlyGuardianSocket', 'namespaces']],
  ["sharing the launcher's (non-initial) mount namespace", (f) => void (f.probe.namespaces.mnt = f.expectations.hostNamespaces.mnt ?? ''), ['namespaces']],
  ["sharing the launcher's network namespace", (f) => void (f.probe.namespaces.net = f.expectations.hostNamespaces.net ?? ''), ['namespaces']],
  ["the host's initial user namespace (rootful, no userns-remap)", (f) => void (f.probe.namespaces.user = 'user:[4026531837]'), ['namespaces']],
  ["the host's initial pid namespace", (f) => void (f.probe.namespaces.pid = 'pid:[4026531836]'), ['namespaces']],
  ['a namespace link unreadable', (f) => void (f.probe.namespaces.uts = 'error:EACCES'), ['namespaces']],
  ['a namespace missing from the probe', (f) => void delete f.probe.namespaces.cgroup, ['namespaces']],
  ['the rootless daemon socket visible inside', (f) => setPath(f, f.expectations.dockerSockets.at(-1) ?? '', 'present'), ['onlyGuardianSocket']],

  [
    'the guardian socket is unreachable',
    (f) => void (f.probe.socket = { connected: false, error: 'ECONNREFUSED', response: null }),
    ['guardianSocket'],
  ],
];

describe('evaluateIsolation', () => {
  it('reports Contain only when every check passes, each with a detail', () => {
    const report = evaluateIsolation(safe());
    expect(report.checks.map((c) => c.id)).toEqual([...CHECK_IDS]);
    expect(report.checks.filter((c) => !c.pass)).toEqual([]);
    for (const c of report.checks) expect(c.detail).not.toBe('');
    expect(report.mode).toBe('contain');
    expect(report.imageId).toBe(fixture.inspect.Image);
  });

  it('reports Guard for the captured container: rootful Docker, so it shares the host user namespace', () => {
    const report = evaluateIsolation(structuredClone(fixture) as unknown as IsolationFacts);
    expect(report.checks.filter((c) => !c.pass).map((c) => c.id)).toEqual(['rootless', 'namespaces']);
    expect(report.mode).toBe('guard');
  });

  for (const [name, mutate, expected] of cases) {
    it(`${name}: fails ${expected.join(' + ')}`, () => {
      const f = safe();
      mutate(f);
      expect(failing(f)).toEqual(expected);
      expect(evaluateIsolation(f).mode).toBe('guard');
    });
  }

  it('never puts env values in the report', () => {
    const f = safe();
    f.inspect.Config.Env.push('API_TOKEN=s3cret-value');
    expect(JSON.stringify(evaluateIsolation(f))).not.toContain('s3cret-value');
  });
});

describe('evaluateIsolation fails closed', () => {
  const runtimeBacked = CHECK_IDS.filter((id) => id !== 'rootless');
  const configBacked: CheckId[] = [
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
  ];

  it('without probe output, every runtime-backed check fails', () => {
    const f = safe();
    f.probe = null as never;
    expect(failing(f)).toEqual(runtimeBacked);
  });

  it('with unreadable docker inspect, every config-backed check fails', () => {
    for (const inspect of [null, {}, { Config: {} }, 'garbage']) {
      const f = safe();
      f.inspect = inspect as never;
      expect(failing(f)).toEqual(configBacked);
    }
  });

  it('accepts docker inspect in its array form', () => {
    const f = safe();
    f.inspect = [f.inspect] as never;
    expect(failing(f)).toEqual([]);
  });

  it('with unreadable docker info, rootless and seccomp fail', () => {
    const f = safe();
    f.info = null as never;
    expect(failing(f)).toEqual(['rootless', 'seccomp']);
  });

  it('a probe that skipped its targets fails every check that needs them', () => {
    const f = safe();
    f.probe.connects = [];
    f.probe.writes = [];
    f.probe.paths = [];
    expect(failing(f)).toEqual(['network', 'readOnlyRootfs', 'onlyGuardianSocket', 'hostServicesUnreachable']);
  });

  it('unreadable network facts fail the network check', () => {
    for (const field of ['interfaces', 'ipv4Routes', 'ipv6Routes', 'mounts'] as const) {
      const f = safe();
      f.probe[field] = null;
      expect(failing(f).length, field).toBeGreaterThan(0);
    }
  });

  it('a failing duplicate probe entry is not hidden by a passing one', () => {
    const f = safe();
    f.probe.writes.push({ path: '/app', result: 'ok' });
    expect(failing(f)).toEqual(['readOnlyRootfs']);
  });
});
