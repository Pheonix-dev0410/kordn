import { describe, expect, it } from 'vitest';
import { dockerSocketPaths, hardenedRunFlags, SANDBOX_SOCKET, sandboxUser, socketFileMode } from '../src/sandbox.js';

describe('hardened run flags', () => {
  const flags = hardenedRunFlags({ socketPath: '/tmp/kordn-abc/guardian.sock', user: '1000:100' });

  it('disables network, writes, capabilities and privilege gain, and caps resources', () => {
    expect(flags).toEqual([
      '--network',
      'none',
      '--ipc',
      'none',
      '--read-only',
      '--cap-drop',
      'ALL',
      '--security-opt',
      'no-new-privileges',
      '--pids-limit',
      '64',
      '--memory',
      '512m',
      '--memory-swap',
      '512m',
      '--cpus',
      '1',
      '--tmpfs',
      '/tmp:rw,nosuid,nodev,noexec,size=64m',
      '--user',
      '1000:100',
      '--mount',
      `type=bind,src=/tmp/kordn-abc/guardian.sock,dst=${SANDBOX_SOCKET},readonly`,
    ]);
  });

  it('mounts the guardian socket and nothing else', () => {
    expect(flags.filter((f) => /^(--mount|-v|--volume|--volumes-from|--device)$/.test(f))).toEqual(['--mount']);
    expect(SANDBOX_SOCKET).toBe('/run/kordn.sock');
  });

  it('refuses socket paths that could smuggle extra mount options', () => {
    for (const socketPath of ['/tmp/a,dst=/x', '/tmp/a"b', '/tmp/a\nb', 'relative.sock', '']) {
      expect(() => hardenedRunFlags({ socketPath, user: '1000:100' })).toThrow(/socket path/);
    }
  });

  it('accepts only a numeric non-root uid:gid', () => {
    for (const user of ['root', '0:0', '1000:0', '0:100', '1000', 'node', '1000:100 --privileged', '']) {
      expect(() => hardenedRunFlags({ socketPath: '/tmp/s.sock', user })).toThrow(/user/);
    }
  });
});

describe('sandbox user and socket mode', () => {
  it('rootful: runs as the host user so a 0600 socket is enough', () => {
    expect(sandboxUser({ rootless: false, uid: 1000, gid: 100 })).toBe('1000:100');
    expect(socketFileMode(false)).toBe(0o600);
  });

  it('rootless: host uid is container root, so use the image user and open the socket inside the private dir', () => {
    expect(sandboxUser({ rootless: true, uid: 1000, gid: 100 })).toBe('65532:65532');
    expect(socketFileMode(true)).toBe(0o666);
  });
});

describe('dockerSocketPaths', () => {
  it('includes the rootful defaults', () => {
    expect(dockerSocketPaths({})).toEqual(['/var/run/docker.sock', '/run/docker.sock']);
  });

  it('adds the socket named by DOCKER_HOST, the docker context and the rootless default', () => {
    expect(
      dockerSocketPaths({
        dockerHost: 'unix:///run/user/1000/docker.sock',
        contextHost: 'unix:///home/alice/.docker/run/docker.sock',
        xdgRuntimeDir: '/run/user/1000',
      }),
    ).toEqual(['/var/run/docker.sock', '/run/docker.sock', '/run/user/1000/docker.sock', '/home/alice/.docker/run/docker.sock']);
  });

  it('ignores non-unix endpoints', () => {
    expect(dockerSocketPaths({ dockerHost: 'tcp://127.0.0.1:2375', contextHost: 'ssh://me@host' })).toEqual([
      '/var/run/docker.sock',
      '/run/docker.sock',
    ]);
  });
});
