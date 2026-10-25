// Contain mode: how the untrusted agent container is run. Design doc §9.1-9.2.
// The guardian socket is the only thing the container gets from the host.

/** Where the guardian socket appears inside the container. */
export const SANDBOX_SOCKET = '/run/kordn.sock';

/** The `nonroot` user of the distroless runtime image (sandbox/Dockerfile). */
const IMAGE_USER = '65532:65532';

export interface RunFlagOptions {
  /** Absolute host path of the guardian socket, inside a private (0700) directory. */
  socketPath: string;
  /** Numeric non-root uid:gid. */
  user: string;
}

export function hardenedRunFlags({ socketPath, user }: RunFlagOptions): string[] {
  // --mount is comma-separated key=value, so a comma or quote in the path could add options.
  if (!/^\/[^,"\n\r]+$/.test(socketPath)) throw new Error(`unsafe guardian socket path: ${JSON.stringify(socketPath)}`);
  const ids = /^([0-9]+):([0-9]+)$/.exec(user);
  if (!ids || Number(ids[1]) === 0 || Number(ids[2]) === 0) {
    throw new Error(`sandbox user must be a numeric non-root uid:gid, got ${JSON.stringify(user)}`);
  }
  return [
    '--network',
    'none',
    // No IPC namespace sharing and no /dev/shm: /tmp stays the only writable scratch space.
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
    // Same as --memory: no swap on top of the memory limit.
    '--memory-swap',
    '512m',
    '--cpus',
    '1',
    '--tmpfs',
    '/tmp:rw,nosuid,nodev,noexec,size=64m',
    '--user',
    user,
    '--mount',
    `type=bind,src=${socketPath},dst=${SANDBOX_SOCKET},readonly`,
  ];
}

/**
 * Rootful Docker: container uids are host uids, so running as the launching user lets it
 * connect to a 0600 socket nobody else can. Rootless Docker: container root is the host
 * user and every other container uid is a subordinate id, so a non-root container user
 * can't own the socket; it stays reachable only through the private 0700 directory.
 */
export function sandboxUser({ rootless, uid, gid }: { rootless: boolean; uid: number; gid: number }): string {
  return rootless ? IMAGE_USER : `${uid}:${gid}`;
}

export function socketFileMode(rootless: boolean): number {
  return rootless ? 0o666 : 0o600;
}
