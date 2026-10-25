// The container settings that hardenedRunFlags (src/sandbox.ts) sets and the isolation checks
// (src/sandbox-checks.ts) require. One source, so the two can't drift apart.

/** Where the guardian socket appears inside the container. */
export const SANDBOX_SOCKET = '/run/kordn.sock';

/** Options of the /tmp tmpfs, the only writable place. Checked for exact equality. */
export const TMP_TMPFS_OPTIONS = 'rw,nosuid,nodev,noexec,size=64m';

/** The container's whole --security-opt list. Anything else (a seccomp profile, LSM opt-outs,
 * systempaths=unconfined) means Guard. */
export const SECURITY_OPTS: readonly string[] = ['no-new-privileges'];

/** OCI runtimes whose isolation the checks were written against. */
export const ALLOWED_RUNTIMES: readonly string[] = ['runc', 'crun'];
