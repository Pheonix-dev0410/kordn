import { spawn } from 'node:child_process';

// --tunnel: a Cloudflare quick tunnel, a free public https URL for kordn's port with no
// account. cloudflared prints the URL on stderr. It changes every time the tunnel starts,
// so apps connected through it have to be added again after a restart; for a URL that
// stays, run your own tunnel and pass --public-url.

const URL_PATTERN = /https:\/\/(?!api\.)[a-z0-9-]+\.trycloudflare\.com/;
const START_TIMEOUT_MS = 30_000;
const INSTALL = 'https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/';

export interface Tunnel {
  url: URL;
  close(): void;
}

export function startQuickTunnel(port: number, command = 'cloudflared'): Promise<Tunnel> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, ['tunnel', '--no-autoupdate', '--url', `http://127.0.0.1:${port}`], {
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let closed = false;
    const close = () => {
      closed = true;
      child.kill();
    };
    // Also on a crash or process.exit(), so cloudflared never outlives kordn.
    process.once('exit', close);
    let output = '';
    let up = false;
    const fail = (error: Error) => {
      if (up) return;
      clearTimeout(timer);
      close();
      reject(error);
    };
    const timer = setTimeout(() => fail(new Error('cloudflared did not print a tunnel URL within 30 seconds')), START_TIMEOUT_MS);
    child.on('error', (error: NodeJS.ErrnoException) =>
      fail(error.code === 'ENOENT' ? new Error(`--tunnel needs cloudflared: brew install cloudflared, or see ${INSTALL}`) : error),
    );
    child.on('exit', (code) => {
      if (!up) fail(new Error(`cloudflared exited (${code ?? 'killed'}) before the tunnel was up`));
      else if (!closed) process.stderr.write('kordn: the tunnel stopped; apps can no longer reach kordn\n');
    });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => {
      if (up) return;
      output = (output + chunk).slice(-8192);
      const match = URL_PATTERN.exec(output);
      if (!match) return;
      up = true;
      clearTimeout(timer);
      resolve({ url: new URL(match[0]), close });
    });
  });
}
