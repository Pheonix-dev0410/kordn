import { spawn } from 'node:child_process';

// --tunnel: a Cloudflare quick tunnel, a free public https URL for kordn's port with no
// account. cloudflared prints the URL on stderr. It changes every time the tunnel starts,
// so apps connected through it have to be added again after a restart; for a URL that
// stays, use --ngrok with your free static domain, or run your own tunnel and pass
// --public-url.
//
// --ngrok <domain>: ngrok on the user's own static domain, which stays the same. ngrok logs
// JSON lines on stdout: "started tunnel" with the url once it's up, an "err" when it fails.
// Its traffic inspector is off, so the requests (and their tokens) aren't kept on :4040.

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
      // A new quick tunnel would have a new URL, which connected apps don't know: no restart.
      else if (!closed) {
        process.stderr.write('kordn: the Cloudflare tunnel stopped, so apps can no longer reach kordn. Restart kordn and update the URL in your apps, or use --ngrok for an address that stays the same\n');
      }
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

const NGROK_INSTALL = 'https://ngrok.com/download';
const RESTART_MAX_MS = 30_000;

/**
 * ngrok on `url`, the user's static domain. If ngrok stops while kordn runs, it is started
 * again on the same URL (waiting longer each time, up to 30 seconds), so apps keep working.
 */
export function startNgrok(port: number, url: URL, command = 'ngrok'): Promise<Tunnel> {
  let child: ReturnType<typeof spawn> | undefined;
  let closed = false;
  const close = () => {
    closed = true;
    child?.kill();
  };
  process.once('exit', close);

  const launch = () =>
    new Promise<void>((resolve, reject) => {
      const args = ['http', `127.0.0.1:${port}`, '--url', url.origin, '--inspect=false', '--log', 'stdout', '--log-format', 'json'];
      const proc = spawn(command, args, { stdio: ['ignore', 'pipe', 'ignore'] });
      child = proc;
      let up = false;
      let error: string | undefined;
      const timer = setTimeout(() => {
        proc.kill();
        reject(new Error('ngrok did not start the tunnel within 30 seconds'));
      }, START_TIMEOUT_MS);
      proc.on('error', (e: NodeJS.ErrnoException) => {
        clearTimeout(timer);
        reject(e.code === 'ENOENT' ? new Error(`--ngrok needs ngrok: brew install ngrok, or see ${NGROK_INSTALL}`) : e);
      });
      // 'close', not 'exit': only then has all of ngrok's output, with its error, been read.
      proc.on('close', (code) => {
        clearTimeout(timer);
        if (!up) reject(new Error(error ?? `ngrok exited (${code ?? 'killed'}) before the tunnel was up`));
        else if (!closed) onDrop();
      });
      let buffered = '';
      proc.stdout!.setEncoding('utf8');
      proc.stdout!.on('data', (chunk: string) => {
        buffered = (buffered + chunk).slice(-65_536);
        const lines = buffered.split('\n');
        buffered = lines.pop() ?? '';
        for (const line of lines) {
          let record: { msg?: unknown; url?: unknown; err?: unknown; lvl?: unknown };
          try { record = JSON.parse(line); } catch { continue; }
          if (record.msg === 'started tunnel' && sameOrigin(record.url, url)) {
            up = true;
            clearTimeout(timer);
            resolve();
          } else if ((record.lvl === 'eror' || record.lvl === 'crit') && typeof record.err === 'string' && record.err !== '<nil>') {
            error ??= ngrokError(record.err);
          }
        }
      });
    });

  let delay = 1_000;
  const onDrop = () => {
    process.stderr.write(`kordn: ngrok stopped; starting it again on ${url.origin}\n`);
    const retry = () => {
      if (closed) return;
      launch().then(
        () => {
          delay = 1_000;
          process.stderr.write('kordn: ngrok is back\n');
        },
        (e: Error) => {
          process.stderr.write(`kordn: ngrok didn't start (${e.message}); trying again in ${delay / 1000}s\n`);
          setTimeout(retry, delay).unref();
          delay = Math.min(delay * 2, RESTART_MAX_MS);
        },
      );
    };
    setTimeout(retry, delay).unref();
  };

  return launch().then(
    () => ({ url, close }),
    (e: unknown) => {
      close();
      throw e;
    },
  );
}

/** ngrok's error, as one line, with the usual fixes spelled out. */
function ngrokError(err: string): string {
  const code = /ERR_NGROK_\d+/.exec(err)?.[0];
  if (code === 'ERR_NGROK_4018') return 'ngrok needs your authtoken: sign up at dashboard.ngrok.com, then run ngrok config add-authtoken <token>';
  const first = err.split(/\r?\n/).find((l) => l.trim())?.trim().slice(0, 200) ?? 'unknown error';
  return `ngrok: ${first}${code && !first.includes(code) ? ` (${code})` : ''}`;
}

function sameOrigin(value: unknown, url: URL): boolean {
  try { return typeof value === 'string' && new URL(value).origin === url.origin; }
  catch { return false; }
}
