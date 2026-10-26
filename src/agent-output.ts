import { StringDecoder } from 'node:string_decoder';

// The agent's output goes to the same terminal as kordn's own report, and the agent is
// untrusted. So every agent line is prefixed (an agent can't print a line that looks like
// kordn's) and control characters are removed (it can't move the cursor to rewrite kordn's
// lines, set the clipboard or title with OSC sequences, or return to the line start with \r).

export const AGENT_STDOUT_PREFIX = 'agent | ';
export const AGENT_STDERR_PREFIX = 'agent! | ';

/** ESC and every other C0 control except \t and \n, DEL, and the C1 controls. */
const CONTROL = /[\x00-\x08\x0b-\x1f\x7f-\x9f]/g;

/**
 * One output stream of the agent, turned into prefixed, inert lines. Keeps the partial line and
 * any partial UTF-8 character between chunks, so a split never breaks a character or a prefix.
 */
export class AgentLines {
  private readonly decoder = new StringDecoder('utf8');
  private atLineStart = true;

  constructor(private readonly prefix: string) {}

  push(chunk: Buffer): string {
    return this.format(this.decoder.write(chunk));
  }

  /** The rest of the stream, ending an unfinished last line so whatever follows starts on its own. */
  end(): string {
    const rest = this.format(this.decoder.end());
    return this.atLineStart ? rest : `${rest}\n`;
  }

  /** A newline if a line is unfinished, so a kordn line can go in between. The prefix comes again after it. */
  breakLine(): string {
    if (this.atLineStart) return '';
    this.atLineStart = true;
    return '\n';
  }

  private format(text: string): string {
    const parts = text.replace(CONTROL, '').split('\n');
    let out = '';
    parts.forEach((part, i) => {
      const last = i === parts.length - 1;
      if (part.length > 0 || !last) {
        if (this.atLineStart) out += this.prefix;
        this.atLineStart = false;
        out += part;
      }
      if (!last) {
        out += '\n';
        this.atLineStart = true;
      }
    });
    return out;
  }
}
