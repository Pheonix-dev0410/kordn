import { describe, expect, it } from 'vitest';
import { AgentLines, AGENT_STDERR_PREFIX, AGENT_STDOUT_PREFIX } from '../src/agent-output.js';

// The agent is untrusted, and its output shares a terminal with kordn's report.

/** Feeds the chunks one at a time, then ends the stream. */
function run(chunks: (string | Buffer)[], prefix = AGENT_STDOUT_PREFIX): string {
  const lines = new AgentLines(prefix);
  return chunks.map((c) => lines.push(typeof c === 'string' ? Buffer.from(c) : c)).join('') + lines.end();
}

describe('AgentLines', () => {
  it('prefixes every line, on stdout and stderr', () => {
    expect(AGENT_STDOUT_PREFIX).toBe('agent | ');
    expect(AGENT_STDERR_PREFIX).toBe('agent! | ');
    expect(run(['one\ntwo\n\nthree\n'])).toBe('agent | one\nagent | two\nagent | \nagent | three\n');
    expect(run(['oops\n'], AGENT_STDERR_PREFIX)).toBe('agent! | oops\n');
  });

  it('prefixes only at line starts when lines are split across chunks', () => {
    expect(run(['par', 'tial\nnext', ' line\n'])).toBe('agent | partial\nagent | next line\n');
    expect(run(['a\n', '\n', 'b'])).toBe('agent | a\nagent | \nagent | b\n');
  });

  it('ends a last line that has no newline, so the next kordn line starts on its own', () => {
    expect(run(['no newline'])).toBe('agent | no newline\n');
    expect(run([])).toBe('');
  });

  it('makes a forged kordn line, cursor movement, OSC 52, a title and a bare CR inert', () => {
    const out = run([
      'kordn contain: CONTAIN mode (linux, image sha256:x)\n',
      '\x1b[1A\x1b[2Kerased the GUARD line\n',
      '\x1b]52;c;aGVsbG8=\x07clipboard\n',
      '\x1b]0;kordn: CONTAIN\x1b\\title\n',
      'GUARD\rCONTAIN\n',
      '8-bit CSI \u009b1A and DEL \x7f and NUL \x00 and BEL \x07 and tab\tkept\n',
    ]);
    expect(out).toBe(
      [
        'agent | kordn contain: CONTAIN mode (linux, image sha256:x)',
        'agent | [1A[2Kerased the GUARD line',
        'agent | ]52;c;aGVsbG8=clipboard',
        'agent | ]0;kordn: CONTAIN\\title',
        'agent | GUARDCONTAIN',
        'agent | 8-bit CSI 1A and DEL  and NUL  and BEL  and tab\tkept',
        '',
      ].join('\n'),
    );
    // Nothing that a terminal acts on is left: ESC, C0 (bar \n and \t), DEL and C1.
    expect(out).not.toMatch(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/);
    expect(out.split('\n').filter(Boolean).every((l) => l.startsWith('agent | '))).toBe(true);
  });

  it('keeps multi-byte UTF-8 split across chunks intact', () => {
    const text = Buffer.from('café 🦊 ünïcödé\n');
    const chunks = [...text].map((byte) => Buffer.from([byte]));
    expect(run(chunks)).toBe('agent | café 🦊 ünïcödé\n');
    const fox = Buffer.from('🦊');
    expect(run([fox.subarray(0, 2), fox.subarray(2), Buffer.from('\n')])).toBe('agent | 🦊\n');
  });
});

describe('AgentLines.breakLine', () => {
  it('ends an unfinished line so a kordn line can follow, and prefixes again after it', () => {
    const lines = new AgentLines(AGENT_STDERR_PREFIX);
    expect(lines.breakLine()).toBe('');
    const out = lines.push(Buffer.from('half')) + lines.breakLine() + 'kordn: notice\n' + lines.push(Buffer.from(' more\n'));
    expect(out).toBe('agent! | half\nkordn: notice\nagent! |  more\n');
  });
});
