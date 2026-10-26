import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const SESSION_TTL_MS = 8 * 3600_000;

/** 256 random bits, URL-safe. Used for the login token, session ids and CSRF tokens. */
export function secret(): string {
  return randomBytes(32).toString('base64url');
}

/** Constant-time comparison. Hashing first hides the length of the expected value too. */
export function sameSecret(given: string | null, expected: string): boolean {
  if (given === null) return false;
  const digest = (s: string) => createHash('sha256').update(s).digest();
  return timingSafeEqual(digest(given), digest(expected));
}

export interface Session {
  id: string;
  csrf: string;
  expiresAt: number;
  /** One-time message for the next page, e.g. "Policy saved". */
  flash: string | null;
}

export class Sessions {
  private readonly byId = new Map<string, Session>();

  constructor(private readonly now: () => number) {}

  create(): Session {
    for (const [id, s] of this.byId) if (s.expiresAt <= this.now()) this.byId.delete(id);
    const session: Session = { id: secret(), csrf: secret(), expiresAt: this.now() + SESSION_TTL_MS, flash: null };
    this.byId.set(session.id, session);
    return session;
  }

  get(id: string): Session | null {
    const session = this.byId.get(id);
    if (!session) return null;
    if (session.expiresAt <= this.now()) {
      this.byId.delete(id);
      return null;
    }
    return session;
  }

  delete(id: string): void {
    this.byId.delete(id);
  }
}

/** At most `max` events per fixed window. Shared by all clients: everyone is 127.0.0.1. */
export class WindowLimit {
  private start = -Infinity;
  private count = 0;

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
    private readonly now: () => number,
  ) {}

  full(): boolean {
    this.roll();
    return this.count >= this.max;
  }

  add(): void {
    this.roll();
    this.count += 1;
  }

  private roll(): void {
    const t = this.now();
    if (t - this.start >= this.windowMs) {
      this.start = t;
      this.count = 0;
    }
  }
}
