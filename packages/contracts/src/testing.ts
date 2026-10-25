import type { Clock } from './interfaces';

/** Deterministic clock for tests (§11.2). */
export class FakeClock implements Clock {
  constructor(private ms: number = Date.UTC(2026, 9, 25, 12, 0, 0)) {}
  nowMs(): number {
    return this.ms;
  }
  advance(ms: number): void {
    if (ms < 0) throw new RangeError('clock cannot go backwards');
    this.ms += ms;
  }
  set(ms: number): void {
    this.ms = ms;
  }
}

export const SECOND = 1_000;
export const MINUTE = 60 * SECOND;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;
