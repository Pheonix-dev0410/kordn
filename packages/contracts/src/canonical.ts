import { createHash } from 'node:crypto';
import type { Sha256Digest } from './primitives';

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/**
 * Deterministic JSON encoding: sorted object keys, no whitespace. Throws on
 * values that have no canonical form (non-finite numbers, undefined, functions,
 * non-plain objects) so they can never be hashed ambiguously.
 */
export function canonicalJson(value: unknown): string {
  return encode(value as Json);
}

function encode(value: Json): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('non-finite number has no canonical form');
      return JSON.stringify(value);
    case 'string':
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map(encode).join(',')}]`;
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) throw new TypeError('only plain objects are canonicalizable');
      const keys = Object.keys(value).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${encode(value[k] as Json)}`).join(',')}}`;
    }
    default:
      throw new TypeError(`${typeof value} has no canonical form`);
  }
}

export function sha256(data: string): Sha256Digest {
  return `sha256:${createHash('sha256').update(data, 'utf8').digest('hex')}`;
}

/** Hash of the canonical request (§7.2). Idempotency is scoped to (agent, key) and compared on this hash. */
export function requestHash(action: unknown): Sha256Digest {
  return sha256(canonicalJson(action));
}
