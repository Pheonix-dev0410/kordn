import type { z } from 'zod';
import type { UntrustedText } from './schema.js';

type Untrusted = z.infer<typeof UntrustedText>;
type Signal = Untrusted['riskSignals'][number];

const MAX_LENGTH = 2000;
// Detection scans at most this many input chars (more than the 2000 kept) so regex work stays bounded
// whatever the memo size. Signals hidden beyond it are not seen; the label is advisory only.
const MAX_SCAN_CHARS = 20_000;

// Label for the model and the UI only. It never feeds into any policy decision.
const SIGNALS: ReadonlyArray<readonly [Signal, readonly RegExp[]]> = [
  [
    'instruction_like_text',
    [
      /\b(?:ignore|disregard|forget|override|bypass)\b.{0,40}\b(?:rules?|instructions?|polic(?:y|ies)|limits?|previous|prior|above)\b/i,
      /\b(?:system|assistant|developer|admin)\s*:/i,
      /\b(?:transfer|send|wire|pay)\b[^.]{0,60}\bto\b/i,
      /\bpre-?approved\b|\bapproved\s+all\b|\bpolicyApproved\b|\bidempotencyKey\b|\badmin\s+token\b/i,
      /\baf_[a-z_]+/i,
      /<\/?(?:description|policy|system|instructions?)\b/i,
      /\b(?:you\s+(?:must|should|are\s+now)|verify\s+your\s+account|call\s+(?:the\s+)?(?:tool|function))\b/i,
    ],
  ],
  [
    'contains_url',
    [
      /(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*:\/\/\S/i,
      /\bwww\./i,
      /(?<![a-z0-9.-])(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|example|xyz|ru|info|biz|app|dev)\b/i,
    ],
  ],
  [
    'contains_payee_like_id',
    [
      // Only quoted ids or the attacker's: bare slug-NN is common in real memos (INV-2024, ACH-1234).
      /["'`][a-z][a-z0-9]*-\d{2,}["'`]/i,
      /\battacker-\d+/i,
      /\bpayee_?id\b\s*[:=]?\s*["'`]?\w/i,
      /\bto\s+(?:the\s+)?attackers?\b/i,
    ],
  ],
];

// Invisible chars outside \p{Cc}\p{Cf} that still render as nothing and can split keywords.
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Variation_Selector}\u034f\u115f\u1160\u3164\uffa0\u2800]/gu;

// invisibleAs '' joins "ig<ZWSP>nore"; ' ' keeps "ignore<ZWSP>previous" as two words. Detection uses both.
function normalize(text: string, invisibleAs: '' | ' '): string {
  return (
    text
      .slice(0, MAX_SCAN_CHARS)
      // Lone surrogates would make the result unserializable or split pairs on truncation.
      .replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, '\ufffd')
      // Compatibility forms (fullwidth letters etc.) must not hide keywords.
      .normalize('NFKC')
      // Newlines and tabs become spaces, so a phrase split across lines still matches.
      .replace(/[\t\n\r\v\f\u2028\u2029]/g, ' ')
      .replace(INVISIBLE, invisibleAs)
      .replace(/\s+/g, ' ')
      .trim()
  );
}

function truncate(text: string): string {
  if (text.length <= MAX_LENGTH) return text;
  const last = text.charCodeAt(MAX_LENGTH - 1);
  const cut = last >= 0xd800 && last <= 0xdbff ? MAX_LENGTH - 1 : MAX_LENGTH;
  return text.slice(0, cut);
}

export function labelUntrusted(text: string): Untrusted {
  const clean = normalize(text, '');
  const spaced = normalize(text, ' ');
  const riskSignals = SIGNALS.filter(([, patterns]) =>
    patterns.some((p) => p.test(clean) || p.test(spaced)),
  ).map(([sig]) => sig);
  return { text: truncate(clean), trust: 'external_untrusted', riskSignals };
}
