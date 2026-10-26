import { Policy } from '../schema.js';

// Exact parsing of admin form input. Money never goes through floats: "75.01" is split as
// text into whole units and cents, so 75.01 can't become 7500.999.

const USD = /^(0|[1-9][0-9]{0,12})(?:\.([0-9]{1,2}))?$/;
const COUNT = /^(0|[1-9][0-9]{0,8})$/;

/** A plain amount with at most two decimals, to integer minor units. Null for anything else. */
export function parseUsd(text: string): number | null {
  const match = USD.exec(text.trim());
  if (!match) return null;
  const dollars = Number(match[1]);
  const cents = Number((match[2] ?? '').padEnd(2, '0'));
  return dollars * 100 + cents;
}

export function formatUsd(minor: number): string {
  return `${Math.floor(minor / 100)}.${String(minor % 100).padStart(2, '0')}`;
}

/** A non-negative integer with no sign, exponent or leading zeros. */
export function parseCount(text: string): number | null {
  const match = COUNT.exec(text.trim());
  return match ? Number(match[1]) : null;
}

/** A urlencoded body. A field sent more than once counts as missing, so it can't be smuggled. */
export class Form {
  constructor(private readonly params: URLSearchParams) {}

  one(name: string): string | null {
    const values = this.params.getAll(name);
    return values.length === 1 ? values[0]! : null;
  }
}

export const POLICY_FIELDS = [
  { name: 'readsPerHour', label: 'Reads per hour', kind: 'count' },
  { name: 'transfersPerDay', label: 'Transfers per 24 hours', kind: 'count' },
  { name: 'maxSingleUsd', label: 'Largest single transfer', kind: 'usd' },
  { name: 'maxTotalUsd', label: 'Total transferred per 24 hours', kind: 'usd' },
  { name: 'approvalAboveUsd', label: 'Ask me to approve transfers above', kind: 'usd' },
] as const;

export type PolicyField = (typeof POLICY_FIELDS)[number]['name'];
export type PolicyFormValues = Record<PolicyField | 'payees', string>;

export function policyFormValues(policy: Policy): PolicyFormValues {
  return {
    readsPerHour: String(policy.reads.maxCalls),
    transfersPerDay: String(policy.transfers.maxCalls),
    maxSingleUsd: formatUsd(policy.transfers.maxSingleMinor),
    maxTotalUsd: formatUsd(policy.transfers.maxCumulativeMinor),
    approvalAboveUsd: formatUsd(policy.transfers.humanApprovalAboveMinor),
    payees: policy.transfers.allowedPayeeIds.join('\n'),
  };
}

const ISSUE_LABELS: Record<string, string> = {
  'reads.maxCalls': 'Reads per hour',
  'transfers.maxCalls': 'Transfers per 24 hours',
  'transfers.maxSingleMinor': 'Largest single transfer',
  'transfers.maxCumulativeMinor': 'Total transferred per 24 hours',
  'transfers.humanApprovalAboveMinor': 'Approval threshold',
  'transfers.allowedPayeeIds': 'Payees',
};

/**
 * Applies the editable fields to the current policy and validates the result with `Policy`.
 * Everything not on the form (resource, read rows, allow flags) is kept as is.
 */
export function readPolicyForm(
  form: PolicyFormValues,
  current: Policy,
): { ok: true; policy: Policy } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  const numbers = {} as Record<PolicyField, number>;
  for (const field of POLICY_FIELDS) {
    const value = field.kind === 'usd' ? parseUsd(form[field.name]) : parseCount(form[field.name]);
    if (value === null) {
      errors.push(
        field.kind === 'usd'
          ? `${field.label}: enter an amount like 75 or 75.01 (no signs, exponents or more than two decimals).`
          : `${field.label}: enter a whole number like 5.`,
      );
    } else {
      numbers[field.name] = value;
    }
  }
  if (errors.length > 0) return { ok: false, errors };

  const payees = form.payees.split(/[\s,]+/).filter((p) => p !== '');
  const parsed = Policy.safeParse({
    ...current,
    reads: { ...current.reads, maxCalls: numbers.readsPerHour, windowSec: 3600 },
    transfers: {
      ...current.transfers,
      maxCalls: numbers.transfersPerDay,
      windowSec: 86400,
      maxSingleMinor: numbers.maxSingleUsd,
      maxCumulativeMinor: numbers.maxTotalUsd,
      allowedPayeeIds: payees,
      humanApprovalAboveMinor: numbers.approvalAboveUsd,
    },
  });
  if (parsed.success) return { ok: true, policy: parsed.data };
  return {
    ok: false,
    errors: parsed.error.issues.map((issue) => {
      const label = ISSUE_LABELS[issue.path.slice(0, 2).join('.')];
      const index = issue.path[2];
      const value = typeof index === 'number' ? ` "${payees[index]}"` : '';
      return label ? `${label}${value}: ${issue.message}` : issue.message;
    }),
  };
}
