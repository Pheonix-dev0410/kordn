import { describe, expect, it } from 'vitest';
import { IpcRequest } from '../src';

describe('IPC frames', () => {
  it('carries no identity or approval fields from the agent', () => {
    const frame = { v: 1, id: 'c1', tool: 'af_get_balance', args: {} };
    expect(IpcRequest.safeParse(frame).success).toBe(true);
    expect(IpcRequest.safeParse({ ...frame, agentId: 'x' }).success).toBe(false);
    expect(IpcRequest.safeParse({ ...frame, policyApproved: true }).success).toBe(false);
  });
});
