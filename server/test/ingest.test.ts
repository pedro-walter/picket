import { describe, it, expect } from 'vitest';
import { shouldEscalate } from '../src/ingest';

describe('shouldEscalate', () => {
  it('true when an open finding gets strictly worse (high -> critical)', () => {
    expect(shouldEscalate('open', 'high', 'critical')).toBe(true);
  });

  it('true for an acked finding too - acking an old severity should not silence a worse one', () => {
    expect(shouldEscalate('acked', 'medium', 'high')).toBe(true);
  });

  it('false when severity improves but stays open (critical -> high)', () => {
    expect(shouldEscalate('open', 'critical', 'high')).toBe(false);
  });

  it('false when severity is unchanged', () => {
    expect(shouldEscalate('open', 'high', 'high')).toBe(false);
  });

  it('false for a muted finding - suppression is an explicit choice to stay quiet', () => {
    expect(shouldEscalate('muted', 'high', 'critical')).toBe(false);
  });

  it('false for a resolved or brand-new finding (no prior severity to compare against)', () => {
    expect(shouldEscalate('resolved', 'high', 'critical')).toBe(false);
    expect(shouldEscalate(undefined, undefined, 'critical')).toBe(false);
  });

  it('treats an unrecognized severity as worst-case low priority, so escalating into one never fires', () => {
    expect(shouldEscalate('open', 'high', 'unknown')).toBe(false);
  });
});
