import { describe, it, expect } from 'vitest';
import { matchSuppression, extractCve, type Suppression } from '../src/suppress';

const rule = (over: Partial<Suppression>): Suppression => ({
  id: 'r1',
  kind: 'image-cve',
  subject_glob: '*',
  identifier_glob: '*',
  cve_glob: '*',
  reason: 'unused code path',
  author: 'seed',
  created_at: '2026-09-08T00:00:00Z',
  expires_at: null,
  ...over,
});

describe('extractCve', () => {
  it('pulls a CVE id out of a compound identifier', () => {
    expect(extractCve('CVE-2026-14456|libssl3')).toBe('CVE-2026-14456');
    expect(extractCve('libssl3')).toBeNull();
  });
});

describe('matchSuppression', () => {
  const f = { kind: 'image-cve', subject: 'postgres', identifier: 'CVE-2026-14456|libssl3' };

  it('matches a package-scoped rule seeded from ignore/*.txt', () => {
    const supps = [rule({ subject_glob: 'postgres', identifier_glob: '*|libssl3' })];
    expect(matchSuppression(supps, f)?.id).toBe('r1');
  });

  it('does not match a different image', () => {
    const supps = [rule({ subject_glob: 'mongo', identifier_glob: '*|libssl3' })];
    expect(matchSuppression(supps, f)).toBeNull();
  });

  it('does not match a different package', () => {
    const supps = [rule({ subject_glob: 'postgres', identifier_glob: '*|stdlib' })];
    expect(matchSuppression(supps, f)).toBeNull();
  });

  it('honours cve_glob when set', () => {
    expect(matchSuppression([rule({ cve_glob: 'CVE-2026-14456' })], f)?.id).toBe('r1');
    expect(matchSuppression([rule({ cve_glob: 'CVE-2025-*' })], f)).toBeNull();
  });

  it('requires the kind to be equal', () => {
    expect(matchSuppression([rule({ kind: 'apt' })], f)).toBeNull();
  });
});
