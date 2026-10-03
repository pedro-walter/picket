import { describe, it, expect } from 'vitest';
import {
  matchSuppression,
  matchSuppressionVia,
  extractCve,
  hasPublishedFix,
  resolveAncestors,
  wouldCreateCycle,
  diffLineage,
  auditRules,
  type Suppression,
  type StoredFinding,
  type Lineage,
} from '../src/suppress';

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

const UP = 'healthchecks/healthchecks';
const OV = 'docker.souspike.com.br/healthchecks/healthchecks';
const lineage: Lineage = new Map([[OV, UP]]);
const ovFinding = (over: Record<string, unknown> = {}) => ({
  kind: 'image-cve',
  subject: OV,
  identifier: 'CVE-2026-44168|libmariadb3',
  detail: 'x:4.4-2 (debian 13.6): libmariadb3 11.8',
  ...over,
});

describe('hasPublishedFix', () => {
  it('reads the structured field first, then trivy detail text', () => {
    expect(hasPublishedFix({ kind: 'image-cve', subject: 's', identifier: 'i', fixed_version: '2.8.0' })).toBe(true);
    expect(hasPublishedFix(ovFinding({ detail: 'pkg 1.0 -> fixed in 1.1; title' }) as never)).toBe(true);
    expect(hasPublishedFix(ovFinding() as never)).toBe(false);
    expect(hasPublishedFix(ovFinding({ detail: 'pkg 1.0 -> fixed in ' }) as never)).toBe(false);
  });
});

describe('lineage inheritance', () => {
  const up = (over: Partial<Suppression> = {}) =>
    rule({ subject_glob: UP, identifier_glob: '*|libmariadb3', ...over });

  it('default (inherit none / absent) never reaches an overlay - existing rules unchanged', () => {
    expect(matchSuppression([up()], ovFinding() as never, resolveAncestors(lineage, OV))).toBeNull();
    expect(matchSuppression([up({ inherit: 'none' })], ovFinding() as never, resolveAncestors(lineage, OV))).toBeNull();
  });

  it('inherit=all covers the overlay, keeps the original rule and records the ancestor it matched through', () => {
    const m = matchSuppressionVia([up({ inherit: 'all', expires_at: '2026-12-01T00:00:00Z' })], ovFinding() as never, resolveAncestors(lineage, OV));
    expect(m?.rule.id).toBe('r1');
    expect(m?.rule.expires_at).toBe('2026-12-01T00:00:00Z');
    expect(m?.via).toBe(UP);
  });

  it('a direct match reports via=null', () => {
    const m = matchSuppressionVia([up({ inherit: 'all' })], { ...ovFinding(), subject: UP } as never, []);
    expect(m?.via).toBeNull();
  });

  it('inherit=unfixed covers an unfixed finding but not one with a published fix (detail or structured)', () => {
    const r = [up({ inherit: 'unfixed' })];
    const anc = resolveAncestors(lineage, OV);
    expect(matchSuppression(r, ovFinding() as never, anc)?.id).toBe('r1');
    expect(matchSuppression(r, ovFinding({ detail: 'libmariadb3 11.8 -> fixed in 11.9' }) as never, anc)).toBeNull();
    expect(matchSuppression(r, ovFinding({ fixed_version: '11.9' }) as never, anc)).toBeNull();
  });

  it('inherit=all still covers a finding that has a fix (reachability rules, e.g. pip-vendored copies)', () => {
    const r = [up({ inherit: 'all', identifier_glob: '*|setuptools' })];
    const f = ovFinding({ identifier: 'CVE-2025-47273|setuptools', detail: 'setuptools 70.3.0 -> fixed in 78.1.1' });
    expect(matchSuppression(r, f as never, resolveAncestors(lineage, OV))?.id).toBe('r1');
  });

  it('still requires identifier/cve globs to match when inherited', () => {
    const r = [up({ inherit: 'all', cve_glob: 'CVE-2025-*' })];
    expect(matchSuppression(r, ovFinding() as never, resolveAncestors(lineage, OV))).toBeNull();
  });

  it('does not go the other way: a rule on the overlay does not touch the upstream image', () => {
    const r = [rule({ subject_glob: OV, identifier_glob: '*|libmariadb3', inherit: 'all' })];
    expect(matchSuppression(r, { ...ovFinding(), subject: UP } as never, resolveAncestors(lineage, UP))).toBeNull();
  });

  it('is transitive (overlay of an overlay) and depth-capped / cycle-safe', () => {
    const l: Lineage = new Map([['c', 'b'], ['b', 'a']]);
    expect(resolveAncestors(l, 'c')).toEqual(['b', 'a']);
    const cyc: Lineage = new Map([['a', 'b'], ['b', 'a']]);
    expect(resolveAncestors(cyc, 'a')).toEqual(['b']);
    const long: Lineage = new Map(Array.from({ length: 20 }, (_, i) => [`n${i}`, `n${i + 1}`] as [string, string]));
    expect(resolveAncestors(long, 'n0').length).toBe(5);
  });

  it('wouldCreateCycle rejects self-edges and cycles, allows chains', () => {
    const l: Lineage = new Map([['b', 'a']]);
    expect(wouldCreateCycle(l, 'x', 'x')).toBe(true);
    expect(wouldCreateCycle(l, 'a', 'b')).toBe(true);
    expect(wouldCreateCycle(l, 'c', 'b')).toBe(false);
  });
});

describe('diffLineage (preview)', () => {
  const stored = (over: Partial<StoredFinding>): StoredFinding => ({
    fingerprint: 'fp',
    status: 'open',
    ...(ovFinding() as object),
    ...over,
  } as StoredFinding);

  it('lists only the findings an added edge would newly mute, and never touches fixable ones', () => {
    const rules = [rule({ id: 'nofix', subject_glob: UP, identifier_glob: '*|libmariadb3', inherit: 'unfixed' })];
    const findings = [
      stored({ fingerprint: 'a' }),
      stored({ fingerprint: 'b', detail: 'libmariadb3 -> fixed in 9' }),
      stored({ fingerprint: 'c', identifier: 'CVE-1-1|other' }),
      stored({ fingerprint: 'd', status: 'resolved' }),
      stored({ fingerprint: 'e', status: 'muted' }),
    ];
    const changes = diffLineage(rules, findings, new Map(), lineage);
    expect(changes.map((c) => c.fingerprint)).toEqual(['a']);
    expect(changes[0]).toMatchObject({ to: 'muted', rule_id: 'nofix', via: UP });
  });

  it('removing an edge reports the muted findings that would reopen', () => {
    const rules = [rule({ id: 'x', subject_glob: UP, identifier_glob: '*|libmariadb3', inherit: 'all' })];
    const changes = diffLineage(rules, [stored({ fingerprint: 'm', status: 'muted' })], lineage, new Map());
    expect(changes).toHaveLength(1);
    expect(changes[0]).toMatchObject({ fingerprint: 'm', to: 'open' });
  });
});

describe('auditRules', () => {
  const NOW = '2026-10-02T00:00:00Z';
  const f = (over: Partial<StoredFinding>): StoredFinding =>
    ({ fingerprint: 'f', status: 'muted', ...(ovFinding() as object), ...over }) as StoredFinding;

  it('flags dead rules with an overlay twin and counts no-expiry', () => {
    const dead = rule({ id: 'old', subject_glob: UP, identifier_glob: '*|libmariadb3', expires_at: null });
    const twin = rule({ id: 'new', subject_glob: OV, identifier_glob: '*|libmariadb3', expires_at: '2026-12-01T00:00:00Z' });
    const out = auditRules([dead, twin], [f({})], lineage, NOW);
    const d = out.find((r) => r.id === 'old')!;
    expect(d).toMatchObject({ dead: true, twin_id: 'new', no_expiry: true, matches_direct: 0, matches_inherited: 0 });
    expect(out.find((r) => r.id === 'new')).toMatchObject({ dead: false, matches_direct: 1, twin_id: null });
  });

  it('counts inherited matches for an opted-in rule and marks expired rules', () => {
    const r = rule({ id: 'inh', subject_glob: UP, identifier_glob: '*|libmariadb3', inherit: 'all', expires_at: '2026-01-01T00:00:00Z' });
    const out = auditRules([r], [f({})], lineage, NOW);
    expect(out[0]).toMatchObject({ matches_inherited: 1, dead: false, expired: true, subject_live: true });
  });
});

describe('vendored identifier shim', () => {
  const V = { kind: 'image-cve', subject: 'x', identifier: 'CVE-2025-47273|setuptools@vendored' };
  const T = { kind: 'image-cve', subject: 'x', identifier: 'CVE-2025-47273|setuptools' };

  it('a legacy *|pkg rule keeps covering the vendored copy and the top-level copy', () => {
    const r = [rule({ subject_glob: 'x', identifier_glob: '*|setuptools' })];
    expect(matchSuppression(r, V)?.id).toBe('r1');
    expect(matchSuppression(r, T)?.id).toBe('r1');
  });

  it('a *|pkg@vendored rule covers only the vendored copy', () => {
    const r = [rule({ subject_glob: 'x', identifier_glob: '*|setuptools@vendored' })];
    expect(matchSuppression(r, V)?.id).toBe('r1');
    expect(matchSuppression(r, T)).toBeNull();
  });

  it('cve globs and other packages are unaffected', () => {
    expect(matchSuppression([rule({ subject_glob: 'x', identifier_glob: '*|setuptools', cve_glob: 'CVE-1-*' })], V)).toBeNull();
    expect(matchSuppression([rule({ subject_glob: 'x', identifier_glob: '*|msgpack' })], V)).toBeNull();
  });
});
