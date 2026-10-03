import { globToRegExp } from './util';

export type Inherit = 'none' | 'unfixed' | 'all';

export interface Suppression {
  id: string;
  kind: string;
  subject_glob: string;
  identifier_glob: string;
  cve_glob: string;
  reason: string;
  author: string;
  created_at: string;
  expires_at: string | null;
  /** how far the rule reaches along image lineage; absent/unknown => 'none' */
  inherit?: Inherit | string;
}

export interface ReportedFinding {
  kind: string;
  subject: string;
  identifier: string;
  severity?: string;
  title?: string;
  detail?: string;
  /** optional explicit CVE id; otherwise parsed out of `identifier` */
  cve?: string;
  /** optional structured fix version (newer agents); otherwise read off `detail` */
  fixed_version?: string;
  /** scan provenance (agent >= 0.3.0): the pinned ref scanned and that scan's digest */
  image_ref?: string;
  image_digest?: string;
}

/** child subject -> upstream subject */
export type Lineage = Map<string, string>;

export interface SuppressionMatch {
  rule: Suppression;
  /** the ancestor subject the rule matched through; null for a direct match */
  via: string | null;
}

const MAX_LINEAGE_DEPTH = 5;

export function extractCve(identifier: string): string | null {
  const m = identifier.match(/CVE-\d{4}-\d{3,}/i);
  return m ? m[0].toUpperCase() : null;
}

/** True when the finding says a fixed version is published (structured field, else trivy's "-> fixed in X"). */
export function hasPublishedFix(f: ReportedFinding): boolean {
  if (f.fixed_version && f.fixed_version.trim() !== '') return true;
  return /->\s*fixed in\s+\S/i.test(f.detail ?? '');
}

export const VENDORED_SUFFIX = '@vendored';

/**
 * Agents >= 0.4.0 tag a python copy vendored inside another package (pip's
 * `_vendor`) as `CVE|pkg@vendored`. Rules written before that split say
 * `*|pkg`, so a rule is also tried against the identifier with the suffix
 * stripped: legacy rules keep covering vendored copies, while a rule that
 * spells `@vendored` cannot reach a top-level copy.
 */
export function legacyIdentifier(identifier: string): string {
  return identifier.endsWith(VENDORED_SUFFIX) ? identifier.slice(0, -VENDORED_SUFFIX.length) : identifier;
}

/** Ancestors of `subject`, nearest first. Cycle-safe and depth-capped. */
export function resolveAncestors(lineage: Lineage, subject: string): string[] {
  const out: string[] = [];
  const seen = new Set([subject]);
  let cur = subject;
  for (let i = 0; i < MAX_LINEAGE_DEPTH; i++) {
    const up = lineage.get(cur);
    if (up === undefined || seen.has(up)) break;
    out.push(up);
    seen.add(up);
    cur = up;
  }
  return out;
}

/** Would adding subject -> upstream make the lineage cyclic (or self-referential)? */
export function wouldCreateCycle(lineage: Lineage, subject: string, upstream: string): boolean {
  if (subject === upstream) return true;
  const next = new Map(lineage);
  next.set(subject, upstream);
  let cur = upstream;
  for (let i = 0; i <= next.size; i++) {
    if (cur === subject) return true;
    const up = next.get(cur);
    if (up === undefined) return false;
    cur = up;
  }
  return true;
}

/**
 * First active suppression that covers this finding, with how it got there.
 *
 * A rule matches when kind is equal and every configured glob matches;
 * `cve_glob` of "*" is ignored (not every finding has a CVE). The subject glob
 * is tested against the finding's own subject, and - only for rules that opted
 * in with inherit != 'none' - against its lineage ancestors. An 'unfixed' rule
 * is never inherited by a finding that has a published fix.
 */
export function matchSuppressionVia(
  supps: Suppression[],
  f: ReportedFinding,
  ancestors: string[] = [],
): SuppressionMatch | null {
  const cve = f.cve ?? extractCve(f.identifier);
  for (const s of supps) {
    if (s.kind !== f.kind) continue;

    let via: string | null = null;
    if (!globToRegExp(s.subject_glob).test(f.subject)) {
      const inherit = s.inherit ?? 'none';
      if (inherit !== 'unfixed' && inherit !== 'all') continue;
      if (inherit === 'unfixed' && hasPublishedFix(f)) continue;
      const re = globToRegExp(s.subject_glob);
      const hit = ancestors.find((a) => re.test(a));
      if (hit === undefined) continue;
      via = hit;
    }

    const idRe = globToRegExp(s.identifier_glob);
    if (!idRe.test(f.identifier) && !idRe.test(legacyIdentifier(f.identifier))) continue;
    if (s.cve_glob !== '*') {
      if (!cve || !globToRegExp(s.cve_glob).test(cve)) continue;
    }
    return { rule: s, via };
  }
  return null;
}

/** Back-compat wrapper: the matching rule, or null. */
export function matchSuppression(supps: Suppression[], f: ReportedFinding, ancestors: string[] = []): Suppression | null {
  return matchSuppressionVia(supps, f, ancestors)?.rule ?? null;
}

// ---- preview / audit (pure; the endpoints feed these rows from D1) ----

export interface StoredFinding extends ReportedFinding {
  fingerprint: string;
  agent_name?: string;
  status: string;
}

export interface LineageChange {
  fingerprint: string;
  agent_name?: string;
  kind: string;
  subject: string;
  identifier: string;
  from: string;
  to: 'muted' | 'open';
  rule_id: string | null;
  reason: string | null;
  expires_at: string | null;
  via: string | null;
}

/**
 * What changes if the lineage goes from `before` to `after`: findings that
 * are open/acked/muted and would flip muted<->open purely because their
 * suppression match changes. Writes nothing.
 */
export function diffLineage(supps: Suppression[], findings: StoredFinding[], before: Lineage, after: Lineage): LineageChange[] {
  const out: LineageChange[] = [];
  for (const f of findings) {
    if (f.status !== 'open' && f.status !== 'acked' && f.status !== 'muted') continue;
    const b = matchSuppressionVia(supps, f, resolveAncestors(before, f.subject));
    const a = matchSuppressionVia(supps, f, resolveAncestors(after, f.subject));
    if (!!b === !!a) continue;
    const to = a ? 'muted' : 'open';
    if (to === 'muted' && f.status === 'muted') continue; // already muted (by other means)
    if (to === 'open' && f.status !== 'muted') continue;
    out.push({
      fingerprint: f.fingerprint,
      agent_name: f.agent_name,
      kind: f.kind,
      subject: f.subject,
      identifier: f.identifier,
      from: f.status,
      to,
      rule_id: a?.rule.id ?? b?.rule.id ?? null,
      reason: a?.rule.reason ?? null,
      expires_at: a?.rule.expires_at ?? null,
      via: a?.via ?? null,
    });
  }
  return out;
}

export interface RuleAudit {
  id: string;
  kind: string;
  subject_glob: string;
  identifier_glob: string;
  cve_glob: string;
  inherit: string;
  expires_at: string | null;
  expired: boolean;
  no_expiry: boolean;
  matches_direct: number;
  matches_inherited: number;
  /** a non-resolved finding exists on a subject this rule's glob reaches (directly, or via lineage if it inherits) */
  subject_live: boolean;
  /** another active rule on a lineage descendant of this rule's subject with the same kind/identifier/cve globs */
  twin_id: string | null;
  dead: boolean;
}

/** Per-rule view for `picketctl rules audit`: what each rule matches today, and which are dead/duplicated. */
export function auditRules(supps: Suppression[], findings: StoredFinding[], lineage: Lineage, now: string): RuleAudit[] {
  const live = findings.filter((f) => f.status === 'open' || f.status === 'acked' || f.status === 'muted');
  const active = (s: Suppression) => s.expires_at === null || s.expires_at > now;
  const descendantsOf = (glob: string): string[] => {
    const re = globToRegExp(glob);
    return [...lineage.keys()].filter((sub) => resolveAncestors(lineage, sub).some((a) => re.test(a)));
  };

  return supps.map((s) => {
    const re = globToRegExp(s.subject_glob);
    let direct = 0;
    let inherited = 0;
    let subjectLive = false;
    for (const f of live) {
      // judge each rule in isolation: would it, alone, cover this finding?
      const m = matchSuppressionVia([s], f, resolveAncestors(lineage, f.subject));
      if (m) (m.via === null ? direct++ : inherited++);
      if (re.test(f.subject) || (m && m.via !== null)) subjectLive = true;
    }
    const desc = descendantsOf(s.subject_glob);
    const twin = supps.find(
      (o) =>
        o.id !== s.id &&
        active(o) &&
        o.kind === s.kind &&
        o.identifier_glob === s.identifier_glob &&
        o.cve_glob === s.cve_glob &&
        desc.some((d) => globToRegExp(o.subject_glob).test(d)),
    );
    return {
      id: s.id,
      kind: s.kind,
      subject_glob: s.subject_glob,
      identifier_glob: s.identifier_glob,
      cve_glob: s.cve_glob,
      inherit: s.inherit ?? 'none',
      expires_at: s.expires_at,
      expired: s.expires_at !== null && s.expires_at <= now,
      no_expiry: s.expires_at === null,
      matches_direct: direct,
      matches_inherited: inherited,
      subject_live: subjectLive,
      twin_id: twin?.id ?? null,
      dead: direct + inherited === 0,
    };
  });
}
