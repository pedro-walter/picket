import { globToRegExp } from './util';

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
}

export function extractCve(identifier: string): string | null {
  const m = identifier.match(/CVE-\d{4}-\d{3,}/i);
  return m ? m[0].toUpperCase() : null;
}

/**
 * First active suppression that covers this finding, or null.
 * A row matches when kind is equal and every configured glob matches;
 * `cve_glob` of "*" is ignored (not every finding has a CVE).
 */
export function matchSuppression(supps: Suppression[], f: ReportedFinding): Suppression | null {
  const cve = f.cve ?? extractCve(f.identifier);
  for (const s of supps) {
    if (s.kind !== f.kind) continue;
    if (!globToRegExp(s.subject_glob).test(f.subject)) continue;
    if (!globToRegExp(s.identifier_glob).test(f.identifier)) continue;
    if (s.cve_glob !== '*') {
      if (!cve || !globToRegExp(s.cve_glob).test(cve)) continue;
    }
    return s;
  }
  return null;
}
