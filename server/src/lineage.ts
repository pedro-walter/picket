import type { Env } from './index';
import { nowIso } from './util';
import {
  matchSuppressionVia,
  resolveAncestors,
  type StoredFinding,
  type Suppression,
} from './suppress';
import { maybeNotify, flushBatch, loadLineage } from './ingest';

export async function loadActiveSuppressions(env: Env, now = nowIso()): Promise<Suppression[]> {
  return (
    (await env.DB.prepare('SELECT * FROM suppressions WHERE expires_at IS NULL OR expires_at > ?').bind(now).all<Suppression>())
      .results ?? []
  );
}

interface FindingRow {
  fingerprint: string;
  agent_name: string;
  kind: string;
  subject: string;
  identifier: string;
  severity: string;
  title: string;
  detail: string | null;
  status: string;
  state_json: string | null;
}

/** Every open/acked/muted finding in the shape the matcher/preview/audit functions take. */
export async function loadStoredFindings(env: Env): Promise<StoredFinding[]> {
  const rows =
    (await env.DB.prepare(
      `SELECT f.fingerprint, a.name AS agent_name, f.kind, f.subject, f.identifier, f.severity, f.title, f.detail, f.status, f.state_json
       FROM findings f JOIN agents a ON a.id = f.agent_id
       WHERE f.status IN ('open','acked','muted')`,
    ).all<FindingRow>()).results ?? [];
  return rows.map((r) => {
    let fixed: string | undefined;
    try {
      fixed = (JSON.parse(r.state_json ?? 'null') as { last?: { fixed_version?: string } } | null)?.last?.fixed_version;
    } catch {
      /* state_json is advisory */
    }
    return {
      fingerprint: r.fingerprint,
      agent_name: r.agent_name,
      kind: r.kind,
      subject: r.subject,
      identifier: r.identifier,
      severity: r.severity,
      title: r.title,
      detail: r.detail ?? '',
      fixed_version: fixed,
      status: r.status,
    };
  });
}

export interface ReevalResult {
  muted: number;
  reopened: number;
}

/**
 * Bring stored findings in line with the active rules + lineage right now:
 * open/acked findings a rule covers become muted; muted findings no rule
 * covers any more (expired, deleted, lineage removed, rule narrowed) reopen.
 *
 * Ingest only re-evaluates findings that arrive in a report body, and
 * hash-gated sections rarely send one, so without this sweep an expired rule
 * would keep its findings muted indefinitely.
 */
export async function reevaluateFindings(env: Env): Promise<ReevalResult> {
  const now = nowIso();
  const [supps, lineage, findings] = await Promise.all([
    loadActiveSuppressions(env, now),
    loadLineage(env),
    loadStoredFindings(env),
  ]);

  const writes: D1PreparedStatement[] = [];
  const reopenedByAgent = new Map<string, StoredFinding[]>();
  let muted = 0;
  let reopened = 0;

  for (const f of findings) {
    const m = matchSuppressionVia(supps, f, resolveAncestors(lineage, f.subject));
    if (m && f.status !== 'muted') {
      writes.push(
        env.DB.prepare(
          "UPDATE findings SET status = 'muted', last_seen = ?, state_json = json_set(COALESCE(state_json,'{}'), '$.suppressed_by', ?, '$.suppressed_via', ?) WHERE fingerprint = ?",
        ).bind(now, m.rule.id, m.via, f.fingerprint),
        env.DB.prepare('DELETE FROM notifications WHERE fingerprint = ?').bind(f.fingerprint),
      );
      muted++;
    } else if (!m && f.status === 'muted') {
      writes.push(
        env.DB.prepare(
          "UPDATE findings SET status = 'open', last_seen = ?, state_json = json_set(COALESCE(state_json,'{}'), '$.suppressed_by', NULL, '$.suppressed_via', NULL) WHERE fingerprint = ?",
        ).bind(now, f.fingerprint),
        env.DB.prepare('DELETE FROM notifications WHERE fingerprint = ?').bind(f.fingerprint),
      );
      reopened++;
      const arr = reopenedByAgent.get(f.agent_name ?? '') ?? [];
      arr.push(f);
      reopenedByAgent.set(f.agent_name ?? '', arr);
    } else if (m && f.status === 'muted') {
      // still muted: keep the attribution current (rule id / inherited-from)
      writes.push(
        env.DB.prepare(
          "UPDATE findings SET state_json = json_set(COALESCE(state_json,'{}'), '$.suppressed_by', ?, '$.suppressed_via', ?) WHERE fingerprint = ? AND COALESCE(json_extract(state_json,'$.suppressed_by'),'') != ?",
        ).bind(m.rule.id, m.via, f.fingerprint, m.rule.id),
      );
    }
  }

  await flushBatch(env, writes);

  for (const [agentName, fs] of reopenedByAgent) {
    await maybeNotify(
      env,
      agentName,
      [],
      fs.map((f) => ({ ...f, fingerprint: f.fingerprint })),
      [],
      [],
    );
  }
  return { muted, reopened };
}
