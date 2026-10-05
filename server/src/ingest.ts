import type { Env } from './index';
import type { Agent } from './auth';
import { sha256Hex, uuid, nowIso, fingerprintInput } from './util';
import { matchSuppressionVia, resolveAncestors, type Lineage, type Suppression, type ReportedFinding } from './suppress';
import { sendReportEmail, type ResolvedItem } from './notify';

/**
 * A lower-cadence check group (image scan, daily). The agent sends `findings`
 * only when `hash` differs from what central last acknowledged; otherwise it
 * sends the hash alone and central refreshes freshness without re-diffing or
 * resolving anything the section covers.
 */
export interface ReportSection {
  hash: string;
  generated_at: string;
  checks_run: string[];
  findings?: ReportedFinding[];
  /** images the section's current scan covered (agent >= 0.3.0) */
  scans?: { ref: string; digest?: string }[];
}

export interface ReportPayload {
  agent_name: string;
  agent_version: string;
  arch?: string;
  sent_at?: string;
  /** CHEAP kinds evaluated this cycle - absence of a stored finding of a kind
   *  with current state (cheap, or a section whose body arrived) => resolved */
  checks_run: string[];
  findings: ReportedFinding[];
  metrics?: {
    cpu_pct?: number;
    mem_pct?: number;
    disk_pct?: number;
    mongo_data_gb?: number;
    registry_data_gb?: number;
    thresholds?: {
      cpu_pct?: number;
      mem_pct?: number;
      disk_pct?: number;
      mongo_data_gb?: number;
      registry_data_gb?: number;
    };
  };
  sections?: Record<string, ReportSection>;
  /** id of the rescan request the agent has finished (agent >= 0.5.0) */
  rescan_done?: string;
}

export interface SelfUpdateResponse {
  desired_version: string;
  url: string;
  sha256: string;
  sig_url: string;
}

export interface ReportResponse extends SelfUpdateResponse {
  /** section -> hash central now holds the full body for (stop resending) */
  sections_ack?: Record<string, string>;
  /** sections whose hash central does not recognise (resend the full body) */
  sections_need_body?: string[];
  /** operator-requested rescan; re-sent on every report until the agent echoes `rescan_done: id` */
  rescan?: { id: string; sections: string[] };
}

type FP = ReportedFinding & { fingerprint: string };

/** generated_at of the section body a finding arrived in (cheap findings have none) */
const bodyScannedAt = new WeakMap<ReportedFinding, string>();

const scansJson = (sec: ReportSection): string | null =>
  Array.isArray(sec.scans)
    ? JSON.stringify(sec.scans.map((s) => ({ ref: String(s.ref), digest: s.digest ? String(s.digest) : null })))
    : null;

// D1 caps bound parameters per statement near 100 and we keep each batch()
// transaction modest; a bulk first image scan is many hundreds of findings,
// and per-row round-trips there blow the agent's report timeout.
const D1_VARS = 90;
const D1_BATCH = 50;

export async function loadLineage(env: Env): Promise<Lineage> {
  const rows =
    (await env.DB.prepare('SELECT subject, upstream FROM image_lineage').all<{ subject: string; upstream: string }>())
      .results ?? [];
  return new Map(rows.map((r) => [r.subject, r.upstream]));
}

export async function flushBatch(env: Env, stmts: D1PreparedStatement[]): Promise<void> {
  for (let i = 0; i < stmts.length; i += D1_BATCH) {
    await env.DB.batch(stmts.slice(i, i + D1_BATCH));
  }
}

export async function ingestReport(env: Env, agent: Agent, payload: ReportPayload): Promise<ReportResponse> {
  const now = nowIso();

  await env.DB.batch([
    env.DB.prepare('INSERT INTO reports (id, agent_id, received_at, payload_json) VALUES (?, ?, ?, ?)').bind(
      uuid(),
      agent.id,
      now,
      JSON.stringify(payload),
    ),
    env.DB.prepare('UPDATE agents SET last_report_at = ?, agent_version = ? WHERE id = ?').bind(
      now,
      payload.agent_version ?? agent.agent_version,
      agent.id,
    ),
    env.DB.prepare('DELETE FROM notifications WHERE fingerprint = ?').bind(`offline:${agent.id}`),
  ]);

  if (payload.metrics) {
    const m = payload.metrics;
    await env.DB.prepare(
      `INSERT OR REPLACE INTO metrics (agent_id, ts, cpu_pct, mem_pct, disk_pct, mongo_data_gb, registry_data_gb)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        agent.id,
        now,
        m.cpu_pct ?? null,
        m.mem_pct ?? null,
        m.disk_pct ?? null,
        m.mongo_data_gb ?? null,
        m.registry_data_gb ?? null,
      )
      .run();
  }

  // ---- sections: decide which contribute current state this cycle ----
  const sectionsAck: Record<string, string> = {};
  const sectionsNeedBody: string[] = [];
  // kinds we have a complete current picture of this cycle (drives resolution)
  const kindsWithCurrentState = new Set(payload.checks_run ?? []);
  // findings to diff = cheap findings + any section bodies that arrived
  const toDiff: ReportedFinding[] = [...(payload.findings ?? [])];

  // ---- host-health: central evaluates the thresholds the agent forwarded ----
  if (payload.metrics) {
    kindsWithCurrentState.add('host-health');
    toDiff.push(...hostHealthFindings(payload.agent_name, payload.metrics));
  }

  for (const [name, sec] of Object.entries(payload.sections ?? {})) {
    if (Array.isArray(sec.findings)) {
      for (const k of sec.checks_run ?? []) kindsWithCurrentState.add(k);
      for (const f of sec.findings) bodyScannedAt.set(f, sec.generated_at ?? now);
      toDiff.push(...sec.findings);
      await env.DB.prepare(
        `INSERT OR REPLACE INTO agent_sections (agent_id, section, hash, generated_at, confirmed_at, scans_json)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
        .bind(agent.id, name, sec.hash, sec.generated_at ?? now, now, scansJson(sec))
        .run();
      sectionsAck[name] = sec.hash;
      continue;
    }

    const stored = await env.DB.prepare('SELECT hash FROM agent_sections WHERE agent_id = ? AND section = ?')
      .bind(agent.id, name)
      .first<{ hash: string }>();

    if (stored && stored.hash === sec.hash) {
      // fresh & unchanged: refresh freshness + last_seen; no diff, no resolution
      const stmts = [
        env.DB.prepare(
          'UPDATE agent_sections SET confirmed_at = ?, generated_at = ?, scans_json = COALESCE(?, scans_json) WHERE agent_id = ? AND section = ?',
        ).bind(now, sec.generated_at ?? now, scansJson(sec), agent.id, name),
      ];
      const kinds = sec.checks_run ?? [];
      if (kinds.length) {
        stmts.push(
          env.DB.prepare(
            `UPDATE findings SET last_seen = ? WHERE agent_id = ? AND status IN ('open','acked','muted')
             AND kind IN (${kinds.map(() => '?').join(',')})`,
          ).bind(now, agent.id, ...kinds),
        );
      }
      await env.DB.batch(stmts);
      sectionsAck[name] = sec.hash;
    } else {
      sectionsNeedBody.push(name);
    }
  }

  // ---- diff every finding we have current state for ----
  const supps =
    (await env.DB.prepare('SELECT * FROM suppressions WHERE expires_at IS NULL OR expires_at > ?').bind(now).all<Suppression>())
      .results ?? [];

  const lineage = await loadLineage(env);

  const reported = new Map<string, FP>();
  for (const f of toDiff) {
    const fp = await sha256Hex(fingerprintInput(f.kind, agent.name, f.subject, f.identifier));
    reported.set(fp, { ...f, fingerprint: fp });
    const sa = bodyScannedAt.get(f);
    if (sa) bodyScannedAt.set(reported.get(fp)!, sa);
  }

  // one read for every reported fingerprint up front, then a single batched
  // write pass below - see D1_VARS / D1_BATCH.
  const priorStatus = new Map<string, string>();
  const priorSeverity = new Map<string, string>();
  {
    const fps = [...reported.keys()];
    for (let i = 0; i < fps.length; i += D1_VARS) {
      const chunk = fps.slice(i, i + D1_VARS);
      const rows =
        (await env.DB.prepare(
          `SELECT fingerprint, status, severity FROM findings WHERE fingerprint IN (${chunk.map(() => '?').join(',')})`,
        )
          .bind(...chunk)
          .all<{ fingerprint: string; status: string; severity: string }>()).results ?? [];
      for (const r of rows) {
        priorStatus.set(r.fingerprint, r.status);
        priorSeverity.set(r.fingerprint, r.severity);
      }
    }
  }

  const opened: FP[] = [];
  const reopened: FP[] = [];
  const escalated: FP[] = [];
  const resolved: ResolvedItem[] = [];
  const writes: D1PreparedStatement[] = [];

  for (const [fp, f] of reported) {
    const existing = priorStatus.get(fp);
    const match = matchSuppressionVia(supps, f, resolveAncestors(lineage, f.subject));
    const supp = match?.rule ?? null;
    const sev = (f.severity ?? 'info').toLowerCase();
    const title = f.title ?? defaultTitle(f);
    const detail = f.detail ?? '';
    const stateJson = JSON.stringify({ last: f, suppressed_by: supp?.id ?? null, suppressed_via: match?.via ?? null });
    // cheap-tier and hash-only cycles carry no provenance and must not blank what the last scan recorded
    const prov = [f.image_ref ?? null, f.image_digest ?? null, bodyScannedAt.get(f) ?? null];
    // a finding from a body overwrites exactly (an older agent's body clears the ref rather than leaving a stale one)
    const PROV = bodyScannedAt.has(f)
      ? 'image_ref = ?, image_digest = ?, scanned_at = ?'
      : 'image_ref = COALESCE(?, image_ref), image_digest = COALESCE(?, image_digest), scanned_at = COALESCE(?, scanned_at)';

    if (existing === undefined) {
      const status = supp ? 'muted' : 'open';
      writes.push(
        env.DB.prepare(
          `INSERT INTO findings
             (fingerprint, agent_id, kind, subject, identifier, severity, title, detail, first_seen, last_seen, status, state_json,
              image_ref, image_digest, scanned_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).bind(fp, agent.id, f.kind, f.subject, f.identifier, sev, title, detail, now, now, status, stateJson, ...prov),
      );
      if (status === 'open') opened.push(f);
      continue;
    }

    if (existing === 'resolved') {
      const status = supp ? 'muted' : 'open';
      writes.push(
        env.DB.prepare(
          `UPDATE findings SET status = ?, last_seen = ?, severity = ?, title = ?, detail = ?, state_json = ?, ${PROV} WHERE fingerprint = ?`,
        ).bind(status, now, sev, title, detail, stateJson, ...prov, fp),
        env.DB.prepare('DELETE FROM notifications WHERE fingerprint = ?').bind(fp),
      );
      if (status === 'open') reopened.push(f);
      continue;
    }

    if (existing === 'muted' && !supp) {
      // the suppression rule that muted it is gone / expired -> back to open
      writes.push(
        env.DB.prepare(
          `UPDATE findings SET status = ?, last_seen = ?, severity = ?, title = ?, detail = ?, state_json = ?, ${PROV} WHERE fingerprint = ?`,
        ).bind('open', now, sev, title, detail, stateJson, ...prov, fp),
        env.DB.prepare('DELETE FROM notifications WHERE fingerprint = ?').bind(fp),
      );
      reopened.push(f);
      continue;
    }

    if ((existing === 'open' || existing === 'acked') && supp) {
      writes.push(
        env.DB.prepare(`UPDATE findings SET status = ?, last_seen = ?, state_json = ?, ${PROV} WHERE fingerprint = ?`).bind(
          'muted',
          now,
          stateJson,
          ...prov,
          fp,
        ),
      );
      continue;
    }

    // unchanged (open / acked / still-muted): bump last_seen, refresh display.
    // A worsening severity on an already-open/acked finding is still "the same
    // finding" (same fingerprint) but deserves a fresh alert - clear its prior
    // notification so maybeNotify treats it as fresh, without touching status.
    const isEscalation = shouldEscalate(existing, priorSeverity.get(fp), sev);

    writes.push(
      env.DB.prepare(
        `UPDATE findings SET last_seen = ?, severity = ?, title = ?, detail = ?, state_json = ?, ${PROV} WHERE fingerprint = ?`,
      ).bind(now, sev, title, detail, stateJson, ...prov, fp),
    );
    if (isEscalation) {
      writes.push(env.DB.prepare("DELETE FROM notifications WHERE fingerprint = ? AND kind = 'alert'").bind(fp));
      escalated.push(f);
    }
  }

  // ---- resolution: stored finding whose kind has current state but is absent ----
  const stored =
    (await env.DB.prepare(
      `SELECT fingerprint, kind, subject, identifier, title, status
       FROM findings WHERE agent_id = ? AND status IN ('open','acked','muted')`,
    )
      .bind(agent.id)
      .all<{ fingerprint: string; kind: string; subject: string; identifier: string; title: string; status: string }>())
      .results ?? [];

  for (const s of stored) {
    if (!kindsWithCurrentState.has(s.kind)) continue;
    if (reported.has(s.fingerprint)) continue;
    writes.push(
      env.DB.prepare("UPDATE findings SET status = 'resolved', last_seen = ? WHERE fingerprint = ?").bind(now, s.fingerprint),
      env.DB.prepare('DELETE FROM notifications WHERE fingerprint = ?').bind(s.fingerprint),
    );
    if (s.status === 'open') {
      resolved.push({ kind: s.kind, subject: s.subject, identifier: s.identifier, title: s.title });
    }
  }

  await flushBatch(env, writes);

  await maybeNotify(env, agent.name, opened, reopened, escalated, resolved);

  const resp: ReportResponse = { ...(await selfUpdateResponse(env, agent, payload.arch)) };
  const rescan = await pendingRescan(env, agent, payload.rescan_done);
  if (rescan) resp.rescan = rescan;
  if (Object.keys(sectionsAck).length) resp.sections_ack = sectionsAck;
  if (sectionsNeedBody.length) resp.sections_need_body = sectionsNeedBody;
  return resp;
}

/** Sections an operator may ask an agent to rescan ("all" = every section it has). */
export const RESCAN_SECTIONS = ['all', 'image-scan', 'daily'];

/**
 * The agent's pending rescan request, or null. A `done` echo matching the
 * request id clears it; the id guard means a request made after the agent
 * fetched the old one is not lost.
 */
async function pendingRescan(env: Env, agent: Agent, done?: string): Promise<ReportResponse['rescan'] | null> {
  if (!agent.rescan_id) return null;
  if (done && done === agent.rescan_id) {
    await env.DB.prepare(
      'UPDATE agents SET rescan_id = NULL, rescan_sections = NULL, rescan_requested_at = NULL WHERE id = ? AND rescan_id = ?',
    )
      .bind(agent.id, agent.rescan_id)
      .run();
    return null;
  }
  let sections: string[] = ['all'];
  try {
    sections = JSON.parse(agent.rescan_sections ?? '["all"]');
  } catch {
    /* fall back to all */
  }
  return { id: agent.rescan_id, sections };
}

export async function maybeNotify(
  env: Env,
  agentName: string,
  opened: FP[],
  reopened: FP[],
  escalated: FP[],
  resolved: ResolvedItem[],
): Promise<void> {
  const candidates = [
    ...opened.map((f) => ({ f, reason: 'new' as const })),
    ...reopened.map((f) => ({ f, reason: 'reopened' as const })),
    ...escalated.map((f) => ({ f, reason: 'escalated' as const })),
  ];

  const alreadySent = new Set<string>();
  {
    const fps = candidates.map((c) => c.f.fingerprint);
    for (let i = 0; i < fps.length; i += D1_VARS) {
      const chunk = fps.slice(i, i + D1_VARS);
      const rows =
        (await env.DB.prepare(
          `SELECT fingerprint FROM notifications
           WHERE kind = 'alert' AND channel = 'email' AND fingerprint IN (${chunk.map(() => '?').join(',')})`,
        )
          .bind(...chunk)
          .all<{ fingerprint: string }>()).results ?? [];
      for (const r of rows) alreadySent.add(r.fingerprint);
    }
  }
  const fresh = candidates.filter((c) => !alreadySent.has(c.f.fingerprint));

  const notifyResolved = (env.NOTIFY_RESOLVED ?? 'true') === 'true';
  if (fresh.length === 0 && !(notifyResolved && resolved.length > 0)) return;

  const sent = await sendReportEmail(
    env,
    agentName,
    fresh.map((x) => ({ finding: x.f, reason: x.reason })),
    notifyResolved ? resolved : [],
  );
  if (!sent) return; // don't mark as notified — retry on the next report

  const stamp = nowIso();
  await flushBatch(
    env,
    fresh.map((x) =>
      env.DB.prepare(
        "INSERT OR IGNORE INTO notifications (fingerprint, sent_at, channel, kind) VALUES (?, ?, 'email', 'alert')",
      ).bind(x.f.fingerprint, stamp),
    ),
  );
}

/**
 * When a suppression rule is created (picketctl rules add / seed-ignores),
 * retroactively mute the open/acked findings it now covers - matching the
 * immediate effect of the dashboard's per-finding mute. Returns the count.
 */
export async function applyNewSuppression(env: Env, rule: Suppression): Promise<number> {
  const rows =
    (await env.DB.prepare(
      "SELECT fingerprint, kind, subject, identifier, detail, state_json FROM findings WHERE kind = ? AND status IN ('open','acked')",
    )
      .bind(rule.kind)
      .all<{ fingerprint: string; kind: string; subject: string; identifier: string; detail: string | null; state_json: string | null }>())
      .results ?? [];
  const lineage = await loadLineage(env);

  const now = nowIso();
  const writes: D1PreparedStatement[] = [];
  for (const r of rows) {
    let fixed: string | undefined;
    try {
      fixed = (JSON.parse(r.state_json ?? 'null') as { last?: { fixed_version?: string } } | null)?.last?.fixed_version;
    } catch {
      /* advisory */
    }
    if (!matchSuppressionVia([rule], { ...r, detail: r.detail ?? '', fixed_version: fixed }, resolveAncestors(lineage, r.subject))) continue;
    writes.push(
      env.DB.prepare("UPDATE findings SET status = 'muted', last_seen = ? WHERE fingerprint = ?").bind(now, r.fingerprint),
      env.DB.prepare('DELETE FROM notifications WHERE fingerprint = ?').bind(r.fingerprint),
    );
  }
  await flushBatch(env, writes);
  return writes.length / 2;
}

interface ReleaseRow {
  version: string;
  url_amd64: string;
  sha256_amd64: string;
  sig_url_amd64: string;
  url_arm64: string | null;
  sha256_arm64: string | null;
  sig_url_arm64: string | null;
}

async function selfUpdateResponse(env: Env, agent: Agent, arch?: string): Promise<SelfUpdateResponse> {
  const dv = agent.desired_version ?? env.DEFAULT_DESIRED_VERSION;
  const rel = await env.DB.prepare('SELECT * FROM releases WHERE version = ?').bind(dv).first<ReleaseRow>();
  if (!rel) {
    // no registered release for the desired version -> version only, no
    // url/sha => the agent will not swap (see selfupdate.Apply).
    return { desired_version: dv, url: '', sha256: '', sig_url: '' };
  }
  const a = arch === 'arm64' ? 'arm64' : 'amd64';
  return {
    desired_version: dv,
    url: (a === 'arm64' ? rel.url_arm64 : rel.url_amd64) ?? rel.url_amd64,
    sha256: (a === 'arm64' ? rel.sha256_arm64 : rel.sha256_amd64) ?? rel.sha256_amd64,
    sig_url: (a === 'arm64' ? rel.sig_url_arm64 : rel.sig_url_amd64) ?? rel.sig_url_amd64,
  };
}

type Metrics = NonNullable<ReportPayload['metrics']>;

/** Synthetic host-health findings for any metric at/over its threshold. */
function hostHealthFindings(agentName: string, m: Metrics): ReportedFinding[] {
  const t = m.thresholds ?? {};
  const thr = (v: number | undefined, dflt: number) => (typeof v === 'number' && v > 0 ? v : dflt);
  const out: ReportedFinding[] = [];
  const add = (id: string, sev: string, title: string, detail: string) =>
    out.push({ kind: 'host-health', subject: 'system', identifier: id, severity: sev, title: `${agentName}: ${title}`, detail });

  const pct = (id: string, label: string, val: number | undefined, threshold: number, hiAt = 95) => {
    if (typeof val !== 'number' || val < threshold) return;
    add(id, val >= hiAt ? 'critical' : 'high', `${label} ${val.toFixed(0)}% (≥ ${threshold}%)`, `${label} at ${val}%`);
  };
  const gb = (id: string, label: string, val: number | undefined, threshold: number | undefined) => {
    if (typeof val !== 'number' || !threshold || val < threshold) return;
    add(id, 'high', `${label} ${val.toFixed(1)} GB (≥ ${threshold} GB)`, `${label} at ${val} GB`);
  };

  pct('disk', 'disk usage', m.disk_pct, thr(t.disk_pct, 85));
  pct('cpu', 'CPU usage', m.cpu_pct, thr(t.cpu_pct, 90));
  pct('mem', 'RAM usage', m.mem_pct, thr(t.mem_pct, 90));
  gb('mongo_data', 'mongo_data size', m.mongo_data_gb, t.mongo_data_gb);
  gb('registry_data', 'registry_data size', m.registry_data_gb, t.registry_data_gb);
  return out;
}

// Lower rank = worse. Matches the ordering dashboard.ts sorts findings by.
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const severityRank = (s: string): number => SEVERITY_RANK[s.toLowerCase()] ?? 4;

/**
 * True when a still-open/acked finding's severity got worse since it was last
 * stored - e.g. disk usage crossing from "high" to "critical" while the
 * fingerprint (kind+subject+identifier) stays the same. Muted findings are
 * excluded: suppression is an explicit choice to stop alerting on them.
 */
export function shouldEscalate(status: string | undefined, priorSeverity: string | undefined, newSeverity: string): boolean {
  if (status !== 'open' && status !== 'acked') return false;
  if (priorSeverity === undefined) return false;
  return severityRank(newSeverity) < severityRank(priorSeverity);
}

function defaultTitle(f: ReportedFinding): string {
  switch (f.kind) {
    case 'image-cve':
      return `${f.subject}: ${f.identifier}`;
    case 'image-tag':
      return f.identifier.endsWith('->rebuilt')
        ? `${f.subject}: pinned tag rebuilt upstream (${f.identifier})`
        : `${f.subject}: newer tag available (${f.identifier})`;
    case 'apt':
      return `apt: ${f.identifier || 'updates pending'}`;
    case 'reboot':
      return `${f.subject || 'host'}: reboot required`;
    case 'container-stale':
      return `${f.subject}: container running a stale image`;
    case 'host-health':
      return `${f.subject}: ${f.identifier}`;
    case 'cert-expiry':
      return `${f.subject}: TLS certificate ${f.identifier}`;
    default:
      return `${f.kind}: ${f.subject} ${f.identifier}`.trim();
  }
}
