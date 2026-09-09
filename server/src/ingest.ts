import type { Env } from './index';
import type { Agent } from './auth';
import { sha256Hex, uuid, nowIso, fingerprintInput } from './util';
import { matchSuppression, type Suppression, type ReportedFinding } from './suppress';
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
}

type FP = ReportedFinding & { fingerprint: string };

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
      toDiff.push(...sec.findings);
      await env.DB.prepare(
        `INSERT OR REPLACE INTO agent_sections (agent_id, section, hash, generated_at, confirmed_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
        .bind(agent.id, name, sec.hash, sec.generated_at ?? now, now)
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
        env.DB.prepare('UPDATE agent_sections SET confirmed_at = ?, generated_at = ? WHERE agent_id = ? AND section = ?').bind(
          now,
          sec.generated_at ?? now,
          agent.id,
          name,
        ),
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

  const reported = new Map<string, FP>();
  for (const f of toDiff) {
    const fp = await sha256Hex(fingerprintInput(f.kind, agent.name, f.subject, f.identifier));
    reported.set(fp, { ...f, fingerprint: fp });
  }

  const opened: FP[] = [];
  const reopened: FP[] = [];
  const resolved: ResolvedItem[] = [];

  for (const [fp, f] of reported) {
    const existing = await env.DB.prepare('SELECT status FROM findings WHERE fingerprint = ?')
      .bind(fp)
      .first<{ status: string }>();
    const supp = matchSuppression(supps, f);
    const sev = (f.severity ?? 'info').toLowerCase();
    const title = f.title ?? defaultTitle(f);
    const detail = f.detail ?? '';
    const stateJson = JSON.stringify({ last: f, suppressed_by: supp?.id ?? null });

    if (!existing) {
      const status = supp ? 'muted' : 'open';
      await env.DB.prepare(
        `INSERT INTO findings
           (fingerprint, agent_id, kind, subject, identifier, severity, title, detail, first_seen, last_seen, status, state_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(fp, agent.id, f.kind, f.subject, f.identifier, sev, title, detail, now, now, status, stateJson)
        .run();
      if (status === 'open') opened.push(f);
      continue;
    }

    if (existing.status === 'resolved') {
      const status = supp ? 'muted' : 'open';
      await env.DB.batch([
        env.DB.prepare(
          'UPDATE findings SET status = ?, last_seen = ?, severity = ?, title = ?, detail = ?, state_json = ? WHERE fingerprint = ?',
        ).bind(status, now, sev, title, detail, stateJson, fp),
        env.DB.prepare('DELETE FROM notifications WHERE fingerprint = ?').bind(fp),
      ]);
      if (status === 'open') reopened.push(f);
      continue;
    }

    if (existing.status === 'muted' && !supp) {
      // the suppression rule that muted it is gone / expired -> back to open
      await env.DB.batch([
        env.DB.prepare(
          'UPDATE findings SET status = ?, last_seen = ?, severity = ?, title = ?, detail = ?, state_json = ? WHERE fingerprint = ?',
        ).bind('open', now, sev, title, detail, stateJson, fp),
        env.DB.prepare('DELETE FROM notifications WHERE fingerprint = ?').bind(fp),
      ]);
      reopened.push(f);
      continue;
    }

    if ((existing.status === 'open' || existing.status === 'acked') && supp) {
      await env.DB.prepare('UPDATE findings SET status = ?, last_seen = ?, state_json = ? WHERE fingerprint = ?')
        .bind('muted', now, stateJson, fp)
        .run();
      continue;
    }

    // unchanged (open / acked / still-muted): bump last_seen, refresh display
    await env.DB.prepare(
      'UPDATE findings SET last_seen = ?, severity = ?, title = ?, detail = ?, state_json = ? WHERE fingerprint = ?',
    )
      .bind(now, sev, title, detail, stateJson, fp)
      .run();
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
    await env.DB.batch([
      env.DB.prepare("UPDATE findings SET status = 'resolved', last_seen = ? WHERE fingerprint = ?").bind(now, s.fingerprint),
      env.DB.prepare('DELETE FROM notifications WHERE fingerprint = ?').bind(s.fingerprint),
    ]);
    if (s.status === 'open') {
      resolved.push({ kind: s.kind, subject: s.subject, identifier: s.identifier, title: s.title });
    }
  }

  await maybeNotify(env, agent.name, opened, reopened, resolved);

  const resp: ReportResponse = { ...(await selfUpdateResponse(env, agent, payload.arch)) };
  if (Object.keys(sectionsAck).length) resp.sections_ack = sectionsAck;
  if (sectionsNeedBody.length) resp.sections_need_body = sectionsNeedBody;
  return resp;
}

async function maybeNotify(
  env: Env,
  agentName: string,
  opened: FP[],
  reopened: FP[],
  resolved: ResolvedItem[],
): Promise<void> {
  const candidates = [
    ...opened.map((f) => ({ f, reason: 'new' as const })),
    ...reopened.map((f) => ({ f, reason: 'reopened' as const })),
  ];

  const fresh: { f: FP; reason: 'new' | 'reopened' }[] = [];
  for (const c of candidates) {
    const already = await env.DB.prepare(
      "SELECT 1 FROM notifications WHERE fingerprint = ? AND kind = 'alert' AND channel = 'email'",
    )
      .bind(c.f.fingerprint)
      .first();
    if (!already) fresh.push(c);
  }

  const notifyResolved = (env.NOTIFY_RESOLVED ?? 'true') === 'true';
  if (fresh.length === 0 && !(notifyResolved && resolved.length > 0)) return;

  await sendReportEmail(
    env,
    agentName,
    fresh.map((x) => ({ finding: x.f, reason: x.reason })),
    notifyResolved ? resolved : [],
  );

  const stamp = nowIso();
  for (const x of fresh) {
    await env.DB.prepare(
      "INSERT OR IGNORE INTO notifications (fingerprint, sent_at, channel, kind) VALUES (?, ?, 'email', 'alert')",
    )
      .bind(x.f.fingerprint, stamp)
      .run();
  }
}

/**
 * When a suppression rule is created (picketctl rules add / seed-ignores),
 * retroactively mute the open/acked findings it now covers - matching the
 * immediate effect of the dashboard's per-finding mute. Returns the count.
 */
export async function applyNewSuppression(env: Env, rule: Suppression): Promise<number> {
  const rows =
    (await env.DB.prepare(
      "SELECT fingerprint, kind, subject, identifier FROM findings WHERE kind = ? AND status IN ('open','acked')",
    )
      .bind(rule.kind)
      .all<{ fingerprint: string; kind: string; subject: string; identifier: string }>()).results ?? [];

  const now = nowIso();
  let n = 0;
  for (const r of rows) {
    if (!matchSuppression([rule], r)) continue;
    await env.DB.batch([
      env.DB.prepare("UPDATE findings SET status = 'muted', last_seen = ? WHERE fingerprint = ?").bind(now, r.fingerprint),
      env.DB.prepare('DELETE FROM notifications WHERE fingerprint = ?').bind(r.fingerprint),
    ]);
    n++;
  }
  return n;
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

function defaultTitle(f: ReportedFinding): string {
  switch (f.kind) {
    case 'image-cve':
      return `${f.subject}: ${f.identifier}`;
    case 'image-tag':
      return `${f.subject}: newer tag available (${f.identifier})`;
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
