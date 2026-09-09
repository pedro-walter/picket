import { Hono } from 'hono';
import { authenticateAgent, authenticateAdmin } from './auth';
import { ingestReport, applyNewSuppression, type ReportPayload } from './ingest';
import { offlineCheck, dailyDigest, staleSectionCheck } from './cron';
import { renderDashboard } from './dashboard';
import { uuid, nowIso, sha256Hex, base64 } from './util';

export interface Env {
  DB: D1Database;
  RESEND_API_KEY?: string;
  ADMIN_TOKEN?: string;
  TOKEN_PEPPER?: string;
  REPORT_INTERVAL_SECONDS: string;
  OFFLINE_GRACE_SECONDS: string;
  ALERT_FROM: string;
  ALERT_TO: string;
  DEFAULT_DESIRED_VERSION: string;
  RELEASE_BASE_URL: string;
  NOTIFY_RESOLVED?: string;
  DIGEST_ALWAYS?: string;
  SECTION_STALE_SECONDS?: string;
}

const app = new Hono<{ Bindings: Env }>();

app.get('/healthz', (c) => c.text('ok'));

// ---------------------------------------------------------------- agent ingest
app.post('/api/v1/report', async (c) => {
  const rawBody = await c.req.text();
  const auth = await authenticateAgent(c.req.raw, rawBody, c.env);
  if ('error' in auth) return c.json({ error: auth.error }, auth.status as 401);

  let payload: ReportPayload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400);
  }
  // A healthy agent legitimately reports nothing; accept absent/null as [].
  // Only reject a value that is present and not an array.
  if (
    (payload.findings != null && !Array.isArray(payload.findings)) ||
    (payload.checks_run != null && !Array.isArray(payload.checks_run))
  ) {
    return c.json({ error: 'findings and checks_run must be arrays when present' }, 400);
  }
  payload.findings ??= [];
  payload.checks_run ??= [];

  const selfUpdate = await ingestReport(c.env, auth.agent, payload);
  return c.json({ ok: true, ...selfUpdate });
});

// ----------------------------------------------------------------------- admin
const admin = new Hono<{ Bindings: Env }>();
admin.use('*', async (c, next) => {
  if (!authenticateAdmin(c.req.raw, c.env)) return c.json({ error: 'unauthorized' }, 401);
  await next();
});

admin.post('/agents', async (c) => {
  const body = await c.req.json<{ name?: string; rollout_bucket?: string; notes?: string; desired_version?: string }>();
  if (!body.name) return c.json({ error: 'name required' }, 400);

  const token = base64(crypto.getRandomValues(new Uint8Array(32))).replace(/=+$/, '');
  const tokenHash = await sha256Hex((c.env.TOKEN_PEPPER ?? '') + token);
  const id = uuid();
  try {
    await c.env.DB.prepare(
      `INSERT INTO agents (id, name, token_hash, rollout_bucket, notes, desired_version, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(id, body.name, tokenHash, body.rollout_bucket ?? 'default', body.notes ?? null, body.desired_version ?? null, nowIso())
      .run();
  } catch (e) {
    return c.json({ error: `could not create agent (name already taken?): ${(e as Error).message}` }, 409);
  }
  return c.json({ id, name: body.name, token });
});

admin.get('/agents', async (c) => {
  const rows = (await c.env.DB.prepare(
    `SELECT id, name, agent_version, desired_version, rollout_bucket, last_report_at, notes, created_at
     FROM agents ORDER BY name`,
  ).all()).results;
  return c.json({ agents: rows });
});

admin.patch('/agents/:name', async (c) => {
  const name = c.req.param('name');
  const body = await c.req.json<{ desired_version?: string | null; rollout_bucket?: string; notes?: string }>();
  const sets: string[] = [];
  const vals: (string | null)[] = [];
  if ('desired_version' in body) {
    sets.push('desired_version = ?');
    vals.push(body.desired_version ?? null);
  }
  if (body.rollout_bucket) {
    sets.push('rollout_bucket = ?');
    vals.push(body.rollout_bucket);
  }
  if (body.notes !== undefined) {
    sets.push('notes = ?');
    vals.push(body.notes);
  }
  if (!sets.length) return c.json({ error: 'nothing to update' }, 400);
  vals.push(name);
  const r = await c.env.DB.prepare(`UPDATE agents SET ${sets.join(', ')} WHERE name = ?`)
    .bind(...vals)
    .run();
  return c.json({ updated: r.meta.changes });
});

admin.get('/findings', async (c) => {
  const status = c.req.query('status');
  const agent = c.req.query('agent');
  const where: string[] = [];
  const vals: string[] = [];
  if (status) {
    where.push('f.status = ?');
    vals.push(status);
  }
  if (agent) {
    where.push('a.name = ?');
    vals.push(agent);
  }
  const sql =
    `SELECT f.*, a.name AS agent_name FROM findings f JOIN agents a ON a.id = f.agent_id` +
    (where.length ? ` WHERE ${where.join(' AND ')}` : '') +
    ` ORDER BY f.status, f.severity, f.last_seen DESC`;
  const rows = (await c.env.DB.prepare(sql).bind(...vals).all()).results;
  return c.json({ findings: rows });
});

const findingRow = (c: { env: Env }, fp: string) =>
  c.env.DB.prepare('SELECT * FROM findings WHERE fingerprint = ?').bind(fp).first<Record<string, string>>();

function respond(c: any, body: unknown) {
  // browser form posts get a redirect back; API clients get JSON
  if ((c.req.header('accept') ?? '').includes('text/html')) {
    return c.redirect(c.req.header('referer') ?? '/', 303);
  }
  return c.json(body);
}

admin.post('/findings/:fp/ack', async (c) => {
  const r = await c.env.DB.prepare("UPDATE findings SET status = 'acked' WHERE fingerprint = ? AND status = 'open'")
    .bind(c.req.param('fp'))
    .run();
  return respond(c, { acked: r.meta.changes });
});

admin.post('/findings/:fp/mute', async (c) => {
  const fp = c.req.param('fp');
  const f = await findingRow(c, fp);
  if (!f) return c.json({ error: 'no such finding' }, 404);

  let reason = '';
  let expires: string | null = null;
  if ((c.req.header('content-type') ?? '').includes('application/json')) {
    const b = await c.req.json<{ reason?: string; expires_at?: string }>();
    reason = b.reason ?? '';
    expires = b.expires_at ?? null;
  } else {
    const b = await c.req.parseBody();
    reason = String(b.reason ?? '');
    expires = b.expires_at ? String(b.expires_at) : null;
  }
  if (!reason) return c.json({ error: 'reason required' }, 400);

  await c.env.DB.batch([
    c.env.DB.prepare(
      `INSERT INTO suppressions (id, kind, subject_glob, identifier_glob, cve_glob, reason, author, created_at, expires_at)
       VALUES (?, ?, ?, ?, '*', ?, ?, ?, ?)`,
    ).bind(
      uuid(),
      f.kind,
      f.subject,
      f.identifier,
      reason,
      c.req.header('Cf-Access-Authenticated-User-Email') ?? 'dashboard',
      nowIso(),
      expires,
    ),
    c.env.DB.prepare("UPDATE findings SET status = 'muted' WHERE fingerprint = ?").bind(fp),
  ]);
  return respond(c, { muted: true });
});

admin.post('/findings/:fp/unmute', async (c) => {
  const fp = c.req.param('fp');
  const f = await findingRow(c, fp);
  if (!f) return c.json({ error: 'no such finding' }, 404);
  await c.env.DB.batch([
    c.env.DB.prepare(
      "DELETE FROM suppressions WHERE kind = ? AND subject_glob = ? AND identifier_glob = ? AND cve_glob = '*'",
    ).bind(f.kind, f.subject, f.identifier),
    c.env.DB.prepare("UPDATE findings SET status = 'open' WHERE fingerprint = ?").bind(fp),
  ]);
  return respond(c, { unmuted: true });
});

admin.get('/suppressions', async (c) => {
  const rows = (await c.env.DB.prepare('SELECT * FROM suppressions ORDER BY created_at DESC').all()).results;
  return c.json({ suppressions: rows });
});

admin.post('/suppressions', async (c) => {
  const b = await c.req.json<{
    kind?: string;
    subject_glob?: string;
    identifier_glob?: string;
    cve_glob?: string;
    reason?: string;
    author?: string;
    expires_at?: string;
  }>();
  if (!b.kind || !b.reason) return c.json({ error: 'kind and reason required' }, 400);
  const now = nowIso();
  const rule = {
    id: uuid(),
    kind: b.kind,
    subject_glob: b.subject_glob ?? '*',
    identifier_glob: b.identifier_glob ?? '*',
    cve_glob: b.cve_glob ?? '*',
    reason: b.reason,
    author: b.author ?? 'picketctl',
    created_at: now,
    expires_at: b.expires_at ?? null,
  };
  await c.env.DB.prepare(
    `INSERT INTO suppressions (id, kind, subject_glob, identifier_glob, cve_glob, reason, author, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      rule.id,
      rule.kind,
      rule.subject_glob,
      rule.identifier_glob,
      rule.cve_glob,
      rule.reason,
      rule.author,
      rule.created_at,
      rule.expires_at,
    )
    .run();
  const muted = await applyNewSuppression(c.env, rule);
  return c.json({ id: rule.id, muted });
});

admin.delete('/suppressions/:id', async (c) => {
  const r = await c.env.DB.prepare('DELETE FROM suppressions WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ deleted: r.meta.changes });
});

// ---- releases (self-update artifact registry) ----
admin.get('/releases', async (c) => {
  const rows = (await c.env.DB.prepare('SELECT * FROM releases ORDER BY created_at DESC').all()).results;
  return c.json({ releases: rows });
});

admin.post('/releases', async (c) => {
  const b = await c.req.json<{
    version?: string;
    url_amd64?: string;
    sha256_amd64?: string;
    sig_url_amd64?: string;
    url_arm64?: string;
    sha256_arm64?: string;
    sig_url_arm64?: string;
    notes?: string;
  }>();
  const v = (b.version ?? '').replace(/^v/, '');
  if (!v || !b.url_amd64 || !b.sha256_amd64 || !b.sig_url_amd64) {
    return c.json({ error: 'version, url_amd64, sha256_amd64, sig_url_amd64 required' }, 400);
  }
  await c.env.DB.prepare(
    `INSERT OR REPLACE INTO releases
       (version, url_amd64, sha256_amd64, sig_url_amd64, url_arm64, sha256_arm64, sig_url_arm64, notes, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      v,
      b.url_amd64,
      b.sha256_amd64,
      b.sig_url_amd64,
      b.url_arm64 ?? null,
      b.sha256_arm64 ?? null,
      b.sig_url_arm64 ?? null,
      b.notes ?? null,
      nowIso(),
    )
    .run();
  return c.json({ version: v });
});

admin.delete('/releases/:version', async (c) => {
  const r = await c.env.DB.prepare('DELETE FROM releases WHERE version = ?')
    .bind(c.req.param('version').replace(/^v/, ''))
    .run();
  return c.json({ deleted: r.meta.changes });
});

// set desired_version for a whole rollout bucket (staggered rollout)
admin.post('/rollout', async (c) => {
  const b = await c.req.json<{ version?: string; bucket?: string }>();
  const v = (b.version ?? '').replace(/^v/, '');
  if (!v) return c.json({ error: 'version required' }, 400);
  const rel = await c.env.DB.prepare('SELECT 1 FROM releases WHERE version = ?').bind(v).first();
  if (!rel) return c.json({ error: `no registered release ${v} (add it first)` }, 400);
  const bucket = b.bucket ?? 'default';
  const r = await c.env.DB.prepare('UPDATE agents SET desired_version = ? WHERE rollout_bucket = ?').bind(v, bucket).run();
  return c.json({ version: v, bucket, agents_updated: r.meta.changes });
});

app.route('/admin', admin);

// ------------------------------------------------------------------- dashboard
app.get('/', async (c) => {
  if (!authenticateAdmin(c.req.raw, c.env)) {
    return c.text('unauthorized — put this Worker behind Cloudflare Access, or append ?token=$ADMIN_TOKEN', 401);
  }
  const token = new URL(c.req.url).searchParams.get('token') ?? '';
  return c.html(await renderDashboard(c.env, token));
});

export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env): Promise<void> {
    if (event.cron === '0 13 * * *') {
      await dailyDigest(env);
      return;
    }
    await offlineCheck(env);
    await staleSectionCheck(env);
  },
};
