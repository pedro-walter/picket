import type { Env } from './index';
import { sendEmail } from './notify';
import { nowIso, isoMinusSeconds } from './util';

/** Mail once when an agent goes quiet for > 2*report_interval + grace. */
export async function offlineCheck(env: Env): Promise<void> {
  const interval = Number(env.REPORT_INTERVAL_SECONDS || '900');
  const grace = Number(env.OFFLINE_GRACE_SECONDS || '300');
  const threshold = isoMinusSeconds(2 * interval + grace);

  const agents =
    (await env.DB.prepare('SELECT id, name, last_report_at FROM agents').all<{
      id: string;
      name: string;
      last_report_at: string | null;
    }>()).results ?? [];

  for (const a of agents) {
    if (!a.last_report_at || a.last_report_at >= threshold) continue;
    const fp = `offline:${a.id}`;
    const already = await env.DB.prepare("SELECT 1 FROM notifications WHERE fingerprint = ? AND kind = 'offline'")
      .bind(fp)
      .first();
    if (already) continue;
    await sendEmail(
      env,
      `[picket] ${a.name} is offline`,
      `No report from ${a.name} since ${a.last_report_at}.\nOffline threshold: ${threshold} (2 x ${interval}s + ${grace}s grace).`,
    );
    await env.DB.prepare(
      "INSERT OR IGNORE INTO notifications (fingerprint, sent_at, channel, kind) VALUES (?, ?, 'email', 'offline')",
    )
      .bind(fp, nowIso())
      .run();
  }
}

/**
 * Mail once when a hash-gated section (image scan, daily) has not been
 * regenerated within SECTION_STALE_SECONDS - the heavy tier has silently
 * stopped. Its findings are deliberately NOT resolved; they are just stale.
 */
export async function staleSectionCheck(env: Env): Promise<void> {
  const staleAfter = Number(env.SECTION_STALE_SECONDS || '93600'); // ~26h
  const threshold = isoMinusSeconds(staleAfter);

  const rows =
    (await env.DB.prepare(
      `SELECT s.agent_id, s.section, s.generated_at, a.name
       FROM agent_sections s JOIN agents a ON a.id = s.agent_id`,
    ).all<{ agent_id: string; section: string; generated_at: string; name: string }>()).results ?? [];

  for (const r of rows) {
    const fp = `stale-section:${r.agent_id}:${r.section}`;
    const fresh = r.generated_at >= threshold;
    if (fresh) {
      await env.DB.prepare("DELETE FROM notifications WHERE fingerprint = ? AND kind = 'stale-section'").bind(fp).run();
      continue;
    }
    const already = await env.DB.prepare("SELECT 1 FROM notifications WHERE fingerprint = ? AND kind = 'stale-section'")
      .bind(fp)
      .first();
    if (already) continue;
    await sendEmail(
      env,
      `[picket] ${r.name}: ${r.section} scan is stale`,
      `The "${r.section}" scan on ${r.name} last ran ${r.generated_at} (older than ${staleAfter}s).\n` +
        `Its findings are still shown as-is - not resolved - until a fresh scan lands.`,
    );
    await env.DB.prepare(
      "INSERT OR IGNORE INTO notifications (fingerprint, sent_at, channel, kind) VALUES (?, ?, 'email', 'stale-section')",
    )
      .bind(fp, nowIso())
      .run();
  }
}

/** Once-daily summary of everything still open, plus a muted count. */
export async function dailyDigest(env: Env): Promise<void> {
  const open =
    (await env.DB.prepare(
      `SELECT agent_id, kind, subject, identifier, severity, title, first_seen
       FROM findings WHERE status IN ('open','acked') ORDER BY agent_id, severity`,
    ).all<{
      agent_id: string;
      kind: string;
      subject: string;
      identifier: string;
      severity: string;
      title: string;
      first_seen: string;
    }>()).results ?? [];

  const mutedRow = await env.DB.prepare("SELECT COUNT(*) AS c FROM findings WHERE status = 'muted'").first<{ c: number }>();
  const muted = mutedRow?.c ?? 0;

  if (open.length === 0 && (env.DIGEST_ALWAYS ?? 'false') !== 'true') return;

  const names = new Map(
    ((await env.DB.prepare('SELECT id, name FROM agents').all<{ id: string; name: string }>()).results ?? []).map((r) => [
      r.id,
      r.name,
    ]),
  );

  const byAgent = new Map<string, typeof open>();
  for (const f of open) {
    const arr = byAgent.get(f.agent_id) ?? [];
    arr.push(f);
    byAgent.set(f.agent_id, arr);
  }

  const lines = [`${open.length} open finding(s), ${muted} muted.`, ''];
  for (const [aid, fs] of byAgent) {
    lines.push(`${names.get(aid) ?? aid}:`);
    for (const f of fs) {
      lines.push(`  [${f.severity.toUpperCase()}] ${f.title} (since ${f.first_seen.slice(0, 10)})`);
    }
    lines.push('');
  }

  await sendEmail(env, `[picket] daily digest: ${open.length} open`, lines.join('\n').trim());
}
