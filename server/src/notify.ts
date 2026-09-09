import type { Env } from './index';
import type { ReportedFinding } from './suppress';

export interface AlertItem {
  finding: ReportedFinding;
  reason: 'new' | 'reopened';
}

export interface ResolvedItem {
  kind: string;
  subject: string;
  identifier: string;
  title: string;
}

/** Low-level: one email via the Resend API. No-ops (logs) without a key. */
export async function sendEmail(env: Env, subject: string, text: string): Promise<void> {
  if (!env.RESEND_API_KEY) {
    console.log(`[picket] email skipped (no RESEND_API_KEY): ${subject}\n${text}`);
    return;
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.ALERT_FROM,
      to: env.ALERT_TO.split(',').map((s) => s.trim()).filter(Boolean),
      subject,
      text,
    }),
  });
  if (!res.ok) console.error(`[picket] resend ${res.status}: ${await res.text()}`);
}

/** One consolidated mail per report that has something new (and, optionally, resolved). */
export async function sendReportEmail(
  env: Env,
  agentName: string,
  alerts: AlertItem[],
  resolved: ResolvedItem[],
): Promise<void> {
  const lines: string[] = [];

  if (alerts.length) {
    lines.push(`New on ${agentName}:`);
    for (const a of alerts) {
      const f = a.finding;
      const tag = a.reason === 'reopened' ? ' (reopened)' : '';
      lines.push(`  [${(f.severity ?? 'info').toUpperCase()}] ${f.title ?? `${f.subject} ${f.identifier}`}${tag}`);
      if (f.detail) lines.push(`      ${f.detail}`);
    }
  }

  if (resolved.length) {
    if (lines.length) lines.push('');
    lines.push(`Resolved on ${agentName}:`);
    for (const r of resolved) lines.push(`  ${r.title}`);
  }

  const n = alerts.length;
  const subject = n
    ? `[picket] ${agentName}: ${n} new finding${n === 1 ? '' : 's'}`
    : `[picket] ${agentName}: ${resolved.length} resolved`;

  await sendEmail(env, subject, lines.join('\n'));
}
