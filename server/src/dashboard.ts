import type { Env } from './index';

const esc = (s: unknown): string =>
  String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);

export async function renderDashboard(env: Env, token: string): Promise<string> {
  const agents =
    (await env.DB.prepare(
      'SELECT id, name, agent_version, desired_version, rollout_bucket, last_report_at FROM agents ORDER BY name',
    ).all<Record<string, string | null>>()).results ?? [];

  const findings =
    (await env.DB.prepare(
      `SELECT fingerprint, agent_id, kind, subject, identifier, severity, title, detail, status, first_seen, last_seen
       FROM findings WHERE status IN ('open','acked','muted')
       ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'acked' THEN 1 ELSE 2 END,
                CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                kind`,
    ).all<Record<string, string>>()).results ?? [];

  const names = new Map(agents.map((a) => [a.id, a.name]));
  const interval = Number(env.REPORT_INTERVAL_SECONDS || '900');
  const grace = Number(env.OFFLINE_GRACE_SECONDS || '300');
  const offlineBefore = Date.now() - (2 * interval + grace) * 1000;
  const q = token ? `?token=${encodeURIComponent(token)}` : '';

  const agentRows =
    agents
      .map((a) => {
        const last = a.last_report_at ? new Date(a.last_report_at) : null;
        const online = last && last.getTime() >= offlineBefore;
        const ver = a.desired_version ? `${esc(a.agent_version ?? '—')} → ${esc(a.desired_version)}` : esc(a.agent_version ?? '—');
        return `<tr><td>${esc(a.name)}</td><td>${ver}</td><td>${esc(a.rollout_bucket)}</td>
          <td class="${online ? 'ok' : 'bad'}">${last ? esc(a.last_report_at) : 'never'}</td></tr>`;
      })
      .join('') || '<tr><td colspan="4">no agents</td></tr>';

  const findingRows =
    findings
      .map((f) => {
        const actions =
          f.status === 'muted'
            ? `<form method="post" action="/admin/findings/${esc(f.fingerprint)}/unmute${q}"><button>unmute</button></form>`
            : `${f.status === 'open' ? `<form method="post" action="/admin/findings/${esc(f.fingerprint)}/ack${q}"><button>ack</button></form>` : ''}
               <form method="post" action="/admin/findings/${esc(f.fingerprint)}/mute${q}">
                 <input name="reason" placeholder="reason" required size="16"><button>mute</button></form>`;
        return `<tr class="sev-${esc(f.severity)}">
          <td>${esc(f.status)}</td><td>${esc(names.get(f.agent_id) ?? f.agent_id)}</td><td>${esc(f.kind)}</td>
          <td class="sev">${esc(f.severity)}</td>
          <td title="${esc(f.detail)}">${esc(f.title)}</td><td>${esc(f.last_seen)}</td><td>${actions}</td></tr>`;
      })
      .join('') || '<tr><td colspan="7">no active findings</td></tr>';

  return `<!doctype html><meta charset="utf-8"><title>picket</title>
<style>
 body{font:14px/1.4 system-ui,sans-serif;margin:2rem;max-width:1150px}
 h1{margin:0 0 1rem} h2{margin:2rem 0 .5rem}
 table{border-collapse:collapse;width:100%}
 th,td{border:1px solid #d0d0d0;padding:4px 8px;text-align:left;vertical-align:top}
 th{background:#f4f4f4}
 .ok{color:#137333}.bad{color:#c5221f;font-weight:bold}
 tr.sev-critical .sev,tr.sev-high .sev{color:#c5221f;font-weight:bold}
 form{display:inline;margin:0 3px 0 0}
 button{cursor:pointer}
</style>
<h1>picket</h1>
<h2>agents</h2>
<table><tr><th>name</th><th>version</th><th>bucket</th><th>last report</th></tr>${agentRows}</table>
<h2>findings</h2>
<table><tr><th>status</th><th>agent</th><th>kind</th><th>sev</th><th>title</th><th>last seen</th><th>actions</th></tr>${findingRows}</table>
`;
}
