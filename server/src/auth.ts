import type { Env } from './index';
import { sha256Hex, hmacSha256Hex, timingSafeEqualHex } from './util';

export interface Agent {
  id: string;
  name: string;
  token_hash: string;
  agent_version: string | null;
  desired_version: string | null;
  rollout_bucket: string;
  last_report_at: string | null;
  notes: string | null;
}

const MAX_SKEW_SECONDS = 300;

export type AgentAuthResult = { agent: Agent } | { error: string; status: number };

/**
 * Bearer token identifies the agent; an HMAC over `timestamp + "." + rawBody`
 * (keyed by the same token) gives body integrity + replay protection.
 * Timestamp is unix seconds; >5min skew is rejected.
 */
export async function authenticateAgent(req: Request, rawBody: string, env: Env): Promise<AgentAuthResult> {
  const authz = req.headers.get('Authorization') ?? '';
  const m = authz.match(/^Bearer\s+(.+)$/);
  if (!m) return { error: 'missing bearer token', status: 401 };
  const token = m[1]!.trim();

  const tokenHash = await sha256Hex((env.TOKEN_PEPPER ?? '') + token);
  const agent = await env.DB.prepare('SELECT * FROM agents WHERE token_hash = ?').bind(tokenHash).first<Agent>();
  if (!agent) return { error: 'unknown agent token', status: 401 };

  const ts = req.headers.get('X-Picket-Timestamp') ?? '';
  const sig = (req.headers.get('X-Picket-Signature') ?? '').toLowerCase();
  if (!ts || !sig) return { error: 'missing signature headers', status: 401 };

  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) return { error: 'bad timestamp', status: 401 };
  if (Math.abs(Date.now() / 1000 - tsNum) > MAX_SKEW_SECONDS) {
    return { error: 'timestamp skew too large', status: 401 };
  }

  const expected = await hmacSha256Hex(token, `${ts}.${rawBody}`);
  if (!timingSafeEqualHex(expected, sig)) return { error: 'signature mismatch', status: 401 };

  return { agent };
}

/**
 * /admin/* + dashboard guard. Cloudflare Access (recommended for production)
 * injects an authenticated-identity header we trust. Without Access, an
 * ADMIN_TOKEN presented via X-Admin-Token, `Authorization: Bearer`, or a
 * `?token=` query param is accepted.
 */
export function authenticateAdmin(req: Request, env: Env): boolean {
  if (req.headers.get('Cf-Access-Authenticated-User-Email')) return true;
  if (!env.ADMIN_TOKEN) return false;
  const url = new URL(req.url);
  const provided =
    req.headers.get('X-Admin-Token') ??
    req.headers.get('Authorization')?.match(/^Bearer\s+(.+)$/)?.[1] ??
    url.searchParams.get('token') ??
    '';
  return provided.length > 0 && timingSafeEqualHex(hexPad(provided), hexPad(env.ADMIN_TOKEN));
}

// pad to compare non-hex admin tokens without early-exit length leak
function hexPad(s: string): string {
  return [...s].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}
