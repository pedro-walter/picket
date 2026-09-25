import { describe, it, expect } from 'vitest';
import { authenticateAdmin } from '../src/auth';
import type { Env } from '../src/index';

const req = (opts: { header?: [string, string]; url?: string } = {}) => {
  const r = new Request(opts.url ?? 'https://picket.example.com/');
  if (opts.header) r.headers.set(...opts.header);
  return r;
};

describe('authenticateAdmin (ADMIN_TOKEN fallback, no Access configured)', () => {
  const env = { ADMIN_TOKEN: 'secret-token' } as Env;

  it('accepts a matching ?token= query param', async () => {
    const result = await authenticateAdmin(req({ url: 'https://picket.example.com/?token=secret-token' }), env);
    expect(result.ok).toBe(true);
  });

  it('accepts a matching X-Admin-Token header', async () => {
    const result = await authenticateAdmin(req({ header: ['X-Admin-Token', 'secret-token'] }), env);
    expect(result.ok).toBe(true);
  });

  it('rejects a wrong token', async () => {
    const result = await authenticateAdmin(req({ url: 'https://picket.example.com/?token=nope' }), env);
    expect(result.ok).toBe(false);
  });

  it('rejects when no ADMIN_TOKEN is configured at all', async () => {
    const result = await authenticateAdmin(req(), {} as Env);
    expect(result.ok).toBe(false);
  });

  it('does not trust a bare Cf-Access-Authenticated-User-Email header without Access configured', async () => {
    const result = await authenticateAdmin(req({ header: ['Cf-Access-Authenticated-User-Email', 'attacker@evil.com'] }), env);
    expect(result.ok).toBe(false);
  });
});

describe('authenticateAdmin (Access configured, no valid JWT)', () => {
  it('rejects a forged identity header with no accompanying Access JWT', async () => {
    const env = { CF_ACCESS_TEAM_DOMAIN: 'team.cloudflareaccess.com', CF_ACCESS_AUD: 'aud-tag', ADMIN_TOKEN: 'secret-token' } as Env;
    const result = await authenticateAdmin(
      req({ header: ['Cf-Access-Authenticated-User-Email', 'attacker@evil.com'] }),
      env,
    );
    expect(result.ok).toBe(false);
  });

  it('does not fall back to ADMIN_TOKEN once Access is configured', async () => {
    const env = { CF_ACCESS_TEAM_DOMAIN: 'team.cloudflareaccess.com', CF_ACCESS_AUD: 'aud-tag', ADMIN_TOKEN: 'secret-token' } as Env;
    const result = await authenticateAdmin(req({ url: 'https://picket.example.com/?token=secret-token' }), env);
    expect(result.ok).toBe(false);
  });
});
