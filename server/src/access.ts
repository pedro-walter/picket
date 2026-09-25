import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { Env } from './index';

// One JWKS per team domain, reused across requests within an isolate; jose's
// remote set already caches keys and rate-limits refetches internally.
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function jwksFor(teamDomain: string) {
  let set = jwksCache.get(teamDomain);
  if (!set) {
    set = createRemoteJWKSet(new URL(`https://${teamDomain}/cdn-cgi/access/certs`));
    jwksCache.set(teamDomain, set);
  }
  return set;
}

/**
 * Verifies the Cf-Access-Jwt-Assertion Cloudflare Access attaches to every
 * request that passed its edge policy, returning the verified identity on
 * success. Signature/issuer/audience checked here so that a request which
 * reaches the Worker directly (e.g. its *.workers.dev URL, which Access
 * doesn't cover) can't get in by forging the identity header by hand.
 *
 * A human login carries `email`; a Service Token (machine auth, e.g.
 * picketctl) carries `common_name` (the token's name) instead and has no
 * `email` claim at all — both are equally verified JWTs, so both are
 * accepted as an admin identity here.
 */
export async function verifyAccessJwt(req: Request, env: Env): Promise<string | null> {
  if (!env.CF_ACCESS_TEAM_DOMAIN || !env.CF_ACCESS_AUD) return null;
  const token = req.headers.get('Cf-Access-Jwt-Assertion');
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, jwksFor(env.CF_ACCESS_TEAM_DOMAIN), {
      issuer: `https://${env.CF_ACCESS_TEAM_DOMAIN}`,
      audience: env.CF_ACCESS_AUD,
    });
    if (typeof payload.email === 'string') return payload.email;
    if (typeof payload.common_name === 'string') return payload.common_name;
    return null;
  } catch (err) {
    console.error(`[picket] Access JWT verification failed: ${err}`);
    return null;
  }
}
