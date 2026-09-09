# Operations

> Stub. Covers the central Worker; agent ops land with the agent build.

## Deploy the Worker

```sh
cd server
npx wrangler d1 create picket            # once; put database_id in wrangler.toml
npm run migrate:remote
npx wrangler secret put RESEND_API_KEY
npx wrangler secret put ADMIN_TOKEN
npx wrangler secret put TOKEN_PEPPER
npm run deploy
```

Attach the custom domain `picket.souspike.com.br` in the Cloudflare dashboard
and, for the dashboard + `/admin/*`, add a Cloudflare Access application in
front of it (Google identity).

## Local end-to-end check (matches PLAN.md "Verification")

```sh
cd server
npm run migrate:local
echo 'ADMIN_TOKEN=dev-admin-token'  > .dev.vars
echo 'TOKEN_PEPPER=dev-pepper'     >> .dev.vars
npm run dev &                                   # :8787

cd ../cli/picketctl
export PICKET_URL=http://localhost:8787 PICKET_ADMIN_TOKEN=dev-admin-token
TOKEN=$(./picketctl mint-agent test | jq -r .token)
```

Sign and send a report (bash):

```sh
BODY='{"agent_name":"test","agent_version":"0.1.0","checks_run":["image-cve"],
 "findings":[{"kind":"image-cve","subject":"postgres","identifier":"CVE-2026-14456|libssl3","severity":"high"}]}'
TS=$(date +%s)
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$TOKEN" -r | cut -d' ' -f1)
curl -sS localhost:8787/api/v1/report \
  -H "Authorization: Bearer $TOKEN" -H "X-Picket-Timestamp: $TS" -H "X-Picket-Signature: $SIG" \
  --data "$BODY" | jq .
```

Expect: `./picketctl findings` shows one `open` image-cve; the dev log shows
one "email skipped (no RESEND_API_KEY)". Send the same report again → still one
finding, `last_seen` advanced, no second email. Add a matching rule
(`./picketctl rules add --kind image-cve --subject postgres --identifier '*|libssl3' --reason test`)
and re-send → finding flips to `muted`.

## Cron

`wrangler.toml` schedules two triggers: `*/15 * * * *` (agent-offline sweep)
and `0 13 * * *` (daily digest). Test locally with
`npx wrangler dev --test-scheduled` then `curl 'localhost:8787/__scheduled?cron=*/15+*+*+*+*'`.

## Retention

`reports` rows are raw and grow ~1/agent/15min. Prune with a scheduled
`DELETE FROM reports WHERE received_at < datetime('now','-30 days')` (add to the
`*/15` cron handler when convenient).

## Migrations

Apply on deploy: `npx wrangler d1 migrations apply picket --remote`.
Current: `0001_init`, `0002_agent_sections` (hash-gated reports),
`0003_releases` (self-update artifact registry).

## Cutting an agent release

Prereqs (one-time): a real `deploy/cosign.pub` + the same PEM in
`agent/internal/selfupdate/pubkey.go`, and repo secrets `COSIGN_KEY` /
`COSIGN_PASSWORD`. See the README "Releasing the agent" section.

```sh
git tag v0.2.0 && git push origin v0.2.0          # release.yml builds + signs + publishes

export PICKET_URL=https://picket.souspike.com.br PICKET_ADMIN_TOKEN=...
curl -fsSLO https://github.com/pedrohardware/picket/releases/download/v0.2.0/SHA256SUMS
picketctl release add v0.2.0 \
  --base-url https://github.com/pedrohardware/picket/releases/download/v0.2.0 \
  --sha256sums ./SHA256SUMS
picketctl release list

picketctl rollout v0.2.0 canary     # agents in the 'canary' bucket update next window
# verify with `picketctl list-agents` (agent_version catches up), then:
picketctl rollout v0.2.0 default
```

Roll back: `picketctl rollout v0.1.9 <bucket>` (the older release row must still
be registered). `wrangler.toml`'s `RELEASE_BASE_URL` var is unused since 0003 —
release URLs come from the `releases` table.

## Bumping crane / trivy

Edit `tools.Default` in `agent/internal/tools/tools.go` (version + both
`SHA256*` from the vendor's published checksums), then cut a normal agent
release — the agent re-downloads on its next `daily` cycle.
