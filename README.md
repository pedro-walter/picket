# Picket

Unified multi-server monitoring for the Soul Spike infra — a lightweight
agent on each server plus a central Cloudflare Worker with a real finding
lifecycle, so a known / vetted / accepted item never re-alerts.

See [`PLAN.md`](./PLAN.md) for the full design and rationale.

## Layout

| Path | What | Status |
|---|---|---|
| `server/` | Central service — Cloudflare Worker (Hono) + D1 + Resend | **working** — deployed at `picket.souspike.com.br` |
| `cli/picketctl/` | Admin CLI (`mint-agent`, `findings`, `mute`, `rules`, `seed-ignores`) | **working** |
| `agent/` | `picket-agent` Go daemon | **step 7 done** — all checks + hash-gated sections + signed self-update + `crane`/`trivy` auto-download |
| `deploy/` | `install.sh` + systemd unit + `agent.example.yaml` + `cosign.pub` | `install.sh` wired (needs a published release + real `cosign.pub`) |
| `.github/workflows/` | `release.yml` — build + cosign-sign + publish on `v*` tag | needs `COSIGN_KEY` / `COSIGN_PASSWORD` secrets |
| `docs/` | architecture / operations / migration / setup | in progress |

Build order (`PLAN.md`): **1** Worker skeleton ✅ · **2** agent skeleton + reboot
check ✅ · **3** image CVE + tag-freshness ✅ · 4 suppression dashboard (server ✅) ·
5 notifications ✅ · **6** apt / stale-container / host-health / cert-expiry ✅ ·
**7** release pipeline + signed self-update + tools auto-download ✅ · 8 one-week
parallel run ← next · 9 weekly review skill.

## Central service — quick start

```sh
cd server
npm install
npx wrangler d1 create picket                 # copy database_id into wrangler.toml
npm run migrate:local                          # apply migrations to local D1
npx wrangler secret put ADMIN_TOKEN            # (dev: use a .dev.vars file instead)
npm run dev                                    # http://localhost:8787
```

`.dev.vars` for local runs (git-ignored):

```
ADMIN_TOKEN=dev-admin-token
TOKEN_PEPPER=dev-pepper
# RESEND_API_KEY=re_...        # omit -> emails are logged, not sent
```

Then, from `cli/picketctl/`:

```sh
export PICKET_URL=http://localhost:8787 PICKET_ADMIN_TOKEN=dev-admin-token
./picketctl mint-agent test
./picketctl seed-ignores ../../../souspike/server-checks/image-watch/ignore
./picketctl findings
```

Dashboard: `http://localhost:8787/?token=dev-admin-token` (production: put the
Worker behind Cloudflare Access and drop the token).

## Agent — build & run

```sh
cd agent
make test            # config, HMAC signing, reboot check, scheduler
make build           # -> ./picket-agent  (static, CGO off)
make cross           # -> dist/picket-agent_<ver>_linux_{amd64,arm64}

./picket-agent --config /etc/picket/agent.yaml --oneshot   # run every tier once
```

Config sample: [`deploy/agent.example.yaml`](./deploy/agent.example.yaml).

## Reporting

One `POST /api/v1/report` per `report_interval`. Cheap findings + metrics are
inline and fresh; lower-cadence tiers (image scan, daily) ride in `sections`
under a content hash and send their full body only when that hash changes —
central acks the hash and the agent stops resending. Hash-only cycles never
re-diff or falsely resolve; a section that stops refreshing is flagged stale by
the `*/15` cron. Details: [`docs/architecture.md`](./docs/architecture.md).

## Tests

```sh
cd server && npm test      # fingerprinting, HMAC, glob, suppression match
cd agent  && go test ./...   # config, sign(), reboot check, section hash-gate protocol
```

End-to-end ingest / lifecycle / section / notification checks run against
`wrangler dev` with the real agent binary — see
[`docs/operations.md`](./docs/operations.md).

## Checks

| tier | kind | source |
|---|---|---|
| cheap 15m | `reboot` | `/var/run/reboot-required` |
| cheap 15m | `apt` | `apt-get -s dist-upgrade` (security vs regular) + last unattended-upgrades run |
| cheap 15m | `container-stale` | `docker inspect` running vs compose-pinned image id (report-only) |
| cheap 15m | *metrics* → `host-health` | `/proc` CPU/RAM, `statfs` disk, `du` of data dirs; central evaluates thresholds |
| `image-scan` 12h | `image-cve`, `image-tag` | `trivy` + `crane` over `compose_files` |
| `daily` 24h | `cert-expiry` | real TLS dial per `domains:` entry (Go `crypto/tls`) |

`image-scan` needs `crane` + `trivy` on `$PATH` or in `<state-dir>/bin`; private
non-first-party images need registry creds at `/var/lib/picket/.docker/config.json`.

## Releasing the agent

1. **One-time:** `cosign generate-key-pair` → paste `cosign.pub` into
   `agent/internal/selfupdate/pubkey.go` **and** `deploy/cosign.pub`; add repo
   secrets `COSIGN_KEY` (the `cosign.key` contents) + `COSIGN_PASSWORD`.
2. `git tag v0.2.0 && git push origin v0.2.0` → `release.yml` builds
   `picket-agent_0.2.0_linux_{amd64,arm64}`, `SHA256SUMS`, `.sig` files and
   publishes a GitHub Release.
3. Register + stage the rollout:
   ```sh
   picketctl release add v0.2.0 \
     --base-url https://github.com/pedrohardware/picket/releases/download/v0.2.0 \
     --sha256sums ./SHA256SUMS
   picketctl rollout v0.2.0 canary        # one bucket first
   # watch, then: picketctl rollout v0.2.0 default
   ```

Each agent verifies the SHA-256 **and** the cosign signature against its
baked-in key before the atomic swap; it only swaps inside `update_window`.
While `cosign.pub` is the placeholder, self-update is disabled (fail-safe).

## Next

Build-order step 8: one-week parallel run — Picket findings vs the still-live
`check-images.sh` Healthchecks pings — then the migration/retirement steps in
[`docs/migration-from-server-checks.md`](./docs/migration-from-server-checks.md).

Setup notes for deploying the Worker and the agent hosts:
[`docs/setup.md`](./docs/setup.md).
