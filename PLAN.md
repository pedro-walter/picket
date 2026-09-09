# Picket — unified multi-server monitoring

> Handoff plan. A fresh agent starting in this folder should build the v1
> prototype described below. Source context: the `souspike` repo at
> `/home/pedro/development/souspike` (its `server-checks/`, `check-updates.sh`,
> `monitoring/`, `HACKED.md`).

## Context

The Soul Spike infra spans three servers — `prod-server` (app), `docker-souspike`
(zot registry), `monitoria-soul-spike` (self-hosted Healthchecks + backup-verify,
on a different provider) — plus the two code repos (`soul-spike`,
`soul-spike-web`). Monitoring today is a pile of independent bash cron scripts in
`souspike`:

- `server-checks/image-watch/check-images.sh` — `crane` + `trivy` on compose images
- `server-checks/auto-security-updates/check-security-updates.sh` — apt / reboot
- `server-checks/pending-restart/check-pending-restart.sh` — stale containers / reboot
- `server-checks/system-health/check-system-health.sh` — CPU/RAM/disk
- `server-checks/cert-expiry/check-cert-expiry.sh` — TLS expiry
- `check-updates.sh` (repo root) — Renovate against the two repos, run by hand on the laptop

They deploy by `rsync` (`server-checks/image-watch/sync-to-servers.sh`) and all
alert through one channel: the self-hosted Healthchecks instance
(`healthchecks.souspike.com.br`), which has **no acknowledge / mute / expected
state**. So `/fail` is overloaded as "review this", and anything not actioned
re-alerts forever. CVE noise is suppressed by fragile per-repo text files
(`server-checks/image-watch/ignore/*.txt`) matched by filename against the compose
`image:` line — a mismatch fails silently open, and a rename lag in Aug–Sep 2026
made every already-vetted CVE re-alert as "new". `HACKED.md` still lists "Fix
cronitor false alerts" as the top open item.

`image-watch` is the biggest time sink and the reason this project exists.

**Goal:** one system — a lightweight agent on each server + a central service —
that (a) collects image-CVE/tag, apt, reboot, stale-container, host-health and
TLS-expiry status, (b) has a real finding lifecycle so a known, vetted, or
accepted item never re-alerts, (c) notifies by email only when something new
needs attention, (d) authenticates agents with per-agent tokens, and (e) installs
and self-updates across many servers without hand-uploading binaries.

Name: **Picket** (a picket guard keeps watch on the perimeter). Agent binary
`picket-agent`; central service `picket`; admin CLI `picketctl`.

## Scope

**In the v1 prototype (this plan):** the agent + central service + email + token
auth + self-update, covering these checks — priority order:

1. **compose image CVEs + tag freshness** — the `image-watch` replacement, the point of v1
2. apt / security updates pending
3. reboot required
4. stale containers (report only — no auto-restart in v1)
5. host health (CPU / RAM / disk, incl. `mongo_data` & `registry_data` size)
6. TLS cert expiry

**Explicitly NOT in v1:** repo dependency / "problematic package" scanning (the
`check-updates.sh` job). That does **not** belong in an always-on agent — it's a
periodic, human-in-the-loop activity. It becomes a **weekly review skill**
(below), built after the prototype is running.

## Later: weekly dependency-review skill (replaces `check-updates.sh`)

A Claude Code skill (e.g. `/picket-review`) the user invokes ~weekly. It spawns an
agent that, for `soul-spike` and `soul-spike-web`:

- runs `osv-scanner` and/or `renovate --platform=local --dry-run=lookup` against
  the working tree (same OSV advisory source `check-updates.sh` uses today),
- summarises known-vulnerable and outdated packages,
- proposes / applies the safe updates and opens the branch/PR for review.

Not wired to Picket's agent or central service at all. Design it once the
prototype is stable; delete `check-updates.sh` when it lands.

## Does the central server need to be a real box? No.

Cloudflare Workers cannot run subprocesses/binaries (`trivy`, `crane`, `git`,
`apt`) and have tight CPU-time limits. **But no scanning runs centrally** — the
agent on each server does all scanning, where the bash scripts run today:

| Work | Where it runs | Tool |
|---|---|---|
| apt simulate / reboot-required / `docker inspect` | agent (must — it's that host) | native |
| compose image: newer tag | agent | `crane` (registry HTTP, no daemon) |
| compose image: HIGH/CRITICAL CVEs | agent | `trivy image` (registry, no daemon) |
| CPU/RAM/disk, TLS expiry | agent | native / Go `crypto/tls` |
| aggregate, dedupe, suppress, decide, email, dashboard, dead-man cron | **central** | Workers + D1 + Resend |

The Worker only ever calls outbound HTTP (Resend for mail). Free-tier headroom is
large: three agents reporting every ~15 min ≈ 300 req/day vs 100k/day Workers and
100k row-writes/day D1.

**Decision: Cloudflare Workers + D1 + Resend.** An extra always-free VM (Fly.io /
Oracle) is only warranted if central must _independently re-scan_ without trusting
agent-submitted results — not a requirement, and it reintroduces the "box to
patch" this project exists to remove.

## Scheduling & cost (the agent does NOT do heavy work every tick)

`picket-agent` is a long-lived systemd daemon with one internal scheduler and
three tiers. Nothing runs at sub-minute cadence.

| Tier | Default interval | Does | Cost |
|---|---|---|---|
| **cheap loop** | `report_interval` = 15m | stat `/var/run/reboot-required(.pkgs)`; `apt-get -s dist-upgrade` + tail `unattended-upgrades` logs; `docker inspect` running-vs-pinned image IDs; read `/proc/stat`,`free`,`df`, `du` of the two data dirs; **POST the consolidated report** (cheap tiers fresh, heavy tier from cache); act on `desired_version` if inside `update_window` | ~1–3s wall, negligible |
| **heavy scan** | `image_scan_interval` = 12h | for each `image:` in the compose files: `crane ls` + `crane digest --platform linux/amd64` (tag freshness, same-major only); `trivy image --scanners vuln --severity HIGH,CRITICAL --format json`. Write result to `/var/lib/picket/scan-cache.json` | tens of s – minutes, CPU + network |
| **daily** | 24h | TLS dial each `domains:` entry for `NotAfter`; refresh managed tool binaries | ~1s |

The cheap loop re-sends the cached heavy-scan result unchanged until the next
heavy scan — so the central service always has current image-CVE state without the
agent re-scanning every 15 min. All intervals are config keys; a `--oneshot` run
does every tier once and exits (for testing).

## Repo layout (this folder, `~/development/picket/`)

```
picket/
  agent/                         Go module — static linux/amd64 (+arm64) binary
    cmd/picket-agent/main.go
    internal/config/             /etc/picket/agent.yaml loader
    internal/checks/{apt,reboot,containers,imagetags,imagecve,syshealth,certexpiry}.go
    internal/scheduler/          the three-tier loop
    internal/report/             payload structs (shared shape with server)
    internal/tools/              download+checksum trivy / crane into /var/lib/picket/bin
    internal/selfupdate/         download + cosign-verify + atomic swap + restart
  server/                        Cloudflare Worker (TypeScript, Hono)
    src/{index,auth,ingest,findings,suppressions,notify,dashboard,cron}.ts
    migrations/0001_init.sql
    wrangler.toml
  cli/picketctl/                 mint-agent, list-agents, findings, mute, rules  (Go or POSIX sh + curl)
  deploy/{install.sh,picket-agent.service}
  .github/workflows/release.yml  build + cosign sign + publish binary/checksums/sig
  docs/{architecture.md,operations.md,migration-from-server-checks.md}
```

## The agent (`picket-agent`)

- **Language: Go.** Single static binary, trivial cross-compile; the tools it
  drives (`trivy`, `crane`) are Go single-binaries too.
- **Runs as** systemd service `picket-agent` — `Type=simple`, `Restart=always`,
  `RestartSec=10`, dedicated `picket` user in the `docker` group,
  `NoNewPrivileges=yes`, `ReadWritePaths=/var/lib/picket`. Internal scheduler (not
  a systemd timer) so it keeps the heavy-scan cache and backoff state.
  apt simulate and `/var/run/reboot-required` are readable unprivileged → expect
  **no sudoers drop-in**; add one only if a check proves to need root.
- **Config** `/etc/picket/agent.yaml` (root:picket 0640); token in
  `/etc/picket/token` (0600, git-ignored, never in the yaml):

  ```yaml
  central_url: https://picket.souspike.com.br
  agent_name: prod-server
  token_file: /etc/picket/token
  report_interval: 15m
  image_scan_interval: 12h
  self_update: true
  update_window: "02:00-04:00"
  compose_files: [/home/pedro/production-setup/docker-compose.yml]
  domains: [souspike.com.br, healthchecks.souspike.com.br]   # cert-expiry; monitoria only
  thresholds: {disk_pct: 85, mongo_data_gb: 20, registry_data_gb: 15}
  tools: {auto_manage: true}
  ```

- **Checks** (port the logic from the named `souspike` scripts):

  1. **compose image CVEs** — port `check-images.sh` `watched_images()` (grep
     `image:` from each `compose_files` entry, skip
     `docker.souspike.com.br/(soul-spike-backend|soul-spike-web)`). Run
     `trivy image --scanners vuln --severity HIGH,CRITICAL --format json
     --quiet`. **Send raw findings** (image, PkgName, VulnerabilityID, severity,
     installed/fixed version) to central. Do **not** apply ignore lists
     agent-side — suppression is central so a rule change needs no redeploy.
  2. **compose image tag freshness** — port `check-images.sh`
     `latest_matching_tag()` (same-major only; `crane digest --platform
     linux/amd64` to defeat floating tags).
  3. **apt / security updates** — port `check-security-updates.sh`: `apt-get -s
     dist-upgrade` + parse `/var/log/unattended-upgrades/*.log` from an offset,
     split security vs regular by origin, surface dpkg ERROR/WARNING lines.
  4. **reboot required** — `/var/run/reboot-required` + `.pkgs`.
  5. **stale containers** — port `check-pending-restart.sh`: running image ID
     (`docker inspect`) vs compose-pinned / pulled image. **Report only in v1.**
  6. **host health** — port `check-system-health.sh`: `/proc/stat`, `free`, `df`,
     `du` of `mongo_data/` & `registry_data/`. Agent sends current values;
     **central** stores the last N and evaluates `thresholds` (drop the local
     `state/history.csv`).
  7. **cert expiry** — port `check-cert-expiry.sh` using Go `crypto/tls` dial (no
     `openssl` shell-out); report `NotAfter` per `domains:` entry.

- **Reporting** — one consolidated `POST /api/v1/report` per `report_interval`
  with the full current state (cheap tiers fresh, image scan from cache). Central
  diffs against stored findings; absence of a previously-reported finding for a
  check that ran = resolved.
- **Tool management** — `tools.auto_manage: true`: download pinned
  `trivy`/`crane` to `/var/lib/picket/bin`, verify SHA256, refresh on the daily
  tier (trivy self-updates its vuln DB on run). Pinned versions+hashes ship in
  agent defaults and can be bumped through the same channel as an agent release.

## Central service (`picket`, Cloudflare Worker + D1)

**HTTP API** (Hono):

- `POST /api/v1/report` — bearer auth + HMAC (below); upsert
  `agents.last_report_at` / `agent_version`; store raw row in `reports` (30-day
  retention); run ingest → findings diff; return `{ desired_version, url, sha256,
  sig_url }` for self-update.
- `GET /` — dashboard (Cloudflare Access, Google identity): agents (last seen,
  version), open findings grouped by agent, buttons → ack / mute (reason +
  optional expiry).
- `POST /admin/agents` — mint agent (returns token once; stores only the hash).
- `POST /admin/suppressions`, `GET /admin/suppressions` — manage rules.
- `/admin/*` behind Access **or** an `ADMIN_TOKEN` secret.

**D1 schema** (`migrations/0001_init.sql`):

- `agents(id, name, token_hash, agent_version, desired_version, rollout_bucket, last_report_at, notes)`
- `reports(id, agent_id, received_at, payload_json)` — raw, pruned at 30 days
- `findings(fingerprint PK, agent_id, kind, subject, identifier, severity, title,
  detail, first_seen, last_seen, status, state_json)` — status ∈
  `open | acked | muted | resolved`
- `suppressions(id, kind, subject_glob, identifier_glob, cve_glob, reason, author, created_at, expires_at)`
- `metrics(agent_id, ts, cpu_pct, mem_pct, disk_pct, mongo_data_gb, registry_data_gb)`
- `notifications(fingerprint, sent_at, channel)` — send-once dedupe

**Fingerprint** = `sha256(kind | agent | subject | identifier)`, e.g.
`image-cve | prod-server | postgres:16-alpine | CVE-2026-14456 | libssl3`. Stable
across reports and across image version bumps (keyed on repo, not tag) — the
property the `ignore/*.txt` files were reaching for, done reliably.

**Ingest / lifecycle (this is the false-positive fix):**

1. For each finding in a report, compute fingerprint.
2. Matches an active `suppressions` row → upsert `status = muted`, **no
   notification**.
3. New fingerprint, not suppressed → `status = open`, `first_seen = now`, **send
   one email**.
4. Already `open` and still present → bump `last_seen`, **no email** (kills the
   re-alert churn).
5. Previously-seen fingerprint missing from a report where its check ran →
   `status = resolved` (+ optional "resolved" email).
6. `resolved` fingerprint reappears → back to `open`, email.

**Notifications (Resend API, `re_…` key as a `wrangler secret`, `souspike.com.br`
already verified):** email on — new open finding; reopened finding; agent offline
(Cron Trigger every 15 min: `last_report_at` older than `2×report_interval +
grace`); optional once-daily digest (Cron Trigger) of everything still `open` plus
a muted count. Never: a repeat email for a still-open known finding. Second
channel (Discord/Telegram webhook) is a later drop-in.

## Agent ↔ server auth

- Per-agent token: 32 random bytes, base64. Sent `Authorization: Bearer <token>`.
  Central stores only `sha256(token)` (optionally peppered with a `wrangler
  secret`). TLS is Cloudflare-terminated.
- Body integrity / anti-replay: agent sends `X-Picket-Timestamp` and
  `X-Picket-Signature: hmac-sha256(token, timestamp + "." + rawBody)`; central
  recomputes and rejects on mismatch or >5-min skew → `401`.
- Provisioning: `picketctl mint-agent prod-server` → `POST /admin/agents` → token
  shown once → written to `/etc/picket/token` (0600) by `install.sh`.

## Install & updates (signed self-update + install.sh bootstrap)

- **Release pipeline** (`.github/workflows/release.yml`): build
  `picket-agent_<version>_linux_{amd64,arm64}`, generate `SHA256SUMS`, **cosign
  sign** (keyless OIDC, or a key whose password is a CI secret). Publish binary +
  `SHA256SUMS` + `.sig` to a GitHub Release. The cosign **public key / identity
  is a compiled-in constant** in the agent.
- **Self-update**: when `self_update: true`, the report response carries the
  desired version; if it differs and now ∈ `update_window`, the agent downloads to
  `/var/lib/picket/agent.new`, verifies SHA256 **and** cosign signature against
  the baked-in key, `chmod +x`, atomically `rename()` over
  `/usr/local/bin/picket-agent`, then `systemctl restart picket-agent`
  (`Restart=always` covers a bare exit too).
- **Staggered rollout**: central sets `desired_version` per `rollout_bucket`, so a
  bad build lands on one server first.
- **`deploy/install.sh`** (served from the Worker at `/install.sh` or an R2
  bucket; `curl -fsSL … | sh -s -- --central https://picket.souspike.com.br
  --name prod-server --token <tok>`): create `picket` user + `docker` group
  membership, drop `picket-agent.service`, write `/etc/picket/agent.yaml`
  skeleton + token file, download+verify the current binary, `systemctl enable
  --now`. Re-runnable as the manual upgrade / disaster-recovery path. Replaces
  `server-checks/image-watch/sync-to-servers.sh`.
- systemd unit changes (rare) ride `install.sh --upgrade`.

## Migration & retirement (after ~1 week parallel run)

1. Seed `suppressions` from the seven `server-checks/image-watch/ignore/*.txt`
   files: one row per package (`kind=image-cve`, `subject_glob=<repo>`,
   `identifier_glob=<pkg>`, `reason=` the existing justification comment).
2. Cross-check: for one week, Picket image-CVE findings vs the still-running
   `check-images.sh` Healthchecks pings — expect parity.
3. Remove cron entries for `check-images.sh`, `check-security-updates.sh`,
   `check-pending-restart.sh`, `check-system-health.sh`, `check-cert-expiry.sh`.
4. Delete from the `souspike` repo: `server-checks/image-watch`,
   `server-checks/system-health`, `server-checks/pending-restart`,
   `server-checks/cert-expiry`. **Keep**
   `server-checks/auto-security-updates/setup.sh` + its apt config (provisioning,
   not monitoring) and `custom-docker/check-bases.sh` (needs local Dockerfiles).
5. `check-updates.sh` stays until the weekly review skill replaces it — separate
   effort.
6. **Keep** the self-hosted Healthchecks instance — it still serves the backend
   APScheduler job heartbeats (MTGO / Melee / Scryfall / …), a different concern.
   Picket could absorb these later via a generic heartbeat endpoint; out of scope.

## Secrets hygiene (do not repeat the current mistake)

`souspike`'s `monitoring/.env` and `maintenance/.env` are committed with a live
Resend key and a live Cloudflare API token. In `picket`: Worker secrets via
`wrangler secret put` (`RESEND_API_KEY`, `ADMIN_TOKEN`, `TOKEN_PEPPER`); agent
token only in `/etc/picket/token` (0600, git-ignored); `agent.yaml` carries no
secrets. Rotate the currently-committed CF token and Resend key when standing this
up.

## Build order

1. Worker skeleton: `/api/v1/report` (auth + HMAC + store raw), D1 schema,
   `picketctl mint-agent`. Deploy to `picket.souspike.com.br`.
2. Agent skeleton: config load, three-tier scheduler, reboot-required check only —
   get end-to-end authenticated POST working from one server.
3. Port the image checks (CVEs + tag freshness) onto the heavy tier with caching;
   central findings table + fingerprinting + ingest diff. **This is the core.**
4. Suppression rules + dashboard (list / ack / mute); seed from `ignore/*.txt`.
5. Notifications: Resend, new-finding email, agent-offline cron, daily digest.
6. Remaining cheap/daily checks: apt, stale containers, host health, cert expiry.
7. Release pipeline + cosign + self-update + `install.sh`; roll to all 3 servers.
8. One-week parallel run, then migration steps above.
9. (Separate, later) the weekly dependency-review skill.

## Verification

- `picketctl mint-agent test`; run `picket-agent --oneshot` against
  `wrangler dev`; confirm the row via `wrangler d1 execute picket --command
  "select * from reports"`.
- Point `compose_files` at a compose pinning a known-vulnerable image → confirm
  one `open` finding **and exactly one email**.
- Trigger a second report on the cheap loop → **no second email**, and the
  finding's `last_seen` advanced without a re-scan (the core fix + the caching).
- Add a matching `suppressions` row → next ingest → finding flips to `muted`, no
  email.
- Stop the agent, wait past grace → agent-offline email from the cron trigger.
- `curl` `/api/v1/report` with a bad token → `401`; with a stale
  `X-Picket-Timestamp` → `401`.
- Publish a `v+1` release, set `desired_version` → confirm the agent verifies the
  signature, swaps the binary, restarts, and reports the new version — and that it
  only does so inside `update_window`.
- Parity: Picket image-CVE findings match `check-images.sh` Healthchecks output
  for the whole parallel week.

## Key source files to read in `souspike` before starting

- `server-checks/image-watch/check-images.sh` — the logic to port for v1's core
- `server-checks/image-watch/ignore/*.txt` — seven suppression lists to migrate
- `server-checks/{auto-security-updates,pending-restart,system-health,cert-expiry}/check-*.sh`
- `server-checks/README.md` — the current convention and why Healthchecks `/fail` is overloaded
- `check-updates.sh` — becomes the later review skill, not part of v1
- `monitoring/docker-compose.yml` + `monitoring/.env` — the Resend setup to reuse
- `HACKED.md` — "Fix cronitor false alerts" and the monitoring wishlist
- `soul-spike/app/scheduler.py` `build_healthcheck_url` — the ping pattern the scripts mirror
