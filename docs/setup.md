# Setup — what you need to do

Two independent things:

- **Part 1 — Go toolchain** on this machine, so the agent (`picket-agent`) can
  be built and tested. Blocks build-order steps 2–3.
- **Part 2 — deploy the central Worker** to `picket.souspike.com.br`. Blocks a
  real end-to-end run; local `wrangler dev` already works without it.

Hand back the checklist at the bottom when done.

---

## Part 1 — install Go (sudo)

`go.mod` needs Go **1.23+**; install current stable (1.25+ in 2026). Pick one:

### Option A — official tarball (recommended, gets latest)

```sh
GO_VER=$(curl -sL "https://go.dev/VERSION?m=text" | head -1)   # e.g. go1.25.1
curl -fsSL "https://go.dev/dl/${GO_VER}.linux-amd64.tar.gz" -o /tmp/go.tgz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go.tgz
rm /tmp/go.tgz

# add to PATH (once)
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
```

### Option B — apt (simpler, may be a version or two behind)

```sh
sudo apt update && sudo apt install -y golang-go
```

If `go version` prints < 1.23, use Option A instead.

### Option C — snap

```sh
sudo snap install go --classic
```

### Verify

```sh
go version                       # want go1.23 or newer
cd ~/development/picket/agent && go build ./... && echo "agent builds"
```

`go build ./...` on the current skeleton exits non-zero at runtime only
(`main` is a stub) — it just needs to **compile**. That's the green light.

**Not needed:** `build-essential` / gcc (the agent builds with `CGO_ENABLED=0`),
and `trivy` / `crane` (the agent downloads and manages those itself at runtime).

---

## Part 2 — deploy the central Worker

All commands run from `~/development/picket/server` unless noted.

### 2.1 Authenticate wrangler to Cloudflare (once)

```sh
cd ~/development/picket/server
npx wrangler login          # opens a browser; approve
npx wrangler whoami         # confirm the right account
```

Headless alternative: create an API token (My Profile → API Tokens →
*Edit Cloudflare Workers* template, add **D1: Edit**), then
`export CLOUDFLARE_API_TOKEN=...` (and `CLOUDFLARE_ACCOUNT_ID=...` if the
account has more than one).

### 2.2 Create the D1 database

```sh
npx wrangler d1 create picket
```

Copy the printed `database_id` into `server/wrangler.toml`, replacing
`"local-dev-placeholder"`:

```toml
[[d1_databases]]
binding = "DB"
database_name = "picket"
database_id = "<paste-the-uuid-here>"
migrations_dir = "migrations"
```

Apply the schema to the remote DB:

```sh
npx wrangler d1 migrations apply picket --remote
```

### 2.3 Secrets

```sh
# strong random values
openssl rand -base64 32        # -> use as ADMIN_TOKEN
openssl rand -base64 32        # -> use as TOKEN_PEPPER

npx wrangler secret put ADMIN_TOKEN      # paste value 1
npx wrangler secret put TOKEN_PEPPER     # paste value 2
npx wrangler secret put RESEND_API_KEY   # paste a Resend key (see below)
```

**Rotate the Resend key.** `souspike/monitoring/.env` and
`souspike/maintenance/.env` are committed with a live `re_…` key — do **not**
reuse it. In the Resend dashboard: create a **new** API key for Picket, put
that one here, then delete the old key. While there, confirm `souspike.com.br`
shows **verified** under Domains (it should already); `ALERT_FROM` in
`wrangler.toml` is `picket@souspike.com.br`, `ALERT_TO` is
`pedrohardware@gmail.com` — edit those vars if you want different addresses.

> `TOKEN_PEPPER` is mixed into stored agent-token hashes and must not change
> after agents are minted (it would invalidate every token). Set it once.

### 2.4 Custom domain `picket.souspike.com.br`

The `souspike.com.br` zone is already on Cloudflare, so add to
`server/wrangler.toml`:

```toml
[[routes]]
pattern = "picket.souspike.com.br"
custom_domain = true
```

`wrangler deploy` (next step) then provisions the DNS record and certificate.
You can also set `workers_dev = false` in the same file once the custom domain
resolves, to turn off the `*.workers.dev` URL.

*(Dashboard alternative: Workers & Pages → `picket` → Settings → Domains &
Routes → Add Custom Domain.)*

### 2.5 Deploy

```sh
npx wrangler deploy
```

This also registers the two cron triggers from `wrangler.toml`
(`*/15 * * * *` offline sweep, `0 13 * * *` daily digest) — nothing extra to do.

Smoke test:

```sh
curl -s https://picket.souspike.com.br/healthz      # -> ok   (may take a few min for DNS/cert)
# until the custom domain is live, use the workers.dev URL wrangler printed
```

### 2.6 Protect `/admin/*` and the dashboard

**Quick path (v1-acceptable):** do nothing here — the Worker already requires
`ADMIN_TOKEN` for `/admin/*` and `/` (dashboard at `/?token=<ADMIN_TOKEN>`).
Keep `ADMIN_TOKEN` long and secret.

**Recommended — add Cloudflare Access** (Zero Trust → Access → Applications):

1. **App A — protect the console.** Add application → Self-hosted.
   - Subdomain `picket`, domain `souspike.com.br`, **path blank** (whole host).
   - Policy: *Allow*, Include → Emails → `pedrohardware@gmail.com`.
   - Identity: Google (configure once under Zero Trust → Settings →
     Authentication), or "One-time PIN" for zero setup.
2. **App B — let agents through.** Add application → Self-hosted.
   - Subdomain `picket`, domain `souspike.com.br`, **path `api/v1/report`**.
   - Policy: **Bypass**, Include → Everyone.
   - Cloudflare matches the most specific path, so agent POSTs skip Access
     while everything else stays gated. (Add a third Bypass app for path
     `healthz` if you want uptime pings unauthenticated.)

With Access on, the dashboard works at plain `https://picket.souspike.com.br/`
(no `?token=`); `picketctl` still uses `PICKET_ADMIN_TOKEN`.

### 2.7 Verify end-to-end

```sh
cd ~/development/picket/cli/picketctl
export PICKET_URL=https://picket.souspike.com.br
export PICKET_ADMIN_TOKEN=<the ADMIN_TOKEN you set>

./picketctl mint-agent prod-server           # prints a token ONCE — save it
./picketctl seed-ignores ~/development/souspike/server-checks/image-watch/ignore
./picketctl rules list
./picketctl list-agents
```

Open `https://picket.souspike.com.br/` (or `…/?token=$PICKET_ADMIN_TOKEN`
without Access) — you should see `prod-server` under agents, no findings yet.

---

## Checklist to hand back

- [ ] `go version` output (want ≥ 1.23) and `cd agent && go build ./...` compiles
- [ ] `curl https://picket.souspike.com.br/healthz` → `ok`
- [ ] `wrangler d1 migrations apply picket --remote` succeeded
- [ ] `ADMIN_TOKEN`, `TOKEN_PEPPER`, `RESEND_API_KEY` set as Worker secrets
- [ ] old Resend key (in `souspike/monitoring/.env`) **revoked**, new one in use
- [ ] `database_id` committed into `server/wrangler.toml`
- [ ] the `prod-server` agent token from `picketctl mint-agent` (I'll need it to
      wire the agent), plus the `ADMIN_TOKEN` — or you keep both and run
      `picketctl` yourself
- [ ] Cloudflare Access configured, or a note that you're staying on
      `ADMIN_TOKEN`-only for now

Once Go is in, I'll start on `picket-agent` (three-tier scheduler +
reboot-required check for a first authenticated POST, then the image
CVE / tag-freshness checks). That work runs against local `wrangler dev`, so it
doesn't wait on the deploy.
