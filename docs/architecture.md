# Architecture

> Stub — expand as the build progresses. Authoritative design is `../PLAN.md`.

## Components

- **`picket-agent`** — long-lived systemd daemon on each server. One internal
  scheduler: a cheap tier every `report_interval` (15m) plus one goroutine per
  lower-cadence *section*. All scanning happens here.
  - cheap (15m): `reboot` (`/var/run/reboot-required`); `apt` (`apt-get -s
    dist-upgrade`, security vs regular by origin, plus the latest
    unattended-upgrades run's WARNING/ERROR lines); `container-stale`
    (`docker inspect` running image id vs the compose-pinned tag's local id,
    report-only); and a metrics sample (`/proc/stat`, `/proc/meminfo`,
    `statfs`, `du` of the data dirs) - central evaluates the forwarded
    thresholds and owns the resulting `host-health` findings.
  - `image-scan` section (12h): `image-cve` (`trivy image --severity
    HIGH,CRITICAL --format json`) and `image-tag` (`crane ls` + `crane digest
    --platform linux/amd64` for same-major newer tags, floating-tag aware).
    Watched images = every `image:` line in `compose_files`, minus first-party
    `soul-spike-backend`/`-web`. Raw CVEs are sent - no ignore-list filtering
    agent-side. Binaries resolve from `<state-dir>/bin` then `$PATH`.
  - `daily` section (24h): `cert-expiry` - a real TLS dial per `domains:` entry
    (Go `crypto/tls`, `InsecureSkipVerify` to read `NotAfter` even off a broken
    chain). Tool-binary refresh joins here at step 7.
  - Section results are cached to `state.json` and reported hash-gated (below).
    A check that errors is left out of the reported kinds; a section whose every
    check errors keeps its previous cached result rather than clearing it.
- **`picket` central** — Cloudflare Worker (Hono) + D1 + Resend. Aggregates,
  fingerprints, applies suppressions, runs the finding lifecycle, emails, serves
  the dashboard, runs the dead-man + digest cron. Only outbound HTTP is Resend.
- **`picketctl`** — admin CLI over the `/admin/*` API.

## Request flow

```
picket-agent --(POST /api/v1/report, Bearer + HMAC)--> Worker
   Worker: store raw report -> fingerprint (cheap findings + any section bodies)
        -> match suppressions -> lifecycle diff (open/muted/resolved/reopened)
        -> email on change
        -> respond { desired_version, url, sha256, sig_url,
                     sections_ack, sections_need_body }
```

## Report sections (hash-gated)

One endpoint, one cadence on the wire. The cheap tier's findings + metrics are
always inline and fresh. Each lower-cadence tier rides in `sections.<name>`:

```jsonc
"sections": {
  "image-scan": {
    "hash": "<sha256 of the section's canonical (kinds, findings)>",
    "generated_at": "<agent-side scan time>",
    "checks_run": ["image-cve", "image-tag"],
    "scans": [{ "ref": "reg/hc:4.4-2", "digest": "sha256:..." }],  // agent >= 0.3.0, also on hash-only reports
    "findings": [ ... ]        // present ONLY until central acks this hash
  }
}
```

- Agent includes `findings` while `hash != acked_hash` (from `state.json`).
  Central ingests + diffs the body, upserts `agent_sections`, replies
  `sections_ack: { "image-scan": "<hash>" }`; the agent records it and drops the
  body on subsequent reports.
- On a hash-only report where `hash` matches the stored one: central refreshes
  `confirmed_at` + `last_seen` for those kinds and does **nothing else** — no
  re-diff, and crucially **no resolution** (it has no current finding list).
- On a hash-only report whose `hash` is unknown (fresh DB, lost report):
  central replies `sections_need_body: ["image-scan"]`; the agent resends the
  full body next cycle.
- **Resolution** of a section's kinds happens only when a body arrives (hash
  changed) and a previously-open finding is absent from it — so a CVE fixed by
  `docker compose pull` clears on the next scan, not before. The scan runs every
  12h **or** as soon as the watched refs change (below).
- **Rescan on compose change (agent >= 0.3.0).** A section may declare an
  `Inputs` digest (for `image-scan`: the sorted `image:` refs from
  `compose_files`, pure file parsing). Each cheap cycle compares it with the
  digest the cached scan was made with; on a mismatch the section rescans in
  the background and one extra report follows, so a repointed compose file
  resolves old-ref findings and scans the new ref within ~15m + scan time
  instead of up to 12h. A failing rescan for the same inputs is not retried for
  an hour. A cache written by an older agent has no digest and rescans once.
  The section hash covers the scanned `(ref, digest)` list, so a changed ref
  or a rebuilt image always sends a body even if the finding set is identical.
  Agents < 0.3.0 keep the 12h behaviour.
- **Scan provenance.** `image-cve` findings carry `image_ref`, `image_digest`
  and `fixed_version`; central stores `findings.image_ref/image_digest/
  scanned_at` (overwritten whenever a body carries the finding, left alone by
  cheap and hash-only cycles) and `agent_sections.scans_json`. The dashboard
  shows a "scanned image" column (marked **stale scan** when the section stopped
  refreshing); `picketctl scans` prints per agent and section when the scan ran
  and which refs/digests it covered. A `container-stale` detail now reads
  "compose pins X; container was created from Y (image …), the local tag now
  resolves to …" so a pulled-but-not-recreated overlay is not mistaken for a
  CVE regression.
- **Stale detection**: the `*/15` cron flags a section whose `generated_at` is
  older than `SECTION_STALE_SECONDS` (~26h) — the heavy tier has stopped — and
  emails once, *without* resolving its findings.

## Finding fingerprint

`sha256( kind \n agent_name \n subject \n identifier )`, hex.

`subject` is chosen by the agent to be stable across version bumps — the bare
repo (`postgres`), never the pinned tag. This is the property the old
`ignore/*.txt` filename matching was reaching for, done reliably.

## Lifecycle

| Transition | Trigger | Email |
|---|---|---|
| → open | new fingerprint, not suppressed | yes (one) |
| → muted | matches an active suppression row | no |
| open, still present | seen again in a later report | no (bump `last_seen`) |
| → resolved | absent from a report that carried current state for its kind (cheap `checks_run`, or a section body) | optional |
| resolved → open | reappears | yes |
| muted → open | its suppression rule removed/expired, or the lineage edge it relied on removed | yes (the `*/15` cron sweep and rule/lineage admin calls reopen it; no wait for a scan body) |

## Suppression rules and image lineage

A rule is `(kind, subject_glob, identifier_glob, cve_glob)` plus `reason`, `expires_at` and `inherit`.
Matching is on the finding's own subject unless the rule opts in to lineage.

`image_lineage` (`subject` -> `upstream`) declares that an image is derived from another, e.g. the overlay
`docker.souspike.com.br/healthchecks/healthchecks` from `healthchecks/healthchecks`. It is only read at
match time; fingerprints and subjects never change. A rule with `inherit != none` also matches a finding whose
**ancestor** subject matches its `subject_glob` (transitive, depth 5, cycle-rejected). Descendants inherit from
ancestors, never the reverse.

| `inherit` | reaches overlays | use for |
|---|---|---|
| `none` (default) | no | everything pre-existing, one-off mutes |
| `unfixed` | only while the finding has no published fix (`fixed_version`, else `-> fixed in` in `detail`) | "no fix exists yet" decisions: an overlay that could patch the package is not silenced |
| `all` | yes, fix or not | reachability decisions with evidence (pip-vendored copies, unused binaries) |

**Vendored python copies (agent >= 0.4.0).** A python-pkg vulnerability with no `PkgPath` in trivy's output (pip's
bundled setuptools/urllib3/msgpack) gets identifier `CVE|pkg@vendored`; the top-level install keeps `CVE|pkg`. The
matcher also tries a rule's `identifier_glob` against the identifier with `@vendored` stripped (`legacyIdentifier`
in `server/src/suppress.ts`), so legacy `*|pkg` rules keep covering both. A rule written as `*|pkg@vendored`
covers only the vendored copy, so it can no longer mask a real top-level one. Deploy the Worker before 0.4.0.

The matched rule's id lands in `findings.state_json.suppressed_by` (so reason/author/expiry stay those of the
original decision) and the ancestor it matched through in `suppressed_via`.

`reevaluateFindings` (`server/src/lineage.ts`) re-applies rules + lineage to stored findings: after rule
delete/patch, lineage add/remove, and every `*/15` cron. Ingest only re-diffs findings in a report body and
hash-gated sections rarely send one, so without it an expired rule would keep findings muted.

## Auth

- Per-agent token (32 random bytes, base64), `Authorization: Bearer`. Central
  stores `sha256(TOKEN_PEPPER || token)` only.
- `X-Picket-Timestamp` (unix seconds) + `X-Picket-Signature:
  hmac-sha256(token, timestamp + "." + rawBody)`. >5-min skew or mismatch → 401.
- `/admin/*` + dashboard: Cloudflare Access (prod) or `ADMIN_TOKEN`.

## Self-update

- `release.yml` (on a `v*` tag) builds static `linux/{amd64,arm64}` binaries,
  `SHA256SUMS`, and per-binary `.sig` files (`cosign sign-blob --key`, i.e.
  ECDSA-P256 over SHA-256, base64 DER), and publishes a GitHub Release.
- `picketctl release add <v> --base-url … --sha256sums …` writes a `releases`
  row; `picketctl rollout <v> [bucket]` sets `agents.desired_version` for that
  `rollout_bucket` (staggered rollout).
- The report response carries `{ desired_version, url, sha256, sig_url }` for
  the agent's `arch`. If `self_update` and the version differs and now ∈
  `update_window`, the agent downloads to a temp file **beside** its binary,
  checks the SHA-256, verifies the signature with the compiled-in public key
  (`selfupdate.SigningPublicKeyPEM`), `rename()`s over
  `/var/lib/picket/bin/picket-agent`, and exits — systemd `Restart=always`
  runs the new one. An empty/placeholder key, a missing `releases` row, or any
  verification failure → no swap.

## Tool binaries

`tools.Ensure` (run on the `image-scan` and `daily` section `Prepare` hooks
when `tools.auto_manage`) downloads the pinned `crane`/`trivy` release tar.gz
for the agent's arch, verifies its SHA-256 against the compiled-in `tools.Default`
pins, extracts the binary into `<state-dir>/bin`, and stamps a `.version` file
so subsequent runs are no-ops until the pin is bumped.
