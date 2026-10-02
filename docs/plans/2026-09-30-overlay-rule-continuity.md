# Task: stop image changes from orphaning suppression rules and leaving stale findings

You are working in the Picket repo (Go agent in `agent/`, Cloudflare Worker server in `server/`,
`cli/picketctl`, overlays in `custom-docker/`, review skill in `.claude/skills/picket-review/`,
past reviews in `docs/reviews/`). Start by reading the code and docs you need; this brief
deliberately does not pre-chew the design. Plan first, get the plan confirmed, then implement.

## What happened (evidence, from the 2026-09-13 to 2026-09-30 reviews)

1. **Rules orphaned by an image rename.** `monitoria-soul-spike` ran upstream
   `healthchecks/healthchecks:v4.4`. Suppression rules were written with
   `--subject healthchecks/healthchecks`. When the compose file moved to the custom overlay
   `docker.souspike.com.br/healthchecks/healthchecks:4.4-1`, the finding *subject* (bare repo name)
   changed, so none of the rules matched. 62 findings reappeared as "new" and had to be re-reviewed
   and re-suppressed under the new subject (see `docs/reviews/2026-09-16-image-cve.md`).
   47 now-dead rules for the old subject are still in the rules table (28 with no expiry).
2. **Stale findings after an image change.** On 2026-09-30 the overlay was bumped to `4.4-2` and the
   compose file repointed. Fourteen findings that `4.4-2` fixes stayed open (their detail still
   said `...:4.4-1`) because `image-scan` only runs every 12h and the agent hadn't rescanned. A
   `container-stale` finding also fired because the host had pulled `4.4-2` but not recreated the
   container. The user read this as "old muted CVEs are back"; it was not, but it was
   indistinguishable at a glance.
3. Vendored-copy findings (pip's `_vendor` setuptools/msgpack/urllib3) recur on every overlay
   version because the overlay can't fix them; the same suppressions have to exist for the upstream
   image and every overlay of it.

## Goals

- **Rule continuity:** a suppression decision made for an image (upstream or one of our overlays of
  it) should keep applying when the same software is served under a different repo name or tag,
  without a human re-creating every rule. Some way of declaring or detecting "this overlay is
  derived from that upstream" is needed. Decide how: e.g. an alias/lineage mapping, rules that
  match across a set of subjects, deriving the upstream from `custom-docker/<name>/Dockerfile`'s
  `FROM`/`BASE_TAG`, or something else. Weigh the trade-offs yourself.
- **Be careful about what should NOT carry over.** A rule suppressing a package because "no fix
  exists" must not silently cover an overlay that *does* patch that package, and a rule for a
  vendored copy must not mask a real top-level copy. Expiry dates and reasons must survive.
- **No stale-finding window:** when the set of watched image refs (or their pinned tags) changes in
  `compose_files`, findings for refs that are gone should resolve and the new ref should be scanned
  promptly, not up to 12h later. Check how the scheduler's hash-gating and per-kind resolution
  work before deciding.
- **Clearer reporting:** make it obvious in the dashboard/`picketctl` output which scan (image ref
  and digest) a finding came from, so a stale finding is distinguishable from a regression.
- **Housekeeping:** propose what to do with the 47 dead `healthchecks/healthchecks` rules, but
  don't delete anything without confirmation.

## Constraints

- Suppression fingerprints are deliberately `(kind, image, package)` and not CVE-id-wide; keep it
  that way (see the skill's Step 3 rationale).
- Agent and server deploy separately: agents self-update via signed GitHub releases
  (`agent/internal/selfupdate`, `release.yml`, `picketctl release add` + `rollout`); the Worker is
  deployed with `npx wrangler deploy`. Any change spanning both must be safe with mixed versions
  (agents are currently on v0.1.0/v0.2.0). A migration under `server/migrations/` may be needed.
- `/picket-review` is read-only for rules and compose files. If the solution changes how rules are
  written, update the skill's instructions and `docs/` to match.
- Don't push, tag, deploy, or run `picketctl rules add/rm` without asking first.

## Deliverables

1. A short plan (options considered, chosen approach, migration/rollout, test plan) for review.
2. After approval: implementation with tests (Go tests under `agent/internal/...`, server tests if
   present), docs updates, and the skill update.
3. A note on how to verify against the real `monitoria-soul-spike` data without suppressing real
   findings.
