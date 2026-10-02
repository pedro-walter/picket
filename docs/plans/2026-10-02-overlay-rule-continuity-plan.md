# Plan: rule continuity across overlays, no stale-finding window, clearer scan provenance

Status: **draft for review**. Nothing implemented. Brief: `2026-09-30-overlay-rule-continuity.md`.
Numbers quoted from the brief (62 re-reviewed findings, 47 dead rules, 28 without expiry) are not re-verified
against production; the plan's first implementation step against real data is read-only.

## What the code does today (root causes)

1. **Rules match `finding.subject` only** (`server/src/suppress.ts`). The subject is the bare repo, so tag
   bumps are already free, but a repo rename (`healthchecks/healthchecks` ->
   `docker.souspike.com.br/healthchecks/healthchecks`) is a different string. Nothing relates an overlay to its
   upstream anywhere in the system. The relationship exists only in `custom-docker/<name>/Dockerfile`
   (`FROM <repo>:${BASE_TAG}`), which no agent or Worker ever sees.
2. **Stale window = interval gating, not a resolve bug.** `image-scan` runs on a 12h ticker
   (`scheduler.Run`). A compose change is invisible until the next tick or a restart (`sectionStale`). Until
   then the agent sends the old hash only; central bumps `last_seen` and resolves nothing
   (`ingest.ts`, hash-match branch). Once a new body does arrive, resolution is correct (kind has current state,
   fingerprint absent -> resolved). So the fix is *when we rescan*, not how central resolves.
   Second trap: the hash covers findings only. If a ref changes but the finding set is identical, the hash is
   unchanged, the body is never resent, and `detail` keeps naming the old ref.
3. **Collapsed duplicates.** `ImageCVE.scanOne` dedups on `CVE|pkg` across all trivy results and keeps the
   first, dropping `PkgPath`. A pip-vendored `setuptools` and a real top-level `setuptools` become one finding.
   A rule written for the vendored copy therefore also mutes the real one (and a rule "for the top-level copy"
   can't be written). This is the "vendored copy must not mask a real copy" problem, and it already exists.
4. **Muted findings only re-open when a body arrives.** `muted && !supp -> open` lives in the per-finding diff,
   which only sees findings in a body. With hash-only image-scan reports, an expired or deleted rule leaves its
   findings muted until the next hash change. `DELETE /admin/suppressions/:id` doesn't unmute either. Lineage
   makes rules longer-lived and wider, so this matters more; see Phase 1, item 6.

## Options considered for rule continuity

| option | how | verdict |
|---|---|---|
| A. Server-side lineage table | `image_lineage(subject -> upstream)`, rules inherit via it at match time | **chosen** |
| B. Agent derives it | image OCI label (`org.opencontainers.image.base.name`) read from trivy's image metadata | rejected as primary: needs agent release, and `4.4-1`/`4.4-2` are already pushed without labels (rebuild required). Could be a later *source* feeding table A. |
| C. Wildcard rules (`--subject '*healthchecks/healthchecks'`) | no code | rejected: matches unrelated forks/mirrors, no notion of "derived", and nothing helps when the repo name differs more than by prefix |
| D. Rewrite fingerprints to a canonical subject | agent/server canonicalise subject | rejected: changes fingerprints (re-opens everything, breaks `notifications`/history) and loses which image actually produced the finding. Fingerprint stays `(kind, agent, subject, identifier)` as required. |
| E. Copy rules on overlay creation | `picketctl` clones upstream rules to overlay subject | rejected: that's today's manual re-creation, automated; copies drift, expiries diverge, and the dead-rule pile grows. |

Why A: it needs no agent change (works with agents v0.1.0/v0.2.0), keeps fingerprints and subjects untouched,
is explicit/auditable, and the data to fill it comes from a file we already own (the overlay Dockerfiles).

### Design of A

- **Table `image_lineage`**: `subject TEXT PK` (the overlay's finding subject, e.g.
  `docker.souspike.com.br/healthchecks/healthchecks`), `upstream TEXT NOT NULL` (e.g.
  `healthchecks/healthchecks`), `note`, `created_at`, `source` (`manual` | `dockerfile`). Resolved
  transitively (overlay of an overlay), depth-capped at 5, cycle-safe (a write that would create a cycle is
  rejected).
- **Direction**: an overlay *inherits* from its ancestors, never the reverse. A rule written for an overlay
  does not touch the upstream image.
- **New column `suppressions.inherit`**: `none` | `unfixed` | `all`, **default `none`**. Existing rules and any
  rule created without the flag behave exactly as today. A rule only reaches a descendant subject if its
  author opted in:
  - `unfixed`: inherited only while the finding has **no published fix**. Intended for "no fix exists yet"
    rules. If the overlay's base gains a fix (or trivy reports `-> fixed in`), the rule stops applying and
    the finding opens, which is the "must not silently cover an overlay that could patch it" case.
  - `all`: inherited regardless of fix availability. For decisions about reachability, not fix status:
    pip-vendored copies, `gosu`-style unused binaries, with the evidence in `--reason`.
- **Guards that need no new information**: expiry is evaluated on the rule exactly as now (the active-rule
  query already filters `expires_at`), the matched rule id is what lands in `state_json.suppressed_by`
  (reason/author/expiry stay attributable to the original decision), and I add `suppressed_via` (the ancestor
  subject that matched) so the dashboard/CLI can say "muted by rule X inherited from `<upstream>`".
- **"Has a published fix"**: agent v0.3+ sends a structured `fixed_version`; older agents don't, so the server
  falls back to detecting `-> fixed in` in `detail` (the format `imagecve.go` writes today and the skill relies
  on). Both paths are tested.
- **Fill the table from the Dockerfiles, not by hand**: `picketctl lineage sync custom-docker/` parses each
  `custom-docker/<name>/Dockerfile` (`FROM <repo>:${BASE_TAG}`, `ARG` substitution) and the registry default
  from `build-and-push.sh` (`PICKET_REGISTRY`), then **prints** the proposed pairs and the effect (below). It
  writes only with `--apply`. Manual `picketctl lineage add|rm|list` for images with no overlay Dockerfile.
- **Preview before commit** (also the answer to verification, deliverable 3): `GET /admin/lineage/preview`
  runs the match with the candidate edge and returns, per open/acked/muted finding on that agent+subject,
  "currently X -> would be Y, by rule Z". `picketctl lineage add|sync` shows this by default and requires
  `--apply` to write. Applying a lineage edge also does the same retroactive sweep `applyNewSuppression`
  does for a new rule.
- **Skill update**: Step 3 category B ends with the exact `picketctl lineage add ...` line for the new overlay
  (printed, never run, same read-only contract as rules). Category C rules gain `--inherit unfixed|all` with the
  guidance above; the "report" template shows it. `custom-docker/README.md` documents the lineage step as part of
  "pointing a compose file at an overlay".

## No stale-finding window

Agent change (v0.3.0), no server change required:

- `SectionSpec` gets an optional `Inputs func() (string, error)` returning a cheap digest of the section's
  inputs. For `image-scan` that is the sorted set of watched refs from `compose.WatchedImages` (pure file
  parsing, no network). It is persisted in the section's state.
- Each cheap cycle (15m) compares the current inputs digest with the stored one; on mismatch it triggers
  `sectionCycle` for that section immediately (off the cheap path, so a multi-minute trivy run doesn't delay the
  host report), then runs one extra `cheapCycle` as soon as it finishes so central gets the body without
  waiting another 15m. Worst case is ~15m + scan time, down from up to 12h. Agent restart behaviour unchanged.
- The section hash includes the scanned refs and digests (see next section), so a ref/digest change always
  forces a body even if the finding set is identical.
- First version rescans the whole section on change (trivy has its own cache; simplest and correct). Per-ref
  incremental scanning is possible later and is not needed to close the window.
- Central needs nothing: a body for a kind with current state already resolves absent fingerprints. Findings for
  a *removed* ref resolve on that body; findings for the new ref open (or are muted via lineage).

Mixed versions: v0.1.0/v0.2.0 agents keep the 12h behaviour (no regression); upgrading is what removes the
window. There is no server dependency in either direction.

## Clearer reporting

- Agent v0.3.0 adds optional per-finding `image_ref`, `image_digest` (trivy's `Metadata.RepoDigests`/`ImageID`
  from the JSON it already requests, so no extra call) and `fixed_version`. Old Worker ignores unknown fields;
  old agents simply omit them.
- Migration `0004`: `findings.image_ref`, `findings.image_digest`, `findings.scanned_at` (nullable),
  `agent_sections.scans_json` (the section's list of `{ref, digest}` actually scanned).
- Dashboard: a "scanned image" column (`<ref>@<short digest>`, age of the scan); a finding whose `image_ref` is
  not in the agent's current `scans_json`, or whose section is older than 2x its interval, is labelled
  **stale scan** instead of looking like a live finding. Muted-by-inheritance shows the source.
- `picketctl findings` already prints raw rows, so the new columns appear automatically; add `picketctl scans`
  (per agent: section, generated_at, confirmed_at, refs+digests).
- `container-stale` detail currently says "container is on X, local tag resolves to Y". Extend with the compose
  pin and the running container's configured image ref (`docker inspect .Config.Image`) so "host pulled 4.4-2,
  container still on 4.4-1" is readable as exactly that and not as a CVE regression.

## Vendored copies (separable phase)

Stop collapsing the vendored and top-level copies: when trivy's `PkgPath` is under a `/_vendor/` or `/vendor/`
directory the agent emits identifier `CVE|pkg@vendored`; top-level copies keep `CVE|pkg`. Rules for vendored
copies are then `*|pkg@vendored` with `--inherit all`, and cannot mask a top-level copy.

- Compatibility shim in the Worker so this ships without a re-review: a rule whose `identifier_glob` matches the
  identifier **with the `@vendored` suffix stripped** keeps matching, i.e. legacy `*|setuptools` rules behave as
  today. Housekeeping then rewrites legacy vendored rules to the explicit form, after which a real top-level
  copy is no longer masked.
- **Verified 2026-10-02 (trivy on the real images)**: the discriminator is *absence* of `PkgPath`, not a
  `/_vendor/` path. On `4.4-1`, `urllib3 2.7.0` appears twice in the python-pkg results: one with
  `PkgPath=usr/local/lib/python3.14/site-packages/urllib3-2.7.0.dist-info/METADATA` (top-level) and one with no
  `PkgPath` (pip's vendored copy); the same for setuptools/msgpack on the vendored side. So the rule is: python-pkg
  vulnerability with empty `PkgPath` => `@vendored`. Today's `seen[CVE|pkg]` dedup collapses exactly these pairs.
  Samples: scratchpad `hc-4.4-1.json`, `hc-4.4-2.json`, `hc-4.4-2-all.json`. Still to decide before Phase 3:
  whether other ecosystems (node, jar) behave the same; python only at first.

## Housekeeping: the 47 dead `healthchecks/healthchecks` rules

Proposal only; nothing is deleted without your say-so.

1. New read-only `picketctl rules audit`: per rule, how many findings it matches now (direct vs inherited),
   whether any finding on its subject exists, whether it has no expiry, and whether another rule already covers
   the same `(kind, subject-lineage, identifier, cve)`. Same logic as the preview endpoint.
2. With the lineage edge declared, the 47 stay inert (their `inherit` is `none`), so the lineage change itself
   neither revives them nor needs them. The overlay-subject rules created on 2026-09-16 already carry the same
   decisions.
3. Recommended disposition, to be confirmed against the audit output: **delete all rules with zero matches that
   have an overlay-subject twin** (expected to be all 47), as an explicit list of `picketctl rules rm <id>`
   commands in a review doc. For the 28 with no expiry, don't promote them to inheriting rules; if any is
   still wanted it is recreated with `--expires` and `--inherit`, which is what the skill already requires.
4. Add `PATCH /admin/suppressions/:id` (`expires_at`, `inherit`) so existing live rules (e.g. the 2026-09-16
   overlay rules) can be given an explicit `inherit` mode and expiry without delete/recreate losing history.
5. Close the re-open gap (root cause 4): a daily cron sweep re-evaluates `muted` findings whose
   `suppressed_by` rule no longer exists or has expired and reopens them; `DELETE /suppressions/:id` does the
   same for its own findings. Needed because lineage extends how long and how widely a rule applies.
   Pause for your call on whether this belongs in this change (see questions).

## Phasing, migration and rollout

| phase | ships | depends on | fixes |
|---|---|---|---|
| 1 | Worker + CLI + skill/docs: migration `0004a` (lineage table, `suppressions.inherit`), matcher, preview, `lineage`/`rules audit`/`rules patch`, expiry sweep | nothing; works with every agent version | rule continuity, housekeeping |
| 2 | Agent v0.3.0 + migration `0004b` (scan columns) + dashboard/CLI reporting | phase 1 not required, either order is safe | stale window, provenance, fix-guard precision |
| 3 | Vendored split + shim | trivy JSON check; phase 1 | vendored-vs-top-level masking |

- Migrations are additive (new table, nullable columns, defaulted column); existing `INSERT`s use explicit
  column lists and the CLI prints `SELECT *`, so a rolled-back Worker is safe on the new schema.
- Deploy order: `wrangler d1 migrations apply` (remote), `npx wrangler deploy`, then agents:
  `picketctl release add 0.3.0`, `rollout 0.3.0 <canary bucket>` first, then the rest. Agents must not need the new
  Worker, and the new Worker must not need new agents, so each step can pause indefinitely.
- Nothing here is pushed, tagged, deployed or applied to rules/lineage by me without asking.

## Test plan

Go (`agent/internal/...`):
- `scheduler`: inputs-digest change triggers a section cycle outside the interval and an immediate follow-up
  report; unchanged inputs don't; a failing scan keeps the old cache (existing behaviour); hash changes when
  only ref/digest changes.
- `checks/imagecve`: fixture trivy JSON -> `image_ref`/`image_digest`/`fixed_version` populated; (phase 3)
  vendored vs top-level same `CVE|pkg` yield two findings; unchanged identifiers for non-vendored.
- `compose`: ref-set digest stable under reorder/comments, changes on tag/repo change.
- `checks/containers`: new detail text.

Worker (vitest, `server/test/`):
- `suppress.test.ts`: inherit none/unfixed/all x fix present/absent (structured field and `detail` fallback);
  transitive lineage; cycle rejected; expired rule not inherited; direction (rule on overlay doesn't hit
  upstream); `unfixed` rule does not mute `PyJWT ... fixed in 2.14.0` on the overlay while muting the same
  package unfixed; legacy rules unaffected by default.
- `ingest.test.ts`: finding on overlay subject muted via upstream rule with `suppressed_via` recorded;
  scan columns stored; `last_seen`-only path leaves them intact; expiry sweep reopens.
- Lineage apply/preview endpoints: preview writes nothing; apply mutes exactly the previewed set.

## Verifying against real `monitoria-soul-spike` data without suppressing anything real

1. Read only: `picketctl rules list`, `findings --agent monitoria-soul-spike --status open` to snapshot.
2. Local replay: export prod D1 (`wrangler d1 export --remote`, read-only) into a local D1, then run the new
   Worker under `wrangler dev` against that copy. All mutation happens in the local copy.
3. `lineage sync --dry` (preview) for `docker.souspike.com.br/healthchecks/healthchecks` ->
   `healthchecks/healthchecks`. Expected: zero newly-muted findings for rules left at `inherit=none`; after
   setting `unfixed`/`all` on a **copy** of a rule locally, only no-fix and vendored findings flip, and every
   `-> fixed in` finding (PyJWT, top-level urllib3, openssl `deb13u3`) stays open.
4. Replay stored `reports.payload_json` from 2026-09-14 and 2026-09-30 through the local Worker with the lineage
   edge and compare to what actually happened: the 62 findings should be covered by inherited rules, the 2026-09-30
   fixable ones should still open.
5. Agent: `picket-agent --oneshot` with a temp state dir, temp config, and compose copy pointing at 4.4-1,
   against `wrangler dev` only; edit the copy to 4.4-2 and confirm a rescan within one (shortened) cheap
   interval and that `4.4-1` findings resolve. Run trivy on the real 4.4-2 image to settle the Phase 3 `PkgPath`
   assumption.
6. Only after you've looked at 3-5 do we discuss pointing prod at it.

## Decisions (2026-10-02)

1. Lineage source: `picketctl lineage sync` from `custom-docker/*/Dockerfile`. OCI labels not pursued now.
2. `inherit` defaults to `none`; explicit `unfixed|all` only.
3. Phase 3 (vendored split) waited for the trivy check; it is now viable (see Phase 3 section) and still comes after phases 1-2.
4. Expiry/removal sweep: **included in phase 1** (delegated). Reason: lineage widens and lengthens rule reach,
   and the fix is small (daily cron + reopen on rule delete) and independent of the agent.
5. OK to prepare the `rules rm` list for the 47 as a review doc; nothing executed.

## Original questions (answered above)

1. Lineage source: table filled by `picketctl lineage sync` from `custom-docker/*/Dockerfile` (recommended)
   vs also adding OCI labels in `build-and-push.sh` as a second source later.
2. Rule opt-in: `inherit` default `none` with explicit `unfixed|all` (recommended, no behaviour change on
   deploy) vs default `unfixed` for new rules created by the skill.
3. Phase 3 (vendored split): include now, or defer until the trivy `PkgPath` check?
4. Expiry/removal sweep (root cause 4): include in phase 1, or separate change?
5. Housekeeping: OK to prepare the `rules rm` list for the 47 as a review doc (no execution)?
