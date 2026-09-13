---
name: picket-review
description: "Use for the periodic (~weekly) review of Picket's open image-cve findings: for every image/package decide whether to bump the pinned tag, ship a custom rebuild, or suppress with a documented reason, then produce a reviewable report plus ready-to-run picketctl commands. Invoke as /picket-review [agent-name]. Never applies anything on its own."
---

# Picket image-CVE review

This is the "weekly dependency-review skill" from `PLAN.md`'s build order
(step 9), scoped to what's actually populating Picket's dashboard: the
`image-cve` findings `trivy` reports off each server's `compose_files`. It
replaces staring at `picketctl findings` by hand and reasoning about each
CVE individually — the same reasoning done ad hoc after the first
`monitoria-soul-spike` scan (2026-09-13, 113 findings).

**Contract: read-only.** This skill produces a report and a block of
ready-to-run commands. It never runs `picketctl rules add`, edits a
compose file, or writes a Dockerfile that gets built — those are for the
user to execute after reading the report. If asked to "apply" a report,
that's a separate, explicit instruction outside this skill's contract, not
something to do as part of running it.

Run from the repo root. Needs `cli/picketctl/picketctl` and
`~/.config/picket/picketctl.env` (or `PICKET_URL`/`PICKET_ADMIN_TOKEN` in
the environment) — same config the operator already uses.

## Step 1 — Pull the current backlog

```sh
cd cli/picketctl
./picketctl findings --status open > /tmp/picket-review-findings.json
```

If invoked with an agent name argument, add `--agent <name>` and scope the
whole review to it; otherwise review every agent in one pass — findings
already carry `agent_name`, so group by `(agent_name, subject)` in that case
rather than just `subject`, since two servers can pin the same image at
different tags.

```sh
jq -r '[.findings[] | select(.kind=="image-cve")] | group_by(.subject) | map({subject: .[0].subject, n: length}) | .[]' /tmp/picket-review-findings.json
```

Also pull `image-tag` findings (same call, filter `kind=="image-tag"`) and
existing suppression rules (`./picketctl rules list`) — `findings
--status open` already excludes anything `muted`, so nothing here re-treads
a suppression that's already in force; the rules list is just useful
context for phrasing a *new* rule consistently with existing ones.

## Step 2 — Per-image context (no SSH, no compose greps)

Everything needed lives in the findings themselves:

- **Currently pinned tag** — every `image-cve` finding's `detail` starts
  with trivy's own `<repo>:<tag> (<os>): ...` prefix (e.g.
  `healthchecks/healthchecks:v4.4 (debian 13.6): perl-base 5.40.1-6 -> ...`).
  Parse it from there. If a `detail` doesn't carry it, say so in the report
  instead of guessing.
- **Is a newer tag already available?** — an `image-tag` finding with the
  same `subject`; its `identifier` is `<current>-><latest>`.
- **Is a fix published?** — trivy appends `-> fixed in <version>` to
  `detail` whenever the distro repo has one. Its absence means "no fix
  exists yet," full stop — don't infer one.

## Step 3 — Classify every open `image-cve` finding

Work image by image, and within an image, package by package — never
CVE-number by CVE-number across images. Blanket-suppressing a CVE ID
everywhere it appears is exactly what `server-checks/image-watch/ignore/*.txt`
did and the reason Picket fingerprints on `(kind, image, package)` instead.

**A — Bump the pinned tag.** A newer tag exists (Step 2) and the affected
package is plausibly part of the base OS layer a rebuild would refresh
(not something the newer tag's own Dockerfile might still pin the same
way). This is usually the highest-leverage fix — one tag bump can clear
dozens of OS-package CVEs at once (see `healthchecks/healthchecks` below).
State plainly that this is **not verified fixed** until Picket rescans the
new tag on its next `image-scan` cycle — recommend the bump, don't also
suppress the finding it's meant to clear.

**B — Custom rebuild.** No newer upstream tag, but `detail` shows a
`FixedVersion` (the distro has already shipped the fix; upstream just
hasn't re-cut the image). Batch every such package for one image into a
single thin Dockerfile rather than one per CVE:

```dockerfile
FROM <repo>:<current-tag>
RUN apt-get update \
 && apt-get install --only-upgrade -y <pkg1> <pkg2> ... \
 && rm -rf /var/lib/apt/lists/*
```

Flag it explicitly as a stopgap in the report — drop the rebuild the
moment upstream publishes a tag that already includes the fix, and note
which compose service(s) would need `build:` instead of `image:` to use it
(you don't know the compose file path from Picket data alone; say "wherever
this image is pinned" and let the user place it).

**C — Suppress.** Only when B doesn't apply: `detail` carries no
`FixedVersion` yet (nothing to install even if you wanted to), or you have
concrete evidence — not an assumption from the package name — that the
package is unused at runtime in this container (state the evidence in the
reason). Every suppression rule gets `--expires` ~90 days out; there is no
permanent, unreviewed ignore here. Write `--reason` as the actual
justification a future reader (including next week's you) can check —
"no fix published yet for CVE-2026-56862 in postgres's bundled Go runtime
as of 2026-09-13" is a reason; "low risk" alone is not.

## Step 4 — Write the report

`docs/reviews/<YYYY-MM-DD>-image-cve.md`, one section per image:

```markdown
## healthchecks/healthchecks (v4.4 -> v5.0 available)

| CVE | package | sev | fix published | action | why |
|---|---|---|---|---|---|
| CVE-2026-13221 | perl-base | critical | yes (5.40.1-6+deb13u1) | bump tag | OS package; v5.0 rebuild expected to carry the Debian point release |
| ... | | | | | |

**Suppress (90d, re-review next pass):**
​```sh
./picketctl rules add --kind image-cve --subject healthchecks/healthchecks \
  --identifier '*|<pkg>' --cve <CVE> --reason "..." --expires <date+90d>
​```
```

Close with a short summary: total findings reviewed, counts per action
(bump / rebuild / suppress), and which images got no clean recommendation
(surface those to the user by name instead of guessing).

## Step 5 — Hand it back

Print the report path and the summary counts in your reply. Do not run any
of the printed commands, and do not create the Dockerfiles as real files
in the repo — inline them in the report as fenced code the user copies
if they want them. Applying a suppression or cutting a rebuild is a
judgment call about the team's own risk tolerance; this skill's job ends at
giving them what they need to make it in under a minute.
