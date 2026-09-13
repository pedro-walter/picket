---
name: picket-review
description: "Use for the periodic (~weekly) review of Picket's open image-cve findings: for every image/package decide whether to bump the pinned tag, ship a custom rebuild (writing + building + pushing a custom-docker/ overlay), or suppress with a documented reason, then produce a reviewable report plus ready-to-run picketctl commands. Invoke as /picket-review [agent-name]. Never applies a suppression rule or touches a compose file on its own."
---

# Picket image-CVE review

This is the "weekly dependency-review skill" from `PLAN.md`'s build order
(step 9), scoped to what's actually populating Picket's dashboard: the
`image-cve` findings `trivy` reports off each server's `compose_files`. It
replaces staring at `picketctl findings` by hand and reasoning about each
CVE individually — the same reasoning done ad hoc after the first
`monitoria-soul-spike` scan (2026-09-13, 113 findings).

**Contract.** For suppression rules and compose files this is read-only:
the skill produces a report and a block of ready-to-run `picketctl rules
add` commands, and never runs them or edits a compose file itself — those
are for the user to execute after reading the report. For a "custom
rebuild" (category B below) it's allowed to go further and actually build
the thing: writing a real `custom-docker/<name>/Dockerfile` and running
`custom-docker/build-and-push.sh` to build and push it to the registry,
since a pushed image tag is inert until a compose file is pointed at it —
see [`../../../custom-docker/README.md`](../../../custom-docker/README.md).
It never edits a compose file to actually start using the image it built.
If asked to "apply" a suppression from a report, that's a separate,
explicit instruction outside this skill's contract, not something to do as
part of running it.

Run from the repo root. Needs `cli/picketctl/picketctl` and
`~/.config/picket/picketctl.env` (or `PICKET_URL`/`PICKET_ADMIN_TOKEN` in
the environment) — same config the operator already uses. Building and
pushing an overlay additionally needs a real docker daemon and registry
auth already set up, which only a real host has, not a sandboxed session —
see Step 3's category B for how to degrade gracefully when either is
missing.

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

- **Currently pinned tag** — trivy scans one "Target" per OS-package layer
  AND one per embedded language-runtime binary it finds inside the image;
  only the OS-layer one's `detail` starts with `<repo>:<tag> (<os>): ...`
  (e.g. `postgres:16-alpine (alpine 3.24.1): libssl3 ...`). A binary target
  instead prefixes with its in-image path (e.g. `usr/local/bin/gosu: stdlib
  v1.24.6 -> ...` — that's a Go stdlib CVE baked into a vendored helper
  binary, not an OS package). **Scan every finding for the subject**, not
  just the first, and take the tag from whichever one matches
  `^<repo>:<tag> \(`. If none do, say so in the report instead of guessing.
- **Is a newer tag already available?** — an `image-tag` finding with the
  same `subject`; its `identifier` is `<current>-><latest>`. Zero
  `image-tag` findings across the board is itself informative (nothing
  agent-side looks newer), but it can't tell rolling-tag-already-rebuilt
  from truly-nothing-newer — for a public image, a quick registry check
  disambiguates: Docker Hub's tags API needs no auth for public repos,
  e.g. `curl -fsS "https://hub.docker.com/v2/repositories/<repo>/tags?page_size=100&name=<prefix>"
  | jq -r '.results[] | "\(.name)\t\(.last_updated)"'` — the `last_updated`
  on the currently-pinned tag itself tells you whether/when it was last
  rebuilt.
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

Before choosing between A/B/C, note whether the pinned tag is **rolling** or
**frozen** — it changes what "wait for upstream" means. A major-only or
`-alpine`/`-slim` style tag (`16-alpine`, `v3.7`) is periodically rebuilt
*in place* by the vendor with a newer base image, same tag name — check its
last-push date on the registry (e.g. Docker Hub's `tags` API) against
today; if the vendor rebuilds every few weeks, a plain re-pull may already
carry the fix, or will soon. A version-pinned release tag (`v4.4`) is
frozen forever — it never gets newer packages baked in on its own, so
"wait for a rebuild" isn't a real option; only a new upstream release
(check the registry for one — that's category A) or your own rebuild
(category B) actually fixes it.

**B — Custom rebuild.** No newer upstream tag, but `detail` shows a
`FixedVersion` (the distro has already shipped the fix; upstream just
hasn't re-cut the image). Batch every such package for one image into a
single thin overlay rather than one per CVE, and actually materialize it
under `custom-docker/` (see [`custom-docker/README.md`](../../../custom-docker/README.md)
for the pattern — same idea as `souspike/custom-docker`, one shared
`build-and-push.sh`):

1. Pick `<name>` = the image's own repo name with `/` kept as-is if it has
   one (`healthchecks/healthchecks`, `postgres`) — it becomes the registry
   path `docker.souspike.com.br/<name>`. If `custom-docker/<name>/` already
   exists from a prior review, read its Dockerfile first: same `BASE_TAG`
   means this is a follow-up patch (bump the version's numeric suffix), a
   different `BASE_TAG` means upstream already moved and the old overlay's
   packages need re-checking against the new base before you reuse any of
   them.
2. Write `custom-docker/<name>/Dockerfile`:
   ```dockerfile
   ARG BASE_TAG=<current-tag>
   FROM <repo>:${BASE_TAG}
   USER root
   RUN apt-get update -q \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade \
         <pkg1> <pkg2> ... \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
   USER <original-runtime-user>
   ```
   A `pip`-installed package (not apt) needs its own `RUN pip install
   --no-cache-dir -U <pkg>` line instead — check which is which; don't
   guess. If the base image's apt sources pin a frozen `snapshot.debian.org`
   timestamp older than the fix (the same issue the prior
   `souspike/custom-docker/healthchecks` overlay hit on `v4.3`), point
   `/etc/apt/sources.list.d/debian.sources` at the live suites first,
   the way that overlay's Dockerfile did — check with `docker run --rm
   <repo>:<tag> cat /etc/apt/sources.list.d/debian.sources` if you have
   docker access, otherwise say in the report that this is unverified and
   the build may need it. **Only re-add `USER <original-user>` if you
   actually know that user's name** (a prior overlay for the same repo, or
   something you can verify) — if you don't, leave the image running as
   root rather than guess a username that might not exist and break the
   container at start time, and say plainly in the report that this needs
   a human to confirm the right non-root user before it's used.
3. Build and push it:
   ```sh
   custom-docker/build-and-push.sh <name> <version> [<base-tag>]
   ```
   `<version>` is `<base-tag-without-leading-v>-<n>` (`4.4-1`, `4.4-2`
   for a follow-up patch on the same base). This needs a working docker
   daemon and registry auth — if either is missing (check `docker info`
   first) the script fails fast and says so; when that happens, still
   commit the Dockerfile, and tell the user in the report to run that exact
   `build-and-push.sh` command themselves from a host that has both. Never
   claim an image was pushed unless the script actually reported success.
4. List the new overlay in `custom-docker/README.md`'s "Current overlays"
   section, same as `souspike/custom-docker` tracks its own.

Flag it explicitly as a stopgap in the report — drop the overlay the
moment upstream publishes a tag that already includes the fix — and note
which compose service(s) would need updating to `image:
docker.souspike.com.br/<name>:<version>` to actually use it (you don't know
the compose file path from Picket data alone; say "wherever this image is
pinned" and let the user place it — the skill never edits a compose file).

**C — Suppress.** Only when B doesn't apply: `detail` carries no
`FixedVersion` yet (nothing to install even if you wanted to), or you have
concrete evidence — not an assumption from the package name — that the
package is unused at runtime in this container (state the evidence in the
reason). Every suppression rule gets `--expires` ~90 days out; there is no
permanent, unreviewed ignore here. Write `--reason` as the actual
justification a future reader (including next week's you) can check —
"no fix published yet for CVE-2026-56862 in postgres's bundled Go runtime
as of 2026-09-13" is a reason; "low risk" alone is not.

A binary-target finding (the `usr/local/bin/<name>: stdlib ...` shape from
Step 2) is a stdlib CVE compiled into a *specific vendored helper binary*,
not the image's actual service. It's a legitimate "unused at runtime"
argument only when you can say what that binary's job actually is and that
the vulnerable stdlib package isn't on its path — e.g. `gosu` in official
Docker images is a minimal setuid-then-exec wrapper that never opens a
network connection, so a `crypto/tls` finding inside it is very likely dead
code; a `libc`/`syscall` finding in the same binary is not the same claim.
Say which binary and what you know about its actual scope in the reason;
don't wave every embedded-binary CVE through as unreachable by category
alone, and still put an expiry on it.

## Step 4 — Write the report

`docs/reviews/<YYYY-MM-DD>-image-cve.md`, one section per image:

```markdown
## healthchecks/healthchecks (v4.4 -> v5.0 available)

| CVE | package | sev | fix published | action | why |
|---|---|---|---|---|---|
| CVE-2026-13221 | perl-base | critical | yes (5.40.1-6+deb13u1) | bump tag | OS package; v5.0 rebuild expected to carry the Debian point release |
| ... | | | | | |

**Custom rebuild — pushed:**
`custom-docker/healthchecks/Dockerfile` built and pushed as
`docker.souspike.com.br/healthchecks/healthchecks:4.4-1` (or, if the build
couldn't run here: "Dockerfile committed at `custom-docker/.../Dockerfile`;
build+push it yourself with `custom-docker/build-and-push.sh
healthchecks/healthchecks 4.4-1` from a host with docker + registry
access"). State whichever actually happened — never phrase it as done if
the script didn't run or failed.

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

Print the report path and the summary counts in your reply, and for each
category-B image whether its overlay actually got built+pushed or only
committed as a Dockerfile (say which, and if only committed, give the
exact `build-and-push.sh` command to finish it). Do not run any of the
printed `picketctl rules add` commands, and do not edit any compose file —
those stay for the user to execute after reading the report. Applying a
suppression is a judgment call about the team's own risk tolerance; a
custom rebuild's actual construction isn't (it's mechanical once the
package list is known), which is why this skill builds and pushes that
part itself when it can, but still leaves pointing a compose file at the
result to the user.
