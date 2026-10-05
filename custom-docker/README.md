# Custom Docker overlays

Small Dockerfiles that patch a third-party image ourselves (an `apt`/`apk`/
`pip` package bump) instead of waiting on upstream to rebuild, pushed to
the Soul Spike infra's private registry. Same pattern as
`souspike/custom-docker`, generated here instead because `/picket-review`
(`../.claude/skills/picket-review/SKILL.md`) is the thing deciding *when*
one is warranted — a "category B" finding: no newer upstream tag exists,
but the distro has already published a fix.

```
<name>/
└── Dockerfile     # ARG BASE_TAG=<pinned tag>, FROM <upstream>:${BASE_TAG}
```

Unlike `souspike/custom-docker`, there's one shared [`build-and-push.sh`](./build-and-push.sh)
instead of a copy per overlay — `/picket-review` only has to write the
Dockerfile, then call `./build-and-push.sh <name> <version> [base-tag]` to
build and push `docker.souspike.com.br/<name>:<version>`. It needs a real
docker daemon and registry auth already in place, so it only actually
builds+pushes when the skill is run from a host that has both (a dev
machine or a server) — from a sandboxed session it writes the Dockerfile
and says so plainly instead of pretending to have pushed anything.

An overlay is a stopgap, never a permanent fork: drop it the moment
upstream cuts a release that already includes the fix (`/picket-review`
checks this on every run and will say so once it's true), and remove the
compose file's now-unnecessary pin back to the real upstream image at that
point — see `souspike/custom-docker/README.md`'s own retirement history
for what that looked like the last two times.

Current overlays:

- [`tecnativa/docker-socket-proxy/`](./tecnativa/docker-socket-proxy/Dockerfile) —
  `apk upgrade pcre2` (Alpine 3.24 fix 10.49-r0) on top of
  `tecnativa/docker-socket-proxy:v0.5.0`, upstream's newest tag (last pushed
  2026-07-27). Pushed as `docker.souspike.com.br/tecnativa/docker-socket-proxy:0.5.0-1`
  on 2026-10-05; compose not yet pointed at it. See
  [`docs/reviews/2026-10-05-image-cve.md`](../docs/reviews/2026-10-05-image-cve.md).
- [`healthchecks/healthchecks/`](./healthchecks/healthchecks/Dockerfile) —
  patches perl-base/libpcre2-8-0/libsqlite3-0/gzip/libssh2-1t64/libssl3t64/
  openssl/openssl-provider-legacy (apt) + setuptools/msgpack (pip) on top
  of `healthchecks/healthchecks:v4.4`, upstream's frozen newest tag as of
  2026-09-13. Built and pushed as
  `docker.souspike.com.br/healthchecks/healthchecks:4.4-1`, and
  `monitoria-soul-spike`'s compose file has been pointed at it — confirmed
  by `docker inspect` (image created 2026-09-13T10:35:47-03:00, never
  rebuilt since) during the 2026-09-16 review. See
  [`docs/reviews/2026-09-13-image-cve.md`](../docs/reviews/2026-09-13-image-cve.md)
  for the original finding list,
  [`docs/reviews/2026-09-13-image-cve-soul-spike.md`](../docs/reviews/2026-09-13-image-cve-soul-spike.md)
  for verification of the built image (fixes landed, still runs as the `hc`
  user), and
  [`docs/reviews/2026-09-16-image-cve.md`](../docs/reviews/2026-09-16-image-cve.md)
  for what Picket found once it rescanned the overlay itself (all
  suppress, no rebuild needed yet). **`4.4-2`** (2026-09-30, pushed; compose
  not yet pointed at it) adds PyJWT/urllib3 (pip) and the openssl
  `deb13u3` point release — see
  [`docs/reviews/2026-09-30-image-cve.md`](../docs/reviews/2026-09-30-image-cve.md).

## Declare the overlay's lineage (so suppression decisions carry over)

Pointing a compose file at `docker.souspike.com.br/<name>:<version>` changes Picket's finding *subject* to
`docker.souspike.com.br/<name>`. Rules written for the upstream subject don't see it until the relationship is
declared (once per overlay, not per version):

```sh
cd cli/picketctl
./picketctl lineage sync ../../custom-docker            # preview: what would be muted / reopened
./picketctl lineage sync ../../custom-docker --apply
```

`sync` derives the pair from each `<name>/Dockerfile` (`FROM <repo>:${BASE_TAG}` -> `<repo>`). Only rules
that opted in (`--inherit unfixed|all`) are inherited; see
[`../docs/architecture.md`](../docs/architecture.md#suppression-rules-and-image-lineage).

## Why upstream freshness can't be automatic once an overlay exists

Once an image is overlaid and pinned to `docker.souspike.com.br/<name>:<version>`,
Picket's `image-tag` check on the agent side only ever sees tags *we've*
pushed to that repo — the upstream repository isn't in the picture
anymore. `/picket-review`'s Docker-Hub-tag-freshness check (Step 2 of the
skill) is what has to catch "upstream shipped a real release, retire this
overlay" instead, since it still has the Dockerfile's `ARG BASE_TAG` on
hand to know what upstream repo/tag to compare against — the agent doesn't.
