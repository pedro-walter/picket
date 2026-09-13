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

- [`healthchecks/healthchecks/`](./healthchecks/healthchecks/Dockerfile) —
  patches perl-base/libpcre2-8-0/libsqlite3-0/gzip/libssh2-1t64/libssl3t64/
  openssl/openssl-provider-legacy (apt) + setuptools/msgpack (pip) on top
  of `healthchecks/healthchecks:v4.4`, upstream's frozen newest tag as of
  2026-09-13. Built and pushed as
  `docker.souspike.com.br/healthchecks/healthchecks:4.4-1` — see
  [`docs/reviews/2026-09-13-image-cve.md`](../docs/reviews/2026-09-13-image-cve.md)
  for the full finding list and
  [`docs/reviews/2026-09-13-image-cve-soul-spike.md`](../docs/reviews/2026-09-13-image-cve-soul-spike.md)
  for verification of the built image. Still not pointed at by any compose
  file (`/picket-review` doesn't do that) — the image sitting in the
  registry doesn't clear Picket's findings on its own; someone has to
  update whichever docker-compose.yml pins this image and redeploy.

## Why upstream freshness can't be automatic once an overlay exists

Once an image is overlaid and pinned to `docker.souspike.com.br/<name>:<version>`,
Picket's `image-tag` check on the agent side only ever sees tags *we've*
pushed to that repo — the upstream repository isn't in the picture
anymore. `/picket-review`'s Docker-Hub-tag-freshness check (Step 2 of the
skill) is what has to catch "upstream shipped a real release, retire this
overlay" instead, since it still has the Dockerfile's `ARG BASE_TAG` on
hand to know what upstream repo/tag to compare against — the agent doesn't.
