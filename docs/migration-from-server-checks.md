# Migration from `souspike/server-checks`

> Stub. Execute after ~1 week of parallel running (PLAN.md "Migration & retirement").

## 1. Seed suppressions from the ignore lists

```sh
cd cli/picketctl
export PICKET_URL=https://picket.souspike.com.br PICKET_ADMIN_TOKEN=...
./picketctl seed-ignores ../../../souspike/server-checks/image-watch/ignore
```

One `suppressions` row per package line: `kind=image-cve`,
`subject_glob=<repo>` (filename with `_`→`/`), `identifier_glob=*|<pkg>`,
`reason=` the file's comment block. Review with `./picketctl rules list`.

## 2. Parity window

For one week, compare Picket `image-cve` findings against the still-running
`check-images.sh` Healthchecks pings. Expect the same set of images flagged and
the same CVEs (modulo suppressions).

## 3. Retire crons

Remove cron entries for `check-images.sh`, `check-security-updates.sh`,
`check-pending-restart.sh`, `check-system-health.sh`, `check-cert-expiry.sh`.

## 4. Delete from `souspike`

`server-checks/image-watch`, `.../system-health`, `.../pending-restart`,
`.../cert-expiry`. **Keep** `server-checks/auto-security-updates/setup.sh` +
apt config (provisioning) and `custom-docker/check-bases.sh` (needs local
Dockerfiles).

## 5. Not in scope

`check-updates.sh` stays until the weekly dependency-review skill replaces it.
Keep the self-hosted Healthchecks instance — it still serves the backend
APScheduler heartbeats.
