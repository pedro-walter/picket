# Dead suppression rules — cleanup proposal (2026-10-02)

**Proposal only. Nothing here has been run.** Prepared as part of
[`docs/plans/2026-10-02-overlay-rule-continuity-plan.md`](../plans/2026-10-02-overlay-rule-continuity-plan.md)
(phase 1, housekeeping). Data: read-only `picketctl rules list` / `findings` against production on 2026-10-02,
analysed locally with the same `auditRules`/`diffLineage` code the new `picketctl rules audit` and `lineage`
preview use (those endpoints are not deployed yet, so the audit was run offline, not against the Worker).

## Findings

| | count |
|---|---|
| rules on `healthchecks/healthchecks` (upstream subject) | 47 |
| ...of which match **zero** current open/acked/muted findings ("dead") | **47** |
| ...of which have no `expires_at` | 28 |
| ...of which have an overlay-subject "twin" (same kind / identifier glob / cve glob on `docker.souspike.com.br/healthchecks/healthchecks`) | 39 |
| ...of which have no twin | 8 |
| rules on the overlay subject (re-created 2026-09-16), all with expiry | 22 |

The 8 without a twin are `libsqlite3-0`, `openssl-provider-legacy`, `openssl`, `libssl3t64`, `libssh2-1t64`, `gzip`
(apt packages the `4.4-1` overlay upgraded) and `sqlparse`, `cryptography` (no longer reported by trivy at all, per
the 2026-09-16 review). They have no twin because there is nothing left to suppress, which is the expected shape,
not a gap: no current finding on the overlay mentions any of those packages.

**Effect of deleting all 47:** none on current findings. They match nothing, and at the default `inherit=none`
they would not reach the overlay even once the lineage edge exists (replay with the edge declared: 0 findings
change status). Deleting them also removes 28 rules that had no expiry, contrary to the review skill's
"every rule expires" rule.

## Proposed commands (review, then run yourself)

Each line's trailing comment: identifier / cve / expiry / twin on the overlay (or `none`).

```sh
cd cli/picketctl
./picketctl rules rm cfe5aaf8-e444-42d4-be1a-66987e59bdca   # *|libudev1 / * / NO EXPIRY / twin: 095c9f8d-ad82-478b-91e0-f0b6d89f0c3e
./picketctl rules rm 43a7e837-1f2f-44e4-b73f-2670339b2b36   # *|libsystemd0 / * / NO EXPIRY / twin: b67f54f1-c576-4819-9026-eadf36a7eeda
./picketctl rules rm 339f6ea4-4115-4e95-97c3-0391f96620ea   # *|libsqlite3-0 / * / NO EXPIRY / twin: none
./picketctl rules rm 3b75c986-611d-425d-95fe-1c55a446ea05   # *|openssl-provider-legacy / * / NO EXPIRY / twin: none
./picketctl rules rm 1436873e-2cbb-4847-8fd6-2c34d4fbf35a   # *|openssl / * / NO EXPIRY / twin: none
./picketctl rules rm 5e56d743-723e-48f4-80db-a4f9a5fb5f05   # *|libssl3t64 / * / NO EXPIRY / twin: none
./picketctl rules rm 3e762556-ac79-4350-b78c-9d6e307ff999   # *|sqlparse / * / NO EXPIRY / twin: none
./picketctl rules rm d5330790-3b8c-4132-9c71-8f09f0b3316d   # *|libssh2-1t64 / * / NO EXPIRY / twin: none
./picketctl rules rm eddf324d-2431-4eb1-a606-b167efa8432e   # *|libcurl4t64 / * / NO EXPIRY / twin: 33dce6f2-e31c-4301-8269-518367d654cf
./picketctl rules rm 95ed3142-d803-4496-ba96-de47483703fd   # *|cryptography / * / NO EXPIRY / twin: none
./picketctl rules rm 6c584153-5b28-4ba5-b907-4ab67082f20b   # *|libacl1 / * / NO EXPIRY / twin: 6bf4cb95-c809-458e-befd-08bd127cbd5d
./picketctl rules rm 77b0481d-5b52-4b7b-b811-a0902a1b0095   # *|gzip / * / NO EXPIRY / twin: none
./picketctl rules rm 32da10c3-284c-4388-8d7b-da4fe6e4fdad   # *|util-linux / * / NO EXPIRY / twin: 6629a608-1c55-4b71-b0be-7e75f9ad0059
./picketctl rules rm 2ce6a6b1-08ac-4993-abe1-f7c90476883f   # *|mount / * / NO EXPIRY / twin: 32ce6352-094c-46bf-bdc7-278057816f62
./picketctl rules rm 0b6b04ec-f0e9-4191-8e2d-e5bad163c214   # *|login / * / NO EXPIRY / twin: 90da017e-7c7d-461d-aa1b-dbefbc8319fb
./picketctl rules rm 2605d39c-4bde-4fb9-90a5-8567d31a7aee   # *|libuuid1 / * / NO EXPIRY / twin: d14de44c-57e2-4b15-819a-a2179c0baed7
./picketctl rules rm f2f585e9-7e1d-47b4-9ddb-539e58416bcf   # *|libsmartcols1 / * / NO EXPIRY / twin: af55795e-d171-4d94-8e2f-6b0f58d96f81
./picketctl rules rm 2fa13784-1fb5-4f6a-aac0-e1261781c108   # *|libmount1 / * / NO EXPIRY / twin: 81097c80-fd79-4c98-aeb2-f53b3c1cf8aa
./picketctl rules rm 85cf38a1-884c-4cb2-8121-713b3ca79fca   # *|liblastlog2-2 / * / NO EXPIRY / twin: b279a2e7-14fa-41cf-afd6-136819bdb276
./picketctl rules rm 4c350458-f5cb-4ead-9bec-f286a17d56ae   # *|libblkid1 / * / NO EXPIRY / twin: 1bd73907-60a8-47b3-a466-605560bed936
./picketctl rules rm 66f679c0-c528-4041-a068-fc6896e5389c   # *|bsdutils / * / NO EXPIRY / twin: bfa2d2ef-f8b7-4692-b989-b104996f3076
./picketctl rules rm 490c5026-3251-4ae3-85d3-7de016b094ac   # *|libtinfo6 / * / NO EXPIRY / twin: 06153093-f22d-4271-92c7-b5eaf517f791
./picketctl rules rm ebb9e2be-5534-4a56-82e8-e4e1dc97724e   # *|libncursesw6 / * / NO EXPIRY / twin: aefe5c6c-a267-4cf6-85a2-4f66aa5f5542
./picketctl rules rm 1bc6143f-dd94-41a3-9e58-71da4eb8a25a   # *|ncurses-bin / * / NO EXPIRY / twin: 0bfde7f3-a390-4db9-843e-171db7588082
./picketctl rules rm 1beb495c-0c94-4cec-afd3-2150742eb920   # *|ncurses-base / * / NO EXPIRY / twin: bbce980a-bc5e-4d42-8bd2-53ccbe1db378
./picketctl rules rm d7912f57-ab3f-4c09-b54b-e68e1efb7144   # *|perl-base / * / NO EXPIRY / twin: bb356f5e-a579-423f-beaf-18a6b1826966
./picketctl rules rm 6328218e-59bb-4f62-be3c-a9cbe40ebbf6   # *|mariadb-common / * / NO EXPIRY / twin: ebd4f8c7-d9df-4544-9e9b-61d19618538e
./picketctl rules rm 19e83420-6252-4ff5-8f5f-31efcccec18d   # *|libmariadb3 / * / NO EXPIRY / twin: f185dc48-630e-4ba8-93e2-6ab88260a23d
./picketctl rules rm 42e809aa-b74d-4e18-bde1-50776e1006f8   # *|mariadb-common / * / 2026-12-12T12:51:03Z / twin: ebd4f8c7-d9df-4544-9e9b-61d19618538e
./picketctl rules rm a0181aea-6321-44e0-a3f0-547e94837cd0   # *|libmariadb3 / * / 2026-12-12T12:51:03Z / twin: f185dc48-630e-4ba8-93e2-6ab88260a23d
./picketctl rules rm 570efc91-d7d3-40ce-998b-420179967937   # *|libudev1 / * / 2026-12-12T12:51:03Z / twin: 095c9f8d-ad82-478b-91e0-f0b6d89f0c3e
./picketctl rules rm 95be329e-e530-4808-9bc1-892615c77544   # *|libsystemd0 / * / 2026-12-12T12:51:03Z / twin: b67f54f1-c576-4819-9026-eadf36a7eeda
./picketctl rules rm 1c15cdaa-925e-450e-8cf0-0f07c5169979   # *|ncurses-bin / * / 2026-12-12T12:51:03Z / twin: 0bfde7f3-a390-4db9-843e-171db7588082
./picketctl rules rm 2d501e6d-5f83-4bf0-a0b1-9face3ebd0f3   # *|ncurses-base / * / 2026-12-12T12:51:03Z / twin: bbce980a-bc5e-4d42-8bd2-53ccbe1db378
./picketctl rules rm da157a2d-3cd8-4690-9917-defb60326632   # *|libtinfo6 / * / 2026-12-12T12:51:03Z / twin: 06153093-f22d-4271-92c7-b5eaf517f791
./picketctl rules rm bf64bde7-dd45-40b3-94d9-641fc5c7e497   # *|libncursesw6 / * / 2026-12-12T12:51:03Z / twin: aefe5c6c-a267-4cf6-85a2-4f66aa5f5542
./picketctl rules rm 024f8a0f-f14a-4cb8-9106-aef8178d7c44   # *|libacl1 / * / 2026-12-12T12:51:03Z / twin: 6bf4cb95-c809-458e-befd-08bd127cbd5d
./picketctl rules rm 1c21c8c6-9c89-4706-9c04-6fceaf488cf5   # *|libcurl4t64 / * / 2026-12-12T12:51:03Z / twin: 33dce6f2-e31c-4301-8269-518367d654cf
./picketctl rules rm de7088c3-e1d5-4709-93b3-e7d901ccda3f   # *|util-linux / * / 2026-12-12T12:51:03Z / twin: 6629a608-1c55-4b71-b0be-7e75f9ad0059
./picketctl rules rm 270e2a2e-0783-4e29-918c-9ac51dc1384e   # *|mount / * / 2026-12-12T12:51:03Z / twin: 32ce6352-094c-46bf-bdc7-278057816f62
./picketctl rules rm d6be5997-14bc-4dc3-9103-b91f04c70308   # *|login / * / 2026-12-12T12:51:03Z / twin: 90da017e-7c7d-461d-aa1b-dbefbc8319fb
./picketctl rules rm ac47c474-f67f-4d3f-b9bb-48a847eb89b1   # *|libuuid1 / * / 2026-12-12T12:51:03Z / twin: d14de44c-57e2-4b15-819a-a2179c0baed7
./picketctl rules rm 1b7285d9-de1b-456a-afb9-6abc5b0209ee   # *|libsmartcols1 / * / 2026-12-12T12:51:03Z / twin: af55795e-d171-4d94-8e2f-6b0f58d96f81
./picketctl rules rm 21a3cb71-9027-418a-b5db-006772e7797d   # *|libmount1 / * / 2026-12-12T12:51:03Z / twin: 81097c80-fd79-4c98-aeb2-f53b3c1cf8aa
./picketctl rules rm 7c6488a2-8373-41ec-bf86-5e806e710443   # *|liblastlog2-2 / * / 2026-12-12T12:51:03Z / twin: b279a2e7-14fa-41cf-afd6-136819bdb276
./picketctl rules rm 353691ff-7a47-43ca-ac38-fe79c507c7c8   # *|libblkid1 / * / 2026-12-12T12:51:03Z / twin: 1bd73907-60a8-47b3-a466-605560bed936
./picketctl rules rm a33022e6-4aa7-4e81-af86-aef3fee743c6   # *|bsdutils / * / 2026-12-12T12:51:03Z / twin: bfa2d2ef-f8b7-4692-b989-b104996f3076
```

## Not part of that list — but noticed

Dead rules on other subjects (their packages no longer appear in findings), none touched by lineage:

- `traefik` `*|libcrypto3` cve `*` — expires never
- `traefik` `*|libssl3` cve `*` — expires never
- `postgres` `*|libuuid` cve `*` — expires never
- `postgres` `*|libcrypto3` cve `*` — expires never
- `postgres` `*|libssl3` cve `*` — expires never
- `mongo` `*|golang.org/x/text` cve `*` — expires never
- `mongo` `*|golang.org/x/net` cve `*` — expires never
- `ghcr.io/project-zot/zot` `*|github.com/go-git/go-git/v5` cve `*` — expires never
- `postgres` `*|libuuid` cve `*` — expires 2026-10-04T12:49:40Z
- `traefik` `*|libssl3` cve `CVE-2026-14456` — expires 2026-10-04T12:48:35Z
- `traefik` `*|libcrypto3` cve `CVE-2026-14456` — expires 2026-10-04T12:48:35Z
- `postgres` `*|libssl3` cve `CVE-2026-14456` — expires 2026-10-04T12:48:35Z
- `postgres` `*|libcrypto3` cve `CVE-2026-14456` — expires 2026-10-04T12:48:35Z

The five that carry an expiry all expire **2026-10-04**; since they are dead, letting them lapse is fine. The
no-expiry ones (`traefik`/`postgres` libssl3/libcrypto3, `mongo` golang.org/x/*, `zot` go-git) have no findings
to hide today; deleting them is a separate call and not proposed here.

## After deleting

`picketctl rules audit` should show no `dead` rule on `healthchecks/healthchecks` and every remaining rule on the
overlay subject with an expiry. Once the Worker with lineage is deployed, run `picketctl lineage sync
../../custom-docker` (preview first) and expect zero findings to flip.
