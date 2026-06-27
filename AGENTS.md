# AGENTS.md — marketplace-catalog

> **Read this first.** Single source of truth for how this repository works.
> If reality and this file disagree, fix this file in the same PR.
>
> Docs site: https://docs.aihummer.ru · Org policy: [AiHummer/.github · GOVERNANCE.md](https://github.com/AiHummer/.github/blob/main/GOVERNANCE.md)

## 1. Purpose
The **public plugin registry** for AiHummer — the producer side of the public
marketplace flow (P3, `AiHummer/docs/MARKETPLACE-PUBLISHING-DESIGN.md`). Third
parties register a publisher and open PRs adding signed plugin submissions; CI
validates them; on merge the registry counter-signs and publishes the official
`catalog.json` to the CDN. It is **NOT** the core gateway (`AiHummer/AiHummer`,
which owns trust/signing/sync code) and **NOT** where plugin source or artifacts
live (authors host their own `.tar.gz`). This repo holds only metadata +
submissions + the CI that gates them.

## 2. Architecture map
- `publishers/<publisher>.json` — one-time publisher identity (public key, key_id, contact).
- `catalog/<publisher>/<slug>/plugin.json` — a submission (the stable contract the SDK's `publish --public` emits).
- `scripts/validate.mjs` — self-contained PR validator (node:crypto only, **no core repo import, no npm deps**).
- `scripts/build-catalog.mjs` — counter-signs each release with the registry key, EXCLUDES `revoked.json` entries, and assembles `catalog.json` (core's `{modules:[…]}` shape).
- `.github/scripts/ai-review.mjs` — advisory AI risk review (reads PR diff via API, STATIC artifact inspection, posts a comment; never executes PR code, never merges).
- `revoked.json` — yank list (`[{namespaced_slug,version,reason,date}]`); build-catalog excludes matches.
- `.github/CODEOWNERS` — maintainer review required on `catalog/**` + `publishers/**` (moderation chokepoint).
- `.github/PULL_REQUEST_TEMPLATE.md` — maintainer moderation checklist.
- `MODERATION.md` — the six-layer moderation policy (AI-assist + mandatory human).
- `.github/workflows/validate.yml` — runs the validator on PRs (`runs-on: ubuntu-latest` — hosted; untrusted PRs must not touch self-hosted infra).
- `.github/workflows/ai-review.yml` — AI review on `pull_request_target` (hosted; gated on `ANTHROPIC_API_KEY`; never executes PR-head code).
- `.github/workflows/publish.yml` — counter-signs + uploads `catalog.json` on push to main (`ubuntu-latest`, trusted; secret-gated).

## 3. Change-impact map ← read before editing
| If you change… | You must also… | Blast radius |
| --- | --- | --- |
| the submission shape (`catalog/**/plugin.json` fields) | keep it in lock-step with core's SDK `publish --public` and `marketplace.CatalogEntry`/`Manifest`; update `validate.mjs`, `build-catalog.mjs`, README, CONTRIBUTING | every publisher; the SDK; core's catalog sync |
| the signed release-identity bytes (`slug\0version\0artifact_url`) | match core's `SignedPayload(slug,version,source_ref)` exactly; re-sign the sample | every signature ever submitted; core install gate |
| `scripts/validate.mjs` | keep it dependency-free and runnable as `node scripts/validate.mjs`; verify against the sample (pass) and a broken copy (fail) | every PR gate |
| `scripts/build-catalog.mjs` | keep the output `{modules:[…]}` shape core's `SyncCatalog` consumes; keep `manifest.signature` = the registry counter-signature; keep `revoked.json` exclusion | every instance syncing the official catalog |
| `revoked.json` | match an existing `namespaced_slug@version`; re-run publish to drop it | the official catalog (yanks a plugin) |
| `.github/scripts/ai-review.mjs` or `ai-review.yml` | keep `pull_request_target` safety (NO PR-head checkout/exec); comment-only; gated on `ANTHROPIC_API_KEY` | privileged token safety; moderation |
| the registry key id / pinning | coordinate with core `internal/marketplace/trust.go` `RegistryPublicKeyB64` (id `7723a1e2b6ec925b`); rotating requires re-counter-signing the whole catalog | every operator's plugin trust |

## 4. Build · Test · Run
```
# validate everything:
node scripts/validate.mjs
# validate specific files:
node scripts/validate.mjs catalog/acme/hello-tool/plugin.json publishers/acme.json
# build catalog.json locally (needs the registry key):
REGISTRY_SIGNING_KEY=<base64 ed25519> node scripts/build-catalog.mjs
```
No package manager, no dependencies — pure Node ≥ 18 (`node:crypto`). CI runs on
**GitHub-hosted `ubuntu-latest`** (NOT self-hosted — this public repo accepts
untrusted PRs).

## 5. Release process
There is no tagged release. The "release" is the published `catalog.json`:
- PR → `validate.yml` (hosted) gates it; `ai-review.yml` posts an advisory verdict;
  a maintainer reviews per `CODEOWNERS` + the PR checklist and merges (mandatory
  human — see `MODERATION.md`).
- Merge to main → `publish.yml` counter-signs with `REGISTRY_SIGNING_KEY`,
  excludes `revoked.json` entries, installs `mc`, and uploads `catalog.json` to
  the CDN.
- `publish.yml` is **secret-gated**: missing secrets ⇒ prints a skip notice,
  exits 0. Required secrets: `REGISTRY_SIGNING_KEY`, `CDN_ENDPOINT`,
  `CDN_ACCESS_KEY`, `CDN_SECRET_KEY`, `CDN_BUCKET`. AI review needs
  `ANTHROPIC_API_KEY` (see README).

## 6. Gotchas / non-obvious
- **Never commit a private key.** The registry private key lives only in the
  `REGISTRY_SIGNING_KEY` secret (host copy: `deploy/registry-signing-key.SECRET`
  in core). Publisher private keys stay with their authors. The `samples/` note
  documents the throwaway demo key used for the `acme` sample.
- **No core-repo dependency.** `validate.mjs` re-implements the contract
  (release-identity signing, manifest scan) so contributors run it identically
  offline. Don't `import` from the private core repo.
- This repo is **private now, PUBLIC at launch** — keep it free of anything
  secret.
- `git add <specific files>` — never `git add .`.

## 7. Links
- Core: `AiHummer/AiHummer` (`internal/marketplace/` trust, signing, sync).
- Design: `AiHummer/docs/MARKETPLACE-PUBLISHING-DESIGN.md` (Public flow / P3).
- Contributor guide: `CONTRIBUTING.md`.

---
<!-- agents-meta -->
_Last verified against `main` @ `initial` on 2026-06-27._
