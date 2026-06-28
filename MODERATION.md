# Moderation policy — AiHummer public plugin registry

**Policy: AI-assist + MANDATORY HUMAN.** An AI reviewer posts a risk verdict on
every submission, but a **human maintainer always makes the final merge
decision.** The AI never merges; automation never merges. Nothing reaches the
official catalog without a maintainer's explicit approval.

This is the security posture for a public registry that accepts untrusted
third-party submissions. It is enforced by six layers:

## The six layers

### 1. Automated gates (`validate.yml`)
Every PR runs `scripts/validate.mjs` on a **GitHub-hosted** runner (never the
org's self-hosted infra — untrusted PR code must not touch our machines). It
enforces the submission contract and a security scan: required fields,
`namespaced_slug == @publisher/slug`, channel ∈ {stable,beta}, non-empty license,
publisher registered + key match, ed25519 signature over
`slug\0version\0artifact_url`, and a manifest scan (a 1:1 mirror of core's
hardened `ScanManifest`, so registry-accepted == instance-accepted) that
**fails** on download-then-exec installers (any downloader — `curl`/`wget`/`fetch`/
`aria2c`/`scp`/PowerShell cradles/… — piped or inline-exec'd into any shell or
interpreter, tolerant of odd whitespace like `|  sh` / `|\tsh` / `| python`),
pipe-to-shell in `exec_start` (a HARD fail, vs a plain network fetch which is a
warn), wide-open **or wildcard-prefix** egress (`*`, `*.evil`), and unflagged
secret-looking config (`token`/`secret`/`credential`/`pat`/`apikey`/… on a
whole-word boundary). A red check blocks merge.

### 2. Maintainer-merge chokepoint
External plugin authors have **no write access** to this repo, so they cannot
self-merge — regardless of any other config. Combined with branch protection on
`main` (require PR + require Code Owner review), the maintainers' exclusive merge
right is the real moderation chokepoint. **Recommended branch protection:**
require a PR, require review from Code Owners, require the `validate` check to
pass, disallow force-push to `main`.

### 3. AI-assist review (`ai-review.yml`)
On each submission PR, an AI reviewer (any OpenAI-compatible endpoint — a free
Groq key or a self-hosted AiHummer gateway / Ollama; no paid model API) assesses risk —
malware/obfuscation red flags, over-broad scope/egress, capability-vs-description
mismatch, license issues — and posts a structured verdict (VERDICT / RISK /
FINDINGS / MAINTAINER-NOTES) as a PR comment. It is **advisory only**: it
comments, never merges.

> **Security model:** the AI review runs on `pull_request_target` (so it has a
> token to comment) but **never checks out or executes PR-head code**. It reads
> the changed `plugin.json` from the API (data, not code) and inspects the
> author-hosted artifact **statically** (listing/strings) — it never
> extracts-and-runs it. This avoids the classic `pull_request_target` secret-theft
> attack. Gated on `AI_REVIEW_BASE_URL` + `AI_REVIEW_API_KEY` (any
> OpenAI-compatible endpoint — recommend a free Groq key or a self-hosted
> AiHummer gateway / Ollama; see README); absent ⇒ it skips and exits 0.

### 4. CODEOWNERS + maintainer checklist
`.github/CODEOWNERS` requires `@AiHummer/maintainers` review on `catalog/**`,
`publishers/**`, and the CI/scripts. `.github/PULL_REQUEST_TEMPLATE.md` gives the
maintainer a moderation checklist: does the plugin do what it claims; no
malware/obfuscation; scopes + egress reasonable & justified; license OK; AI verdict
read; publisher trust tier considered.

### 5. Trust tiers
- **New publisher** (first submission, or no track record): **full review** — the
  maintainer scrutinizes the artifact, scopes, and egress closely.
- **Established publisher** (history of clean, accepted submissions): **faster
  path** — the maintainer can rely more on the automated gates + AI verdict and
  focus on what changed. Still a human merge; never auto-merge.

A publisher's tier is a judgment call recorded in the PR decision notes, not an
automated flag (keep it simple in v1).

### 6. Post-publish revoke + abuse reports
A plugin that turns out to be malicious or broken **after** publishing is yanked
via `revoked.json` (an array of `{ namespaced_slug, version, reason, date }`).
`scripts/build-catalog.mjs` **excludes** any revoked `namespaced_slug@version`
when assembling `catalog.json`, and `publish.yml` reports how many were excluded.
The next publish drops it from the official catalog; instances stop seeing it on
their next sync.

**Abuse reports:** open a GitHub issue (or email the contact in the README) with
the plugin and the concern. A maintainer triages, adds it to `revoked.json` if
warranted, and re-runs publish.

## Quick reference

| Layer | Mechanism | Enforced by |
| --- | --- | --- |
| 1 Auto-gates | `validate.mjs` on hosted runner | `validate.yml` (red = block) |
| 2 Merge chokepoint | no external write access + branch protection | repo perms |
| 3 AI-assist | risk verdict comment | `ai-review.yml` (advisory) |
| 4 CODEOWNERS + checklist | required review + manual checks | `CODEOWNERS`, PR template |
| 5 Trust tiers | new = full review, established = faster | maintainer judgment |
| 6 Revoke + abuse | yank from catalog | `revoked.json` + `build-catalog.mjs` |
