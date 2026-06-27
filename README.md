# AiHummer marketplace-catalog

The **public plugin registry** for [AiHummer](https://aihummer.ru) — the
producer side of the public marketplace flow (P3 in
[`MARKETPLACE-PUBLISHING-DESIGN.md`](https://github.com/AiHummer/AiHummer/blob/main/docs/MARKETPLACE-PUBLISHING-DESIGN.md)).

A third-party plugin author registers a **publisher** identity, then opens a PR
adding their **submission**. CI validates the submission (shape, signature,
security scan). On merge, AiHummer **counter-signs** the release with the pinned
registry key and publishes a **`community-catalog.json`** to the CDN — the
community catalog, kept separate from the curated first-party `catalog.json`. An
AiHummer instance opts in by adding this catalog as an extra source (Plugins →
Sources); entries are trusted via the pinned registry key — no per-operator trust
step needed.

> **This repo will be PUBLIC at launch.** It is private for now while the flow is
> being wired. Nothing here is a secret: there are no private keys in the repo
> (the registry private key lives only in the `REGISTRY_SIGNING_KEY` repo secret;
> publisher private keys stay with their authors). Flip the repo to public when
> the public marketplace launches.

## Repository layout

```
publishers/<publisher>.json              one-time publisher registration
catalog/<publisher>/<slug>/plugin.json   a plugin submission (one per version line)
scripts/validate.mjs                     self-contained PR validator (node:crypto, no deps)
scripts/build-catalog.mjs                counter-signs + assembles catalog.json on merge
.github/workflows/validate.yml           runs validate.mjs on every PR
.github/workflows/publish.yml            counter-signs + uploads community-catalog.json on merge to main
```

## The submission contract

This shape is **stable** — the core SDK's `aihummer plugin publish --public`
opens PRs in exactly this form.

### `publishers/<publisher>.json` — one-time registration
```json
{
  "publisher": "acme",
  "public_key": "<base64 std ed25519 public key>",
  "key_id": "<sha256(public_key)[:16] hex>",
  "contact": "<email or URL>"
}
```
The file name must equal the `publisher` field. `key_id` must equal the first 16
hex chars of `sha256(raw public key)`.

### `catalog/<publisher>/<slug>/plugin.json` — a submission
```json
{
  "publisher": "acme",
  "slug": "hello-tool",
  "namespaced_slug": "@acme/hello-tool",
  "version": "1.0.0",
  "channel": "stable",
  "artifact_url": "https://acme.example.com/plugins/hello-tool-1.0.0.tar.gz",
  "license": "MIT",
  "publisher_key_id": "bd68f2deedad25b1",
  "signature": "<base64 ed25519 over the release identity>",
  "manifest": { "...the full marketplace Manifest object..." }
}
```
- `namespaced_slug` must equal `@<publisher>/<slug>`.
- `channel` ∈ `stable | beta`.
- `artifact_url` is the **author-hosted** `.tar.gz`.
- `publisher_key_id` must match the registered publisher's `key_id`.
- **Release identity signed** = the bytes `slug \x00 version \x00 artifact_url`
  (matches core's `SignedPayload(slug, version, source_ref)`).

#### Store-page manifest fields

For a **public** submission the embedded `manifest` must also carry store-page
metadata:
- `manifest.description` — **required**, a non-empty string describing the plugin.
- `manifest.icon` — **required**, a non-empty string: an `https://` URL or a
  `data:` URI for the plugin icon.
- `manifest.screenshots` — **optional**, an array of non-empty `https://` URL
  strings.

## Validation (what CI checks)

Run it yourself before opening a PR:
```bash
node scripts/validate.mjs                    # everything
node scripts/validate.mjs catalog/acme/hello-tool/plugin.json
```
For each changed submission the validator enforces:
- all required fields present and correctly typed; `namespaced_slug == @publisher/slug`;
  `channel ∈ {stable,beta}`; non-empty `license`.
- store-page fields on `manifest`: non-empty `description` (**required**),
  non-empty `icon` (**required**, https URL or data URI), and — if present —
  `screenshots` must be an array of non-empty strings.
- the publisher is registered (`publishers/<publisher>.json`) and
  `publisher_key_id` matches it.
- the `signature` verifies (ed25519) against the registered public key over
  `slug\0version\0artifact_url`.
- a security scan of `manifest` **fails** on: install steps that pipe-to-shell
  (`curl … | sh`), wildcard egress (`allowed_hosts` contains `*`), or
  secret-looking config fields not marked `secret:true`.

## Publishing secrets (operator must set these)

`publish.yml` is **gated**: if any secret is missing it prints a `publish
skipped` notice and exits 0 (so the repo works before secrets are wired). To
enable publishing, set these **repository secrets**:

| Secret | What it is |
| --- | --- |
| `REGISTRY_SIGNING_KEY` | The AiHummer **registry private key**, base64 ed25519 (32-byte seed or 64-byte seed‖pub). Lives on the build host at `deploy/registry-signing-key.SECRET`; its public half is pinned in core (`internal/marketplace/trust.go`, key id `7723a1e2b6ec925b`). **Never commit it.** |
| `CDN_ENDPOINT` | S3/MinIO endpoint URL of the catalog CDN. |
| `CDN_ACCESS_KEY` | CDN access key. |
| `CDN_SECRET_KEY` | CDN secret key. |
| `CDN_BUCKET` | Bucket the `community-catalog.json` is written to. |

The publish job counter-signs each release with `REGISTRY_SIGNING_KEY`, injects
the signature as `manifest.signature`, and uploads `community-catalog.json` via `mc`
(MinIO client) or `aws s3`.

## AI review configuration (free / local — no paid model API)

The advisory AI review (`ai-review.yml`) calls a generic **OpenAI-compatible**
`POST {BASE_URL}/chat/completions` endpoint, so you can wire it to any
**free or self-hosted** provider — aligning with AiHummer's "free/local models,
no paid model APIs" principle. Configure:

| Name | Kind | What it is |
| --- | --- | --- |
| `AI_REVIEW_BASE_URL` | repo **variable** (secret override allowed) | OpenAI-compatible base URL, e.g. `https://api.groq.com/openai/v1`. |
| `AI_REVIEW_MODEL` | repo **variable** | model id, e.g. `llama-3.3-70b-versatile`. |
| `AI_REVIEW_API_KEY` | repo **secret** | the endpoint's API key. |

If `AI_REVIEW_BASE_URL` **or** `AI_REVIEW_API_KEY` is empty, the review **skips
and exits 0** (advisory-only, never blocks).

Recommended free options:
- **Groq free API** — `https://api.groq.com/openai/v1`, a free API key with **no
  card required**; e.g. model `llama-3.3-70b-versatile`.
- **Self-hosted AiHummer gateway / Ollama** — `http://<host>/v1`, fully
  local/free; pick any served model id.

## Moderation

This is a public registry that accepts untrusted submissions. The policy is
**AI-assist + mandatory human**: an AI reviewer posts a risk verdict, but a human
maintainer always makes the final merge decision. See
[`MODERATION.md`](MODERATION.md) for the full six-layer policy (auto-gates →
maintainer-merge chokepoint → AI-assist review → CODEOWNERS + checklist → trust
tiers → post-publish revoke + abuse reports).

The AI review (`ai-review.yml`) is gated on **`AI_REVIEW_BASE_URL`** +
**`AI_REVIEW_API_KEY`** (any OpenAI-compatible endpoint — recommend a free Groq
key or a self-hosted AiHummer gateway / Ollama; see *AI review configuration*
above); absent ⇒ it skips and exits 0.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Agents/maintainers: read
[`AGENTS.md`](AGENTS.md) first.

## CI runner

PR CI (`validate.yml`) and `ai-review.yml` run on **GitHub-hosted**
`ubuntu-latest` — deliberately NOT the org self-hosted runner, since this repo is
public and accepts untrusted PRs (untrusted code must never run on our infra;
public repos get unlimited hosted minutes). `publish.yml` also runs on
`ubuntu-latest` (it is trusted — push to `main` only — and installs `mc` in a
step). The validator has **no npm dependencies**.
