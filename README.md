# AiHummer marketplace-catalog

The **public plugin registry** for [AiHummer](https://aihummer.ru) — the
producer side of the public marketplace flow (P3 in
[`MARKETPLACE-PUBLISHING-DESIGN.md`](https://github.com/AiHummer/AiHummer/blob/main/docs/MARKETPLACE-PUBLISHING-DESIGN.md)).

A third-party plugin author registers a **publisher** identity, then opens a PR
adding their **submission**. CI validates the submission (shape, signature,
security scan). On merge, AiHummer **counter-signs** the release with the pinned
registry key and publishes the official `catalog.json` to the CDN. Every
AiHummer instance syncs that catalog and trusts entries via the pinned key — no
per-operator trust step needed.

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
.github/workflows/publish.yml            counter-signs + uploads catalog.json on merge to main
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

## Validation (what CI checks)

Run it yourself before opening a PR:
```bash
node scripts/validate.mjs                    # everything
node scripts/validate.mjs catalog/acme/hello-tool/plugin.json
```
For each changed submission the validator enforces:
- all required fields present and correctly typed; `namespaced_slug == @publisher/slug`;
  `channel ∈ {stable,beta}`; non-empty `license`.
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
| `CDN_BUCKET` | Bucket the `catalog.json` is written to. |

The publish job counter-signs each release with `REGISTRY_SIGNING_KEY`, injects
the signature as `manifest.signature`, and uploads `catalog.json` via `mc`
(MinIO client) or `aws s3`.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Agents/maintainers: read
[`AGENTS.md`](AGENTS.md) first.

## CI runner

Both workflows use `runs-on: aihummer` (the org self-hosted runner). Node is
available there; the validator has **no npm dependencies**.
