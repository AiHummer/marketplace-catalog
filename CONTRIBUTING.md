# Contributing a plugin to the AiHummer marketplace

This repo is the **public** AiHummer plugin registry. Submitting is a two-step
process: register once as a publisher, then open a PR per plugin (and per new
version line).

## 1. Register as a publisher (one time)

Generate an author keypair with the SDK:
```bash
aihummer plugin keygen          # prints your public key (base64) and key_id
```
Add `publishers/<you>.json` (the file name must equal your publisher name):
```json
{
  "publisher": "yourname",
  "public_key": "<base64 std ed25519 public key from keygen>",
  "key_id": "<key_id from keygen>",
  "contact": "you@example.com"
}
```
`key_id` is `sha256(raw public key)[:16]` in hex — `keygen` prints it for you.
This reserves the `@yourname` namespace. **Keep your private key safe and out of
this repo** — you sign every submission with it.

## 2. Submit a plugin

1. Host your built, packaged artifact yourself (`aihummer plugin package`
   produces `<slug>-<version>.tar.gz`). Put it at a stable HTTPS URL.
2. Sign the release identity:
   ```bash
   aihummer plugin sign --key author.key   # signs slug\0version\0artifact_url
   ```
3. Add `catalog/<you>/<slug>/plugin.json`:
   ```json
   {
     "publisher": "yourname",
     "slug": "my-tool",
     "namespaced_slug": "@yourname/my-tool",
     "version": "1.0.0",
     "channel": "stable",
     "artifact_url": "https://you.example.com/my-tool-1.0.0.tar.gz",
     "license": "MIT",
     "publisher_key_id": "<your key_id>",
     "signature": "<base64 signature from `aihummer plugin sign`>",
     "manifest": { "...full marketplace Manifest..." }
   }
   ```
4. Validate locally (same check CI runs):
   ```bash
   node scripts/validate.mjs catalog/yourname/my-tool/plugin.json
   ```
5. Open a PR. `validate.yml` runs automatically. Fix any annotations until green.

## Rules the validator enforces

- `namespaced_slug` must equal `@<publisher>/<slug>`.
- `channel` must be `stable` or `beta`.
- `license` must be non-empty.
- Your publisher must be registered and `publisher_key_id` must match it.
- The signature must verify against your registered public key over
  `slug\0version\0artifact_url`.
- The manifest must pass the security scan — **no** `curl … | sh` install steps,
  **no** wildcard (`*`) `allowed_hosts`, and any credential-looking config field
  must be `secret:true`.

## After merge

A maintainer (human/AI) reviews and merges. On merge, the publish job
**counter-signs** your release with the AiHummer registry key and uploads the
official `catalog.json` to the CDN. Every AiHummer instance then sees your plugin
and trusts it via the pinned registry key.

## Updating a plugin

Open a new PR that bumps `version` and `artifact_url`, re-sign, and re-validate.
Use `channel: beta` for pre-release lines.
