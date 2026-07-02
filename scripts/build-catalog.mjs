#!/usr/bin/env node
// build-catalog.mjs — assemble the official catalog.json from every accepted
// submission, COUNTER-SIGNING each release identity with the AiHummer registry
// private key. Runs on merge to main (publish.yml). Zero external deps.
//
// Env:
//   REGISTRY_SIGNING_KEY  base64 ed25519 key — either a 32-byte seed or a
//                         64-byte seed||pub (the format of
//                         deploy/registry-signing-key.SECRET). REQUIRED.
//   OUT                   output path (default ./catalog.json)
//
// Output shape is exactly what core's SyncCatalog expects: {"modules":[...]},
// each module a marketplace.CatalogEntry. The registry counter-signature is
// injected as manifest.signature so every instance verifies it against the
// pinned RegistryPublicKeyB64 (key id 7723a1e2b6ec925b).

import { readFileSync, readdirSync, statSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createPrivateKey, sign as edSign, verify as edVerify, createHash, createPublicKey } from "node:crypto";

const ROOT = process.cwd();
const OUT = process.env.OUT || join(ROOT, "catalog.json");

const keyB64 = (process.env.REGISTRY_SIGNING_KEY || "").trim();
if (!keyB64) {
  console.error("REGISTRY_SIGNING_KEY is empty");
  process.exit(2);
}

// Load the registry private key. Accept a 32-byte seed or 64-byte seed||pub.
function loadPrivateKey(b64) {
  const buf = Buffer.from(b64, "base64");
  let seed;
  if (buf.length === 64) seed = buf.subarray(0, 32);
  else if (buf.length === 32) seed = buf;
  else throw new Error(`registry key must decode to 32 or 64 bytes, got ${buf.length}`);
  // PKCS8 DER for an ed25519 private key from a raw seed.
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function keyIDOfPublic(pubRaw) {
  return createHash("sha256").update(pubRaw).digest("hex").slice(0, 16);
}

const priv = loadPrivateKey(keyB64);
const pubRaw = Buffer.from(createPublicKey(priv).export({ format: "jwk" }).x, "base64url");
const registryKeyId = keyIDOfPublic(pubRaw);
console.log(`registry counter-sign key id: ${registryKeyId}`);
if (registryKeyId !== "7723a1e2b6ec925b" && process.env.ALLOW_UNPINNED_REGISTRY_KEY !== "1") {
  console.error(`FATAL: registry key id ${registryKeyId} != pinned 7723a1e2b6ec925b — every instance would REJECT this catalog. Set ALLOW_UNPINNED_REGISTRY_KEY=1 only for a coordinated key rotation.`);
  process.exit(2);
}

// signedPayload mirrors core's marketplace.SignedPayloadWithDigest: when a hex
// artifact_sha256 is present it binds it into the signed bytes so the registry
// counter-signature matches exactly what the gateway Install gate verifies
// (otherwise a community plugin declaring artifact_sha256 would fail to install).
// An empty digest reproduces the plain URL release-identity the publisher signs.
function signedPayload(slug, version, sourceRef, sha256Hex) {
  const d = (sha256Hex || "").trim().toLowerCase();
  const base = `${slug}\x00${version}\x00${sourceRef}`;
  return Buffer.from(d ? `${base}\x00sha256:${d}` : base, "utf8");
}

// loadPublicKeyRaw wraps a raw 32-byte ed25519 public key (base64) in SPKI DER.
function loadPublicKeyRaw(pubB64) {
  const raw = Buffer.from(pubB64, "base64");
  if (raw.length !== 32) throw new Error(`publisher public_key must decode to 32 bytes, got ${raw.length}`);
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

// verifyPublisher re-checks the publisher registration + release-identity
// signature BEFORE the registry counter-signs. build-catalog is the last gate
// before the pinned registry key blesses an entry, so it must not rely solely on
// validate.yml running under (recommended-not-enforced) branch protection: a
// merge that skips validate must still not produce a first-party-trusted entry.
function verifyPublisher(sub) {
  const pf = join(ROOT, "publishers", `${sub.publisher}.json`);
  if (!existsSync(pf)) throw new Error(`no registered publisher record publishers/${sub.publisher}.json`);
  const pub = JSON.parse(readFileSync(pf, "utf8"));
  if (sub.publisher_key_id && pub.key_id && sub.publisher_key_id !== pub.key_id) {
    throw new Error(`publisher_key_id ${sub.publisher_key_id} != registered ${pub.key_id}`);
  }
  const key = loadPublicKeyRaw(pub.public_key);
  // The publisher signs the URL-only release identity (public submission contract).
  const payload = signedPayload(sub.slug, sub.version, sub.artifact_url);
  const sig = Buffer.from(sub.signature || "", "base64");
  if (sig.length !== 64 || !edVerify(null, payload, key, sig)) {
    throw new Error("publisher signature does not verify against the registered key");
  }
}

// Load the revoke/yank list: revoked.json is an array of
// { namespaced_slug, version, reason, date }. Any submission whose
// namespaced_slug + version matches a revoked entry is EXCLUDED from catalog.json
// (post-publish takedown — see MODERATION.md, layer 6). Returns a Set of
// "namespaced_slug@version" keys.
function loadRevoked() {
  const file = join(ROOT, "revoked.json");
  if (!existsSync(file)) return new Set();
  let arr;
  try {
    arr = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    console.error(`revoked.json is invalid JSON: ${e.message}`);
    process.exit(2);
  }
  if (!Array.isArray(arr)) {
    console.error("revoked.json must be a JSON array");
    process.exit(2);
  }
  const set = new Set();
  for (const r of arr) {
    if (r && r.namespaced_slug && r.version) {
      set.add(`${r.namespaced_slug}@${r.version}`);
    }
  }
  return set;
}

function walk(dir, match, acc) {
  if (!existsSync(dir)) return acc;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, match, acc);
    else if (match(p)) acc.push(p);
  }
  return acc;
}

const submissions = walk(join(ROOT, "catalog"), (p) => p.endsWith("/plugin.json") || p.endsWith("\\plugin.json"), []);
const revoked = loadRevoked();
const modules = [];
let excluded = 0;

for (const file of submissions) {
  const s = JSON.parse(readFileSync(file, "utf8"));

  // skip any submission on the revoke/yank list (matched by namespaced_slug@version).
  const revokeKey = `${s.namespaced_slug || `@${s.publisher}/${s.slug}`}@${s.version}`;
  if (revoked.has(revokeKey)) {
    console.log(`excluded (revoked): ${revokeKey}`);
    excluded++;
    continue;
  }

  // Re-verify the publisher registration + signature before counter-signing with
  // the pinned registry key (do not trust that validate.yml gated this merge).
  try {
    verifyPublisher(s);
  } catch (e) {
    console.error(`REJECTED ${s.namespaced_slug || s.slug}@${s.version}: ${e.message}`);
    process.exit(2);
  }

  const manifest = { ...(s.manifest || {}) };

  // counter-sign the release identity with the registry key, mirroring core's
  // SignedPayloadWithDigest (sha-bound when the manifest carries artifact_sha256).
  const payload = signedPayload(s.slug, s.version, s.artifact_url, manifest.artifact_sha256);
  const registrySignature = edSign(null, payload, priv).toString("base64");

  // inject the registry signature as manifest.signature so instances verify it
  // against the pinned registry key.
  manifest.signature = registrySignature;
  manifest.publisher = manifest.publisher || s.publisher;
  manifest.visibility = "public";

  modules.push({
    slug: s.slug,
    name: manifest.name || s.namespaced_slug || s.slug,
    kind: manifest.kind || "openapi",
    description: manifest.description || "",
    source_type: "host",          // author-hosted .tar.gz over HTTP(S)
    source_ref: s.artifact_url,
    latest_version: s.version,
    channel: s.channel,
    manifest,
    origin: "official",
    visibility: "public",
  });

  console.log(`counter-signed ${s.namespaced_slug || s.slug}@${s.version} (${s.channel})`);
}

modules.sort((a, b) => a.slug.localeCompare(b.slug));
writeFileSync(OUT, JSON.stringify({ modules }, null, 2) + "\n");
console.log(`wrote ${modules.length} module(s) to ${OUT} (excluded ${excluded} revoked)`);
