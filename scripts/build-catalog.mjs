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
import { createPrivateKey, sign as edSign, createHash, createPublicKey } from "node:crypto";

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
if (registryKeyId !== "7723a1e2b6ec925b") {
  console.error(`WARNING: registry key id ${registryKeyId} != pinned 7723a1e2b6ec925b — instances will reject this catalog`);
}

function signedPayload(slug, version, sourceRef) {
  return Buffer.from(`${slug}\x00${version}\x00${sourceRef}`, "utf8");
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
const modules = [];

for (const file of submissions) {
  const s = JSON.parse(readFileSync(file, "utf8"));
  const manifest = { ...(s.manifest || {}) };

  // counter-sign slug\0version\0artifact_url with the registry key.
  const payload = signedPayload(s.slug, s.version, s.artifact_url);
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
console.log(`wrote ${modules.length} module(s) to ${OUT}`);
