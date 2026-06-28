#!/usr/bin/env node
// validate.mjs — self-contained PR validator for the AiHummer public plugin
// registry. Zero dependencies beyond the Node standard library (node:crypto).
// It MUST NOT import anything from the private core repo: the submission contract
// (release-identity signing, manifest scan) is re-implemented here so third
// parties can run it locally exactly as CI does.
//
// Usage:
//   node scripts/validate.mjs                 # validate every submission + publisher
//   node scripts/validate.mjs <file...>       # validate only the given files
//
// Exit code 0 = all clean, 1 = at least one error. Each finding is printed as a
// GitHub Actions annotation (::error file=...::message) so it surfaces inline on
// the PR, plus a human summary.

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { createPublicKey, verify as edVerify, createHash } from "node:crypto";

const ROOT = process.cwd();
const CHANNELS = new Set(["stable", "beta"]);
// Mirrors core's ValidPublisher (cmd/aihummer/plugin.go / internal/marketplace):
// the publisher namespace must match this exact pattern.
const VALID_PUBLISHER = /^[a-z0-9][a-z0-9-]{1,38}$/;
// Mirrors core's slugRE (internal/marketplace/publish.go): a slug is a single
// safe path segment. Same shape as the publisher rule but a 1-char slug is OK.
// The producer (`publish --public`) enforces this, so the registry enforces the
// identical rule to stay in lock-step (a hand-crafted PR cannot introduce a slug
// the SDK would never emit).
const VALID_SLUG = /^[a-z0-9][a-z0-9-]{0,38}$/;

let errorCount = 0;
let fileCount = 0;

// --- annotation helpers -----------------------------------------------------

function annotate(level, file, msg) {
  // GitHub Actions workflow command. `level` ∈ error|warning|notice.
  const rel = file ? relative(ROOT, file) : "";
  const loc = rel ? ` file=${rel}` : "";
  // newlines are not allowed in a single annotation
  const flat = String(msg).replace(/\r?\n/g, " ");
  console.log(`::${level}${loc}::${flat}`);
}
function err(file, msg) {
  errorCount++;
  annotate("error", file, msg);
}
function ok(file, msg) {
  console.log(`  ok: ${relative(ROOT, file)} — ${msg}`);
}

// --- crypto: ed25519 over the release identity ------------------------------

// KeyID mirrors core's marketplace.KeyID: first 16 hex chars of sha256(raw pubkey).
function keyID(publicKeyB64) {
  let raw;
  try {
    raw = Buffer.from(publicKeyB64.trim(), "base64");
  } catch {
    return "";
  }
  if (raw.length !== 32) return "";
  return createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

// SignedPayload mirrors core's marketplace.SignedPayload: slug\0version\0source_ref.
function signedPayload(slug, version, sourceRef) {
  return Buffer.from(`${slug}\x00${version}\x00${sourceRef}`, "utf8");
}

// Wrap a 32-byte raw ed25519 public key in a SPKI DER so node:crypto can load it.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function publicKeyFromRaw(publicKeyB64) {
  const raw = Buffer.from(publicKeyB64.trim(), "base64");
  if (raw.length !== 32) throw new Error("public key is not 32 raw bytes");
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

function verifySignature(payload, signatureB64, publicKeyB64) {
  let sig;
  try {
    sig = Buffer.from(signatureB64.trim(), "base64");
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  let pub;
  try {
    pub = publicKeyFromRaw(publicKeyB64);
  } catch {
    return false;
  }
  try {
    return edVerify(null, payload, pub, sig);
  } catch {
    return false;
  }
}

// --- manifest security scan (standalone mirror of core ScanManifest) --------
// Returns an array of { severity, field, message }. High findings fail the gate.
//
// This is a 1:1 port of `internal/marketplace/scan.go` (core's hardened
// ScanManifest, PR #28). The rule set is COORDINATED with core so that
// registry-accepted == instance-accepted: a submission that passes this gate
// passes core's in-process scan, and vice-versa. When core's scan.go changes,
// change this block to match (and the self-tests in validate.test.mjs).

// pipeShellRe matches a pipe into a shell/interpreter, tolerant of odd spacing
// (`|sh`, `|  sh`, `|\tsh`, `| sudo bash`, `| /bin/sh`) and many interpreters
// (sh/bash/zsh/dash/ksh/ash/fish, python[23], perl, ruby, node, php, pwsh,
// powershell, iex). Closes the `|  sh` / `| python` bypasses of the old
// `includes("| sh")` check.
//
// It also tolerates an `env` launcher in front of the interpreter
// (`| env sh`, `| /usr/bin/env bash`, `| env -S python3`, `| env VAR=v sh`):
// `env <shell>` (optionally path-prefixed, with flag/assignment args) is just
// pipe-to-shell with a space before the interpreter, which the old regex missed.
const pipeShellRe = /\|\s*(?:sudo\s+)?(?:(?:[\w./-]*\/)?env\s+(?:(?:-\S+|[\w.]+=\S+)\s+)*)?(?:[\w./-]*\/)?(sh|bash|zsh|dash|ksh|ash|fish|python[23]?|perl|ruby|node|php|pwsh|powershell|iex|invoke-expression)\b/;

// inlineExecRe matches an interpreter invoked with an inline-code flag
// (`python -c`, `bash -c`, `node -e`, `powershell -Command`) — the
// "download then exec inline" form that doesn't use a literal pipe.
const inlineExecRe = /\b(sh|bash|zsh|dash|ksh|python[23]?|perl|ruby|node|php|pwsh|powershell)\b\s+-(c|e|command|enc|encodedcommand)\b/;

// downloaders are network fetch commands. A pipe-to-shell (or inline-exec) from
// ANY of these is the supply-chain footgun — not just curl/wget. Matched as
// lowercased substrings; a few carry a trailing space to avoid false hits.
const DOWNLOADERS = [
  "curl", "wget", "fetch ", "aria2c", "lwp-download", "lwp-request",
  "nc ", "ncat", "socat", "scp ", "sftp ", "ftp ", "tftp",
  "invoke-webrequest", "invoke-restmethod", "iwr ", "irm ",
  "downloadstring", "downloadfile", "start-bitstransfer",
  "urllib", "requests.get", "requests.post", "http.client", "httpie", "wsgiref",
];

const containsAny = (s, subs) => subs.some((sub) => s.includes(sub));

// riskyShellExec reports whether a command line downloads code and runs it via a
// shell/interpreter — either piped (`fetch URL | python`) or inline
// (`python -c "import urllib...; exec(...)"`).
function riskyShellExec(l) {
  if (pipeShellRe.test(l)) return true;
  return containsAny(l, DOWNLOADERS) && inlineExecRe.test(l);
}

// credExactHints are short/ambiguous credential tokens matched on a whole-word
// boundary (so "pat" flags a `pat` field but not `path`/`pattern`/`compatible`,
// and "passwd"/"passphrase" flag `db_passwd`/`vault_passphrase` but never
// `path`/`pattern`).
const CRED_EXACT_HINTS = ["pat", "key", "token", "secret", "cred", "auth", "passwd", "passphrase"];

// credSubHints are unambiguous credential markers matched anywhere in the key.
const CRED_SUB_HINTS = [
  "token", "secret", "password", "passwd", "passphrase", "api_key", "apikey",
  "private_key", "privatekey", "credential", "client_secret", "access_key",
  "secret_key", "bearer", "auth_token", "refresh_token", "session_key",
  "signing_key",
];

// looksLikeCredential reports whether a config key name suggests it holds a
// secret. Long markers match as substrings; short ambiguous ones (pat/key/auth)
// only match as a standalone token to avoid false positives like "path".
function looksLikeCredential(key) {
  const k = String(key || "").toLowerCase();
  if (containsAny(k, CRED_SUB_HINTS)) return true;
  for (const tok of k.split(/[^a-z0-9]+/)) {
    if (CRED_EXACT_HINTS.includes(tok)) return true;
  }
  return false;
}

function scanManifest(m) {
  const out = [];
  const add = (severity, field, message) => out.push({ severity, field, message });
  m = m || {};
  const hostNative = m.host_native || {};

  // 1. install steps that download code and run it through a shell/interpreter —
  //    matched across downloaders + interpreters + odd whitespace + inline-exec.
  const install = Array.isArray(hostNative.install) ? hostNative.install : [];
  install.forEach((step, i) => {
    if (riskyShellExec(String(step).toLowerCase())) {
      add("high", `host_native.install[${i}]`, "downloads code and pipes/execs it through a shell (review the source)");
    }
  });

  // 1b. exec_start that pipes a download into a shell is a HARD finding (high):
  //     a process that fetches+runs code at every start defeats the
  //     signed-artifact model. A plain network fetch (no shell) stays a warn.
  const execStart = String(hostNative.exec_start || "").toLowerCase();
  if (riskyShellExec(execStart)) {
    add("high", "host_native.exec_start", "pipes/execs a network download through a shell at start (use a vendored, signed binary)");
  } else if (execStart.includes("curl ") || execStart.includes("wget ") || containsAny(execStart, DOWNLOADERS)) {
    add("warn", "host_native.exec_start", "fetches from the network at start — prefer a vendored binary");
  }

  // 2. egress allow-lists: "*" lets the agent reach any host; ANY wildcard inside
  //    an entry — prefix (`*.evil`, `*foo`), suffix (`evil*`), or embedded
  //    (`e*il.com`) — is broad/forgeable (`evil*` matches `evil-exfil.com`) and
  //    must be flagged too.
  const openapi = m.openapi || {};
  const allowed = Array.isArray(openapi.allowed_hosts) ? openapi.allowed_hosts : [];
  for (const h of allowed) {
    const t = String(h).trim();
    if (t === "*") {
      add("high", "openapi.allowed_hosts", "allows egress to ANY host (*) — scope to specific hosts");
    } else if (t.includes("*")) {
      add("high", "openapi.allowed_hosts", `wildcard host "${t}" allows a broad/ambiguous host set — pin exact hosts`);
    }
  }

  // 3. secret-looking config fields not marked secret:true.
  const config = Array.isArray(m.config) ? m.config : [];
  config.forEach((c, i) => {
    if (c && c.secret) return;
    const key = (c && c.key) || "";
    if (looksLikeCredential(key)) {
      add("high", `config[${i}].key=${key}`, "looks like a credential but is not marked secret:true");
    }
  });

  return out;
}

// --- publishers -------------------------------------------------------------

function readJSON(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

// Load and validate a publisher registration. Returns the parsed object or null
// (and records an error) on failure.
function loadPublisher(name) {
  const file = join(ROOT, "publishers", `${name}.json`);
  if (!existsSync(file)) {
    return { file, missing: true };
  }
  let p;
  try {
    p = readJSON(file);
  } catch (e) {
    err(file, `invalid JSON: ${e.message}`);
    return { file, error: true };
  }
  return { file, data: p };
}

function validatePublisherFile(file) {
  fileCount++;
  let p;
  try {
    p = readJSON(file);
  } catch (e) {
    err(file, `invalid JSON: ${e.message}`);
    return;
  }
  const required = ["publisher", "public_key", "key_id", "contact"];
  let bad = false;
  for (const f of required) {
    if (typeof p[f] !== "string" || p[f].trim() === "") {
      err(file, `missing or non-string required field "${f}"`);
      bad = true;
    }
  }
  if (bad) return;

  // file name must match the publisher field
  const base = file.split(sep).pop().replace(/\.json$/, "");
  if (base !== p.publisher) {
    err(file, `file name "${base}.json" must match publisher "${p.publisher}"`);
  }
  if (!VALID_PUBLISHER.test(p.publisher)) {
    err(file, `publisher "${p.publisher}" invalid (must match ^[a-z0-9][a-z0-9-]{1,38}$)`);
  }
  // public_key must be a valid 32-byte ed25519 key and key_id must match.
  const derivedId = keyID(p.public_key);
  if (!derivedId) {
    err(file, `public_key is not a valid base64 ed25519 public key (need 32 raw bytes)`);
    return;
  }
  if (derivedId !== p.key_id) {
    err(file, `key_id "${p.key_id}" does not match sha256(public_key)[:16] = "${derivedId}"`);
    return;
  }
  ok(file, `publisher "${p.publisher}" key_id ${p.key_id}`);
}

// --- submissions ------------------------------------------------------------

function validateSubmissionFile(file) {
  fileCount++;
  let s;
  try {
    s = readJSON(file);
  } catch (e) {
    err(file, `invalid JSON: ${e.message}`);
    return;
  }

  const stringFields = ["publisher", "slug", "namespaced_slug", "version", "channel", "artifact_url", "license", "signature", "publisher_key_id"];
  let bad = false;
  for (const f of stringFields) {
    if (typeof s[f] !== "string" || s[f].trim() === "") {
      err(file, `missing or non-string required field "${f}"`);
      bad = true;
    }
  }
  if (s.manifest == null || typeof s.manifest !== "object" || Array.isArray(s.manifest)) {
    err(file, `"manifest" must be a JSON object (the full marketplace Manifest)`);
    bad = true;
  }
  if (bad) return;

  // publisher namespace must match core's ValidPublisher.
  if (!VALID_PUBLISHER.test(s.publisher)) {
    err(file, `publisher "${s.publisher}" invalid (must match ^[a-z0-9][a-z0-9-]{1,38}$)`);
  }

  // slug must match core's slugRE (lock-step with the SDK producer).
  if (!VALID_SLUG.test(s.slug)) {
    err(file, `slug "${s.slug}" invalid (must match ^[a-z0-9][a-z0-9-]{0,38}$)`);
  }

  // namespaced_slug == @publisher/slug
  const expectedNs = `@${s.publisher}/${s.slug}`;
  if (s.namespaced_slug !== expectedNs) {
    err(file, `namespaced_slug "${s.namespaced_slug}" must equal "${expectedNs}"`);
  }

  // path must be catalog/<publisher>/<slug>/plugin.json
  const rel = relative(ROOT, file);
  const expectedPath = join("catalog", s.publisher, s.slug, "plugin.json");
  if (rel !== expectedPath) {
    err(file, `submission must live at "${expectedPath}" (found "${rel}")`);
  }

  // channel ∈ {stable,beta}
  if (!CHANNELS.has(s.channel)) {
    err(file, `channel "${s.channel}" invalid (want stable|beta)`);
  }

  // publisher must be registered, and publisher_key_id must match it.
  const pub = loadPublisher(s.publisher);
  if (pub.missing) {
    err(file, `publisher "${s.publisher}" is not registered — add publishers/${s.publisher}.json first`);
    return;
  }
  if (pub.error || !pub.data) return;
  const reg = pub.data;
  if (typeof reg.public_key !== "string" || typeof reg.key_id !== "string") {
    err(file, `publisher registration publishers/${s.publisher}.json is malformed`);
    return;
  }
  if (s.publisher_key_id !== reg.key_id) {
    err(file, `publisher_key_id "${s.publisher_key_id}" does not match registered key_id "${reg.key_id}" for "${s.publisher}"`);
    return;
  }

  // signature must verify over slug\0version\0artifact_url against the registered key.
  const payload = signedPayload(s.slug, s.version, s.artifact_url);
  if (!verifySignature(payload, s.signature, reg.public_key)) {
    err(file, `signature does not verify (ed25519 over slug\\0version\\0artifact_url) against ${s.publisher}'s registered public key`);
    return;
  }

  // store-page fields on the manifest (mirror core's public-submission contract):
  // description + icon are REQUIRED for a public submission; screenshots optional.
  const m = s.manifest;
  if (typeof m.description !== "string" || m.description.trim() === "") {
    err(file, `manifest.description is required for a public submission (non-empty string)`);
    return;
  }
  if (typeof m.icon !== "string" || m.icon.trim() === "") {
    err(file, `manifest.icon is required for a public submission (non-empty https URL or data URI string)`);
    return;
  }
  if (m.screenshots !== undefined) {
    if (
      !Array.isArray(m.screenshots) ||
      m.screenshots.some((x) => typeof x !== "string" || x.trim() === "")
    ) {
      err(file, `manifest.screenshots, when present, must be an array of non-empty strings`);
      return;
    }
  }

  // basic security scan of the embedded manifest — high findings fail.
  const findings = scanManifest(s.manifest);
  let scanFailed = false;
  for (const f of findings) {
    if (f.severity === "high") {
      err(file, `manifest scan [HIGH] ${f.field}: ${f.message}`);
      scanFailed = true;
    } else {
      annotate("warning", file, `manifest scan [${f.severity}] ${f.field}: ${f.message}`);
    }
  }
  if (scanFailed) return;

  ok(file, `${s.namespaced_slug}@${s.version} (${s.channel}) — signature + scan ok`);
}

// --- file discovery ---------------------------------------------------------

function walk(dir, match, acc) {
  if (!existsSync(dir)) return acc;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, match, acc);
    else if (match(p)) acc.push(p);
  }
  return acc;
}

function main() {
  const argv = process.argv.slice(2);
  let submissions = [];
  let publishers = [];

  if (argv.length > 0) {
    for (const a of argv) {
      const abs = join(ROOT, a);
      if (!existsSync(abs)) {
        err(abs, "file does not exist");
        continue;
      }
      const rel = relative(ROOT, abs).split(sep).join("/");
      if (/^catalog\/[^/]+\/[^/]+\/plugin\.json$/.test(rel)) {
        submissions.push(abs);
      } else if (/^publishers\/[^/]+\.json$/.test(rel)) {
        publishers.push(abs);
      } else {
        console.log(`  skip (not a catalog/publisher file): ${rel}`);
      }
    }
  } else {
    submissions = walk(join(ROOT, "catalog"), (p) => p.endsWith(`${sep}plugin.json`), []);
    publishers = walk(join(ROOT, "publishers"), (p) => p.endsWith(".json"), []);
  }

  for (const f of publishers) validatePublisherFile(f);
  for (const f of submissions) validateSubmissionFile(f);

  console.log("");
  console.log(`validated ${fileCount} file(s): ${errorCount === 0 ? "all clean" : errorCount + " error(s)"}`);
  if (errorCount > 0) process.exit(1);
}

// Pure, side-effect-free helpers are exported for the self-tests
// (scripts/validate.test.mjs). Importing this module does NOT run the CLI.
export { keyID, signedPayload, verifySignature, scanManifest, VALID_PUBLISHER, VALID_SLUG, CHANNELS };

// Run the CLI only when executed directly (`node scripts/validate.mjs`), not when
// imported by the test harness.
const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) main();
