#!/usr/bin/env node
// ai-review.mjs — ADVISORY AI risk review of plugin submissions. Runs from
// ai-review.yml (pull_request_target). It COMMENTS a verdict; it NEVER merges.
//
// SECURITY: invoked from a privileged pull_request_target context. It reads the
// changed catalog/**/plugin.json files from the GitHub API (data, not code) and
// optionally downloads the author-hosted artifact for STATIC inspection only
// (listing + string scan). It never checks out, extracts-and-runs, or executes
// any PR-controlled code. The only secret it uses (ANTHROPIC_API_KEY) is sent to
// Anthropic; it is never handed to attacker-controlled code.
//
// Env: GH_TOKEN, ANTHROPIC_API_KEY, PR_NUMBER, REPO (owner/name).
// Zero npm deps — uses fetch + child_process(gh) only.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const MODEL = "claude-opus-4-8";
const ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION = "2023-06-01";

const { GH_TOKEN, ANTHROPIC_API_KEY, PR_NUMBER, REPO } = process.env;
if (!ANTHROPIC_API_KEY) {
  console.log("AI review skipped: set ANTHROPIC_API_KEY to enable.");
  process.exit(0);
}
if (!GH_TOKEN || !PR_NUMBER || !REPO) {
  console.error("missing GH_TOKEN / PR_NUMBER / REPO");
  process.exit(1);
}

function gh(args) {
  return execFileSync("gh", args, { encoding: "utf8", env: { ...process.env, GH_TOKEN } });
}

// List the files changed by this PR via the API (data only — no checkout).
function changedCatalogFiles() {
  const raw = gh([
    "api",
    "--paginate",
    `repos/${REPO}/pulls/${PR_NUMBER}/files`,
    "--jq",
    '.[] | select(.status != "removed") | {filename, raw_url, contents_url, sha}',
  ]);
  const out = [];
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    const f = JSON.parse(t);
    if (/^catalog\/[^/]+\/[^/]+\/plugin\.json$/.test(f.filename)) out.push(f);
  }
  return out;
}

// Fetch a changed file's content from the PR HEAD via the API (a string, never
// executed).
function fetchFileContent(filename) {
  // contents API at the PR head ref.
  const headSha = gh(["api", `repos/${REPO}/pulls/${PR_NUMBER}`, "--jq", ".head.sha"]).trim();
  const b64 = gh([
    "api",
    `repos/${REPO}/contents/${filename}?ref=${headSha}`,
    "--jq",
    ".content",
  ]).replace(/\n/g, "");
  return Buffer.from(b64, "base64").toString("utf8");
}

// Download the author-hosted artifact for STATIC inspection only: list entries +
// flag obviously risky filenames. We do NOT extract into an executable layout and
// we never run anything. Returns a short text summary (or a note on failure).
async function staticInspectArtifact(url) {
  if (!/^https?:\/\//.test(url || "")) return "artifact_url not http(s); skipped.";
  try {
    const res = await fetch(url, { redirect: "follow" });
    if (!res.ok) return `artifact fetch failed: HTTP ${res.status}`;
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > 25 * 1024 * 1024) return `artifact ${buf.length} bytes — too large to inspect inline; manual review advised.`;
    const dir = mkdtempSync(join(tmpdir(), "art-"));
    const tgz = join(dir, "artifact.tar.gz");
    writeFileSync(tgz, buf);
    // `tar -tz` LISTS entries; it does not extract or execute. Static only.
    let listing = "";
    try {
      listing = execFileSync("tar", ["-tzf", tgz], { encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
    } catch (e) {
      return `artifact is not a readable .tar.gz (${(e.message || "").slice(0, 80)}); manual review advised.`;
    }
    const entries = listing.split("\n").filter(Boolean);
    const risky = entries.filter((e) =>
      /\.(sh|bash|exe|dll|so|dylib)$/i.test(e) || /(^|\/)(install|postinstall|preinstall)\b/i.test(e)
    );
    const head = entries.slice(0, 60).join("\n");
    return [
      `artifact: ${buf.length} bytes, ${entries.length} entries.`,
      risky.length ? `potentially-executable/install entries:\n${risky.slice(0, 40).join("\n")}` : "no obviously-executable/install entries flagged by filename.",
      `entry listing (first 60):\n${head}`,
    ].join("\n\n");
  } catch (e) {
    return `artifact inspection error: ${(e.message || "").slice(0, 120)}`;
  }
}

async function callClaude(prompt) {
  const res = await fetch(ANTHROPIC_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": ANTHROPIC_API_KEY,
      "anthropic-version": ANTHROPIC_VERSION,
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 1500,
      messages: [{ role: "user", content: prompt }],
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Anthropic API ${res.status}: ${body.slice(0, 300)}`);
  }
  const data = await res.json();
  return (data.content || []).map((b) => b.text || "").join("").trim();
}

function buildPrompt(submission, artifactSummary) {
  return [
    "You are the security/quality reviewer for the AiHummer PUBLIC plugin marketplace.",
    "Assess the risk of the following plugin SUBMISSION. You are ADVISORY: a human",
    "maintainer makes the final merge decision. Be concise and specific.",
    "",
    "Assess these dimensions:",
    "1. Malware / supply-chain red flags (pipe-to-shell installers, obfuscation,",
    "   surprising executables, network calls at install/start).",
    "2. Over-broad scope/egress: are declared capabilities, scope, and",
    "   openapi.allowed_hosts justified and least-privilege? Flag any '*' egress.",
    "3. Capability/permission MISMATCH vs the stated description (does it ask for",
    "   more than it claims to do?).",
    "4. License issues (present, OSS-compatible, consistent).",
    "",
    "Return EXACTLY this structure:",
    "VERDICT: one of [APPROVE / APPROVE-WITH-NOTES / NEEDS-CHANGES / REJECT]",
    "RISK: one of [low / medium / high]",
    "FINDINGS: bullet list (cite the field). Say 'none' if clean.",
    "MAINTAINER-NOTES: what the human should double-check before merging.",
    "",
    "=== submission plugin.json ===",
    "```json",
    JSON.stringify(submission, null, 2),
    "```",
    "",
    "=== static artifact inspection (NOT executed) ===",
    artifactSummary,
  ].join("\n");
}

function postComment(body) {
  // gh pr comment — COMMENT only. This script has no merge capability.
  const tmp = join(mkdtempSync(join(tmpdir(), "cmt-")), "body.md");
  writeFileSync(tmp, body);
  gh(["pr", "comment", String(PR_NUMBER), "--repo", REPO, "--body-file", tmp]);
}

async function main() {
  const files = changedCatalogFiles();
  if (files.length === 0) {
    console.log("no changed catalog/**/plugin.json files — nothing to review.");
    return;
  }

  const sections = [];
  for (const f of files) {
    let submission;
    try {
      submission = JSON.parse(fetchFileContent(f.filename));
    } catch (e) {
      sections.push(`### \`${f.filename}\`\n\nCould not parse as JSON: ${e.message}`);
      continue;
    }
    const artifactSummary = await staticInspectArtifact(submission.artifact_url);
    let verdict;
    try {
      verdict = await callClaude(buildPrompt(submission, artifactSummary));
    } catch (e) {
      verdict = `AI review error: ${e.message}`;
    }
    sections.push(`### \`${f.filename}\` — ${submission.namespaced_slug || ""}@${submission.version || "?"}\n\n${verdict}`);
  }

  const header = [
    "## 🤖 AI risk review (advisory — a human maintainer makes the final call)",
    "",
    `Model: \`${MODEL}\`. This bot **only comments**; it never merges. The plugin`,
    "artifact was inspected **statically** (listing/strings) and **never executed**.",
    "Maintainers: complete the checklist in the PR template before merging.",
    "",
  ].join("\n");

  postComment(header + sections.join("\n\n---\n\n"));
  console.log(`posted AI review for ${files.length} file(s).`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
