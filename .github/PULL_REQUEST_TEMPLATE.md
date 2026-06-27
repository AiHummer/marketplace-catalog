<!--
For plugin SUBMISSIONS: the automated `validate` check must pass and a maintainer
must complete the moderation checklist below before merge. See MODERATION.md.
The `ai-review` bot will post a risk verdict — read it before deciding.
-->

## What is this PR?

<!-- New publisher? New plugin? Version bump? Briefly: what does the plugin do? -->

- Publisher:
- Plugin (`@publisher/slug`):
- Version / channel:
- Artifact URL:

---

## Maintainer moderation checklist

> Complete before merge. This is the **mandatory human** step — the AI review is
> advisory only.

- [ ] **Does the plugin do what it claims?** Description, capabilities, and the
      actual manifest/artifact line up — no hidden behavior.
- [ ] **No malware / obfuscation red flags.** No pipe-to-shell installers, no
      obfuscated/minified blobs presented as source, no surprising network calls.
- [ ] **Scopes are reasonable & justified.** Declared `scope`/`capabilities`
      match what the plugin needs (least privilege).
- [ ] **Egress is reasonable & justified.** `openapi.allowed_hosts` is scoped to
      specific hosts the plugin genuinely needs (no `*`, no unrelated domains).
- [ ] **License is acceptable** and present (`license` non-empty; OSS-compatible).
- [ ] **AI-review verdict read.** The `ai-review` bot comment was reviewed and any
      flagged risks are resolved or explicitly accepted (note why below).
- [ ] **Publisher trust tier considered.** New publisher → full review; an
      established publisher with a track record → faster path (see MODERATION.md,
      trust tiers).

### Decision notes
<!-- Anything the next maintainer should know: accepted risks, follow-ups, etc. -->
