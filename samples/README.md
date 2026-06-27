# Samples

The repo ships a working reference submission so the validator has something to
pass against and so contributors can copy a known-good shape:

- `publishers/acme.json` — a demo publisher `acme`.
- `catalog/acme/hello-tool/plugin.json` — a demo `@acme/hello-tool@1.0.0`
  submission, correctly signed over `slug\0version\0artifact_url`.

## The demo key is a THROWAWAY

The `acme` keypair is a **disposable demo key generated solely for this sample**.
It is **not** a publisher of record and **not** the registry key. Its public half
is in `publishers/acme.json`; its **private half is intentionally NOT in this
repo**.

If you need to re-sign the sample (e.g. after changing the artifact URL or
version), generate a fresh throwaway keypair and update both files — never reuse a
real publisher key or the registry key for samples:

```bash
node - <<'EOF'
const crypto = require("crypto");
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const pubRaw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
const seed  = Buffer.from(privateKey.export({ format: "jwk" }).d, "base64url");
const pubB64 = pubRaw.toString("base64");
const keyId  = crypto.createHash("sha256").update(pubRaw).digest("hex").slice(0, 16);

// edit these to match your sample submission:
const slug = "hello-tool";
const version = "1.0.0";
const artifactUrl = "https://acme.example.com/plugins/hello-tool-1.0.0.tar.gz";

const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
const pk = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
const sig = crypto.sign(null, Buffer.from(`${slug}\x00${version}\x00${artifactUrl}`), pk);

console.log("public_key:", pubB64);
console.log("key_id:    ", keyId);
console.log("signature: ", sig.toString("base64"));
EOF
```
Put `public_key`/`key_id` in `publishers/acme.json`, and `key_id`/`signature` in
the submission. The private key (`seed`) is printed only here at your terminal —
do **not** commit it.
