# FAPI / OpenID RP Conformance Client

A TypeScript Relying-Party (RP) reference client for the OpenID FAPI 1.0 Advanced Final certification, plus the tooling that takes you from an empty repo to a complete, OpenID-Foundation-ready submission **with zero clicks in the suite UI**.

Originally built to certify *Seen Tarbie's* FAPI KSA `private_key_jwt` plan, the project is fully white-label: any organisation testing an OpenID Connect / FAPI flow can clone, drop in their own credentials, and submit.

## What you get

| Tool | What it does |
|---|---|
| `dist/index.js <test-name>` | The actual FAPI RP client. Runs one test (happy path, invalid-iss, refresh-token, …) end-to-end against a live conformance suite alias. |
| `run-conformance-logs.sh` | **Manual mode.** Wraps the CLI so you can run one or all tests yourself, click through the suite UI between them, and collect per-test client logs. |
| `dist/orchestrate-cert.js` | **Automated mode.** Drives the entire test plan via the conformance suite's REST API: creates each test, polls until it's ready, runs the client, captures the log, advances. No UI clicks. |
| `client-logs.zip` | The official submission artefact — one log per test, named exactly as OpenID expects. |

## Prerequisites

- Node.js 18+ (this project's `package.json` was built against `@types/node@22`)
- An account at <https://www.certification.openid.net> with an API token (`/tokens.html`)
- A test plan already created in the suite UI for the profile you're certifying (e.g. `fapi1-advanced-final-client-test-plan`)
- Your own client identity: `client_id`, JWKS signing key, and (for FAPI Advanced) an mTLS certificate

## 1. Setup

```bash
git clone <this-repo>
cd fapi
npm install
cp .env.example .env
```

Open `.env` and fill in:

```bash
SUITE_TOKEN=<your API token from /tokens.html>
SUITE_PLAN_ID=<plan ID from the URL of your suite plan page>
SUITE_ALIAS=<the alias you set when creating the plan>
SUITE_DISCOVERY_URL=https://www.certification.openid.net/test/a/<alias>/.well-known/openid-configuration
SUITE_RESOURCE_ENDPOINT=<your protected-resource URL — e.g. /open-banking/v1.1/accounts under your mTLS host>
CLIENT_ID=<your client_id from the plan>
KEY_ID=<your signing JWKS kid>
```

### Drop in your client material

Place these files under `src/certs/` (never commit private keys):

| File | What it is |
|---|---|
| `src/certs/private_key.pem` | Your **JWT signing** private key (used for `private_key_jwt` client assertions, PS256) |
| `src/certs/certs.pem` | Your **mTLS** client certificate chain |
| `src/certs/privatekey.key` | Your **mTLS** client private key |
| `src/certs/client2_signing_key.pem` | (Only for encrypted-id_token tests) second client's JWT signing key |
| `src/certs/client2_encryption_key.pem` | (Only for encrypted-id_token tests) second client's encryption key |

Then register the corresponding **public** JWKS with your test plan in the suite UI.

### Build

```bash
npm run build
```

## 2. Run — pick a mode

### Mode A — Automated (recommended): drive the entire plan via the API

This is the fast path. One command runs all 24+ tests, captures per-test logs, and zips them.

```bash
npm run cert-run                              # run every module in your plan
npm run cert-run -- --only happy-path         # run a single module (by CLI name or full module name)
npm run cert-run -- --dry-run                 # show what would run without hitting the API
npm run cert-run -- --upload                  # after the run, POST client-logs.zip to /api/plan/{id}/certificationpackage
                                              # ⚠ this PUBLISHES the plan and marks it IMMUTABLE
```

Flags can also be passed via env:

```bash
SUITE_TOKEN=... SUITE_PLAN_ID=... npm run cert-run
```

**What it does for each module:**

1. `POST /api/runner?test=<module>&plan=<id>` — creates the test instance, the alias rotates to it
2. Polls `GET /api/info/{id}` until status `WAITING`
3. Spawns `node dist/index.js <local-cli> <discoveryUrl> <resourceEndpoint>` and tees stdout+stderr to `client-logs/<module>.log`
4. Polls until `FINISHED`/`INTERRUPTED`
5. `DELETE /api/runner/{id}` to free the alias for the next module
6. After all modules: zips `client-logs/` → `client-logs.zip`

A successful run looks like:

```
SUMMARY
=========================================================
  fapi1-advanced-final-client-test                                 → FINISHED (local exit 0)
  fapi1-advanced-final-client-test-invalid-iss                     → FINISHED (local exit 0)
  fapi1-advanced-final-client-test-invalid-aud                     → FINISHED (local exit 0)
  ...
Zip created: /<repo>/client-logs.zip
```

### Mode B — Manual: per-test, with UI clicks

Useful when you want to inspect the suite UI between tests, or you don't want the script to drive the API.

```bash
./run-conformance-logs.sh --list                 # show every CLI command + the OpenID test name it produces
./run-conformance-logs.sh --only happy-path \    # run one test (click Create-Test in the UI first)
    <discoveryUrl> <resourceEndpoint>
./run-conformance-logs.sh --zip-only             # after collecting all logs, zip them
```

For a full plan in manual mode: in the suite UI, click **Create Test** for each test → wait for `WAITING` → run the matching `--only <name>` → repeat. When done, `--zip-only`.

## 3. Verify the logs

Every negative-test log **must** contain an explicit `REJECTED:` line. The OpenID reviewer will check for these. Quick audit:

```bash
cd client-logs
for f in *.log; do
    echo "=== $f ==="
    grep -E "REJECTED:|Test PASSED" "$f" | head -3
done
```

Expected output per file: a `REJECTED:` line (for negative tests) or a `✓ Test PASSED:` line (for positive tests).

## 4. Submit to OpenID

**Two paths:**

**Manual:** Attach `client-logs.zip` to your reply on the OpenID Foundation certification ticket.

**Programmatic:** Run `npm run cert-run -- --upload`. This calls `POST /api/plan/{id}/certificationpackage` with the zip, **publishes** your plan, makes it **immutable**, and saves the official `certification-package.zip` next to `client-logs.zip`. Only do this when every log looks right.

## Test mapping reference

The `MODULE_TO_CLI` table in `src/orchestrate-cert.ts` maps each OpenID conformance test name to the local CLI subcommand that exercises it. If your plan contains a test not in the table, add a row there.

| CLI subcommand | OpenID module name |
|---|---|
| `happy-path` | `fapi1-advanced-final-client-test` |
| `invalid-issuer` | `fapi1-advanced-final-client-test-invalid-iss` |
| `invalid-missing-iss` | `fapi1-advanced-final-client-test-invalid-missing-iss` |
| `invalid-audience` | `fapi1-advanced-final-client-test-invalid-aud` |
| `invalid-missing-aud` | `fapi1-advanced-final-client-test-invalid-missing-aud` |
| `invalid-secondary-aud` | `fapi1-advanced-final-client-test-invalid-secondary-aud` |
| `invalid-signature` | `fapi1-advanced-final-client-test-invalid-signature` |
| `invalid-null-alg` | `fapi1-advanced-final-client-test-invalid-null-alg` |
| `invalid-alternate-alg` | `fapi1-advanced-final-client-test-invalid-alternate-alg` |
| `invalid-expired-exp` | `fapi1-advanced-final-client-test-invalid-expired-exp` |
| `invalid-missing-exp` | `fapi1-advanced-final-client-test-invalid-missing-exp` |
| `iat-is-week-in-past` | `fapi1-advanced-final-client-test-iat-is-week-in-past` |
| `invalid-shash` | `fapi1-advanced-final-client-test-invalid-shash` |
| `invalid-missing-shash` | `fapi1-advanced-final-client-test-invalid-missing-shash` |
| `invalid-chash` | `fapi1-advanced-final-client-test-invalid-chash` |
| `invalid-nonce` | `fapi1-advanced-final-client-test-invalid-nonce` |
| `invalid-missing-nonce` | `fapi1-advanced-final-client-test-invalid-missing-nonce` |
| `discovery-issuer-mismatch` | `fapi1-advanced-final-client-test-discovery-issuer-mismatch` |
| `encrypted-idtoken` | `fapi1-advanced-final-client-test-encrypted-idtoken` |
| `encrypted-rsa15` | `fapi1-advanced-final-client-test-encrypted-idtoken-usingrsa15` |
| `aud-as-array` | `fapi1-advanced-final-client-test-valid-aud-as-array` |
| `no-scope` | `fapi1-advanced-final-client-test-no-scope-in-token-endpoint-response` |
| `missing-at-hash` | `fapi1-advanced-final-client-test-missing-athash` |
| `refresh-token` | `fapi1-advanced-final-client-refresh-token-test` |

## Validator chain

The detection that produces the `REJECTED:` lines lives in `src/fapiClient.ts` → `handleRedirectUrlAndExchangeCode`. After extracting the `id_token` from the redirect fragment, the client runs:

1. `alg = none` rejection
2. `alg ≠ PS256` rejection (FAPI requirement)
3. Required claims present (`iss`, `aud`, `exp`, `nonce`)
4. Signature verification
5. `iss` matches configured issuer
6. `aud` matches client_id
7. `exp` not in the past
8. `iat` not absurdly old
9. `nonce` matches the one we sent
10. `s_hash` matches the returned `state`
11. `c_hash` matches the returned `code`
12. `azp` rule when `aud` is multi-valued, plus "no untrusted secondary audience"

Each failing check throws with a message that gets logged as a `REJECTED:` line.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `POST /api/runner → 415 …form-urlencoded… is not supported` | The orchestrator uses Node's native `fetch` so it sends *no* Content-Type for the body-less POST. If you've forked the script and switched to axios, restore the `fetch` call in `createTest()`. |
| `POST /api/runner → 400` | Don't send a body when creating a test from a plan. The suite treats any body as a "supplied configuration". |
| Stuck at `Waiting for WAITING state…` | Either the test failed to allocate (check the suite UI for the test ID — look for a CONFIGURED→FAILED transition) or your alias is in use by another running test. The orchestrator auto-cancels stale tests on startup. |
| Local CLI exits with `Usage: …` | Your `.env` doesn't have `SUITE_DISCOVERY_URL` and `SUITE_RESOURCE_ENDPOINT` set. |
| Discovery issuer rejected on every test | The `issuer` claim in your test plan's discovery doc doesn't match your `SUITE_ALIAS`. Either fix the alias or remove the discovery-issuer-mismatch validator from `fapiClient.ts` for non-conformance use. |
| `Cannot find module './certs/private_key.pem'` | You missed step 1's certificate placement. The signing key + mTLS cert + mTLS key all need to exist under `src/certs/`. |

## Scripts (in `package.json`)

```bash
npm run build               # tsc + copy src/certs/ to dist/certs/
npm run cert-run            # automated full-plan run (with .env)
npm run cert-logs           # manual per-test wrapper (alias for run-conformance-logs.sh)
npm run cert-logs:fapi      # same, explicit FAPI profile
npm run cert-logs:oidcc     # same, OIDCC profile
npm run refresh-token-test  # legacy: standalone refresh-token script
npm run encrypted-idtoken-test  # legacy: standalone encrypted id_token script
```

## Project layout

```
src/
├── index.ts                 # CLI entry point + all test runners
├── fapiClient.ts            # the FAPI client itself (FAPIClient class)
├── orchestrate-cert.ts      # automated plan-driver (talks to the suite REST API)
├── jwks-server.ts           # tiny static JWKS server (optional)
├── certs/                   # your signing key + mTLS cert/key (gitignored)
└── __tests__/               # unit tests

run-conformance-logs.sh      # manual per-test wrapper
conformance-config.json      # client/plan config you upload to the suite UI
.env / .env.example          # credentials + plan / endpoint config
client-logs/                 # per-test client evidence logs (produced by orchestrator)
client-logs.zip              # final submission artefact
```

## License

MIT
