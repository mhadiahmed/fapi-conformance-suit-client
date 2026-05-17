#!/usr/bin/env bash
#
# Generate per-test client logs for OpenID RP certification submission.
#
# Produces one file per test in ./client-logs/, named exactly as the
# OpenID conformance test (e.g. fapi1-advanced-final-client-test-invalid-iss.log)
# so the OpenID Foundation can match each client log to its server-side test.
#
# Final output: client-logs.zip — upload this in the "Exported Test Results"
# field of your certification request alongside the conformance suite export.
#
# Usage:
#   ./run-conformance-logs.sh <discoveryUrl> <resourceEndpoint> [--profile fapi1|oidcc]
#
# Example:
#   ./run-conformance-logs.sh \
#     https://www.certification.openid.net/test/a/ksa-rp-seentarbie/.well-known/openid-configuration \
#     https://www.certification.openid.net/test/a/ksa-rp-seentarbie/accounts
#
# Notes:
#   - Each test runs against its OWN conformance-suite test instance. Before
#     calling this script, create the test plan in the conformance suite UI,
#     then for each test the suite assigns a unique discoveryUrl path. If your
#     plan uses a single alias and the suite rotates internally, the base URL
#     above is enough.
#   - For tests that do not take URL args in our CLI (the *Mock variants),
#     the script just invokes the CLI without extras.
#

set -u  # do NOT use -e — negative tests are expected to exit non-zero, that's the proof

# ----- args -----
DISCOVERY_URL="${1:-}"
RESOURCE_ENDPOINT="${2:-}"
PROFILE="fapi1"  # default to FAPI Advanced Final RP test name prefix

# parse --profile flag if given
shift 2 || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [[ -z "$DISCOVERY_URL" || -z "$RESOURCE_ENDPOINT" ]]; then
    echo "Usage: $0 <discoveryUrl> <resourceEndpoint> [--profile fapi1|oidcc]"
    exit 1
fi

# Test-name prefix per certification profile.
# Match this to the test plan you registered in the conformance suite.
case "$PROFILE" in
    fapi1)
        PREFIX="fapi1-advanced-final-client-test"
        ;;
    oidcc)
        PREFIX="oidcc-client-test"
        ;;
    *)
        echo "Unknown profile: $PROFILE (use fapi1 or oidcc)"
        exit 1
        ;;
esac

LOG_DIR="client-logs"
ZIP_NAME="client-logs.zip"

# Build TypeScript once before running anything
echo "==> Building TypeScript..."
npm run build || { echo "Build failed"; exit 1; }

mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/*.log "$ZIP_NAME"

# Map: <CLI subcommand>|<official test suffix>|<extra args>
# - CLI subcommand: the value passed to dist/index.js
# - official test suffix: appended to $PREFIX to form the log filename
# - extra args: "url" if the subcommand needs discoveryUrl + resourceEndpoint,
#               empty otherwise
TESTS=(
    "happy-path|         |url"
    "invalid-issuer|-invalid-iss|"
    "invalid-audience|-invalid-aud|"
    "invalid-signature|-invalid-id_token-signature|"
    "none-algorithm|-bad-signature-rs256|"
    "expired-exp|-invalid-id_token-expired|"
    "missing-exp|-missing-id_token-exp|"
    "invalid-s-hash|-invalid-shash|"
    "invalid-c-hash|-invalid-chash|"
    "invalid-nonce|-nonce-invalid|"
    "old-iat|-iat-in-the-past|"
    "missing-at-hash|-missing-at_hash|url"
    "aud-as-array|-aud-as-array|url"
    "no-scope|-scope-not-returned-in-token-response|url"
    "missing-fields|-token-response-missing-fields|"
    "refresh-token|-refresh-token|url"
    "encrypted-idtoken|-encrypted-id_token|url"
    "encrypted-rsa15|-encrypted-id_token-rsa1_5-rejection|url"
)

run_one() {
    local cli="$1"
    local suffix="$2"
    local needs_url="$3"
    local fname="${PREFIX}${suffix}.log"
    local path="$LOG_DIR/$fname"

    echo
    echo "==> Test: $cli  ->  $fname"
    {
        echo "============================================================"
        echo " OpenID RP Certification — client-side evidence log"
        echo " Test name : ${PREFIX}${suffix}"
        echo " CLI cmd   : node dist/index.js $cli"
        echo " Profile   : $PROFILE"
        echo " Started   : $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "============================================================"
        echo
        if [[ "$needs_url" == "url" ]]; then
            node dist/index.js "$cli" "$DISCOVERY_URL" "$RESOURCE_ENDPOINT" 2>&1
        else
            node dist/index.js "$cli" 2>&1
        fi
        local rc=$?
        echo
        echo "============================================================"
        echo " Exit code : $rc"
        echo " Finished  : $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        if [[ $rc -ne 0 ]]; then
            echo " NOTE: non-zero exit. For NEGATIVE tests this is the"
            echo "       expected behavior — the client detected the bad"
            echo "       server response and refused to proceed."
        fi
        echo "============================================================"
    } > "$path"
}

for entry in "${TESTS[@]}"; do
    IFS='|' read -r cli suffix needs_url <<< "$entry"
    cli="$(echo "$cli" | xargs)"
    suffix="$(echo "$suffix" | xargs)"
    needs_url="$(echo "$needs_url" | xargs)"
    run_one "$cli" "$suffix" "$needs_url"
done

echo
echo "==> Packaging $ZIP_NAME ..."
cd "$LOG_DIR" && zip -q "../$ZIP_NAME" ./*.log && cd ..

echo
echo "Done."
echo "  Logs : $LOG_DIR/"
echo "  Zip  : $ZIP_NAME"
echo
echo "Upload $ZIP_NAME together with the conformance-suite test-plan export"
echo "in the 'Exported Test Results' field of your certification request."
