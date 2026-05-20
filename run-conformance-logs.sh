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
# ============================================================================
# RECOMMENDED PER-TEST WORKFLOW (the OpenID suite drives RP plans one test at
# a time — only one test is "active" in the UI at any moment, so all-at-once
# runs hit the same active test repeatedly):
#
#   1. List your plan's tests:
#        ./run-conformance-logs.sh --list
#
#   2. For each test in the plan, in order:
#        a. In the suite UI, click "Create Test" so it shows "Waiting".
#        b. ./run-conformance-logs.sh <discoveryUrl> <resourceEndpoint> \
#               --only <suffix>
#        c. Confirm the new log under client-logs/ looks right
#           (negative tests should log a clear rejection).
#
#   3. When all per-test logs are present:
#        ./run-conformance-logs.sh --zip-only
#      → produces client-logs.zip ready for submission.
# ============================================================================
#
# Other usage:
#   ./run-conformance-logs.sh <discoveryUrl> <resourceEndpoint> \
#       [--profile fapi1|oidcc]          # run ALL tests sequentially
#   ./run-conformance-logs.sh --list [--profile fapi1|oidcc]
#   ./run-conformance-logs.sh --zip-only
#
# --only matches any of:
#     - CLI subcommand (e.g. invalid-issuer)
#     - test suffix with or without leading dash (e.g. invalid-iss, -invalid-iss)
#     - full OpenID test name (e.g. fapi1-advanced-final-client-test-invalid-iss)
#

set -u  # do NOT use -e — negative tests are expected to exit non-zero, that's the proof

# ----- args -----
DISCOVERY_URL=""
RESOURCE_ENDPOINT=""
PROFILE="fapi1"
ONLY=""
ZIP_ONLY=0
LIST_ONLY=0

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="${2:-}"; shift 2 ;;
        --only)
            ONLY="${2:-}"; shift 2 ;;
        --zip-only)
            ZIP_ONLY=1; shift ;;
        --list)
            LIST_ONLY=1; shift ;;
        -h|--help)
            sed -n '2,42p' "$0"; exit 0 ;;
        *)
            POSITIONAL+=("$1"); shift ;;
    esac
done

DISCOVERY_URL="${POSITIONAL[0]:-}"
RESOURCE_ENDPOINT="${POSITIONAL[1]:-}"

# Test-name prefix per certification profile.
case "$PROFILE" in
    fapi1) PREFIX="fapi1-advanced-final-client-test" ;;
    oidcc) PREFIX="oidcc-client-test" ;;
    *) echo "Unknown profile: $PROFILE (use fapi1 or oidcc)"; exit 1 ;;
esac

LOG_DIR="client-logs"
ZIP_NAME="client-logs.zip"

# Map: <CLI subcommand>|<official test suffix>|<extra args>
# - CLI subcommand: the value passed to dist/index.js
# - official test suffix: appended to $PREFIX to form the log filename
# - extra args: "url" if the subcommand needs discoveryUrl + resourceEndpoint
TESTS=(
    "happy-path|         |url"
    "invalid-issuer|-invalid-iss|"
    "invalid-missing-iss|-invalid-missing-iss|"
    "discovery-issuer-mismatch|-discovery-issuer-mismatch|"
    "invalid-audience|-invalid-aud|"
    "invalid-missing-aud|-invalid-missing-aud|"
    "invalid-secondary-aud|-invalid-secondary-aud|"
    "invalid-signature|-invalid-signature|"
    "invalid-null-alg|-invalid-null-alg|"
    "invalid-alternate-alg|-invalid-alternate-alg|"
    "invalid-expired-exp|-invalid-expired-exp|"
    "invalid-missing-exp|-invalid-missing-exp|"
    "iat-is-week-in-past|-iat-is-week-in-past|"
    "invalid-shash|-invalid-shash|"
    "invalid-missing-shash|-invalid-missing-shash|"
    "invalid-chash|-invalid-chash|"
    "invalid-nonce|-invalid-nonce|"
    "invalid-missing-nonce|-invalid-missing-nonce|"
    "missing-at-hash|-missing-athash|url"
    "aud-as-array|-valid-aud-as-array|url"
    "no-scope|-no-scope-in-token-endpoint-response|url"
    "missing-fields|-token-response-missing-fields|"
    "encrypted-idtoken|-encrypted-idtoken|url"
    "encrypted-rsa15|-encrypted-idtoken-usingrsa15|url"
    # refresh-token has a non-standard official filename
    # (fapi1-advanced-final-client-refresh-token-test, with "refresh-token" INSIDE
    # the prefix, not appended). Its row uses an OVERRIDE filename in the 4th field.
    "refresh-token|         |url|fapi1-advanced-final-client-refresh-token-test"
)

trim() { echo "$1" | xargs; }

# --- --list -----------------------------------------------------------------
if [[ $LIST_ONLY -eq 1 ]]; then
    echo "Tests available for profile '$PROFILE' (prefix: $PREFIX)"
    echo
    printf "  %-22s  %s\n" "CLI / --only value" "OFFICIAL TEST NAME"
    printf "  %-22s  %s\n" "------------------" "------------------"
    for entry in "${TESTS[@]}"; do
        IFS='|' read -r cli suffix _ override_fname <<< "$entry"
        cli="$(trim "$cli")"; suffix="$(trim "$suffix")"; override_fname="$(trim "$override_fname")"
        if [[ -n "$override_fname" ]]; then
            printf "  %-22s  %s\n" "$cli" "$override_fname"
        else
            printf "  %-22s  %s\n" "$cli" "${PREFIX}${suffix}"
        fi
    done
    echo
    echo "Use:  ./run-conformance-logs.sh <discoveryUrl> <resourceEndpoint> --only <cli-or-suffix>"
    exit 0
fi

# --- --zip-only -------------------------------------------------------------
if [[ $ZIP_ONLY -eq 1 ]]; then
    if [[ ! -d "$LOG_DIR" ]] || ! compgen -G "$LOG_DIR/*.log" > /dev/null; then
        echo "No logs found in $LOG_DIR/ — nothing to zip."
        echo "Run individual tests first with --only, or a full run."
        exit 1
    fi
    rm -f "$ZIP_NAME"
    (cd "$LOG_DIR" && zip -q "../$ZIP_NAME" ./*.log)
    n=$(ls "$LOG_DIR"/*.log 2>/dev/null | wc -l)
    echo "Packaged $ZIP_NAME ($n log file(s))"
    echo
    echo "Upload $ZIP_NAME together with the conformance-suite test-plan export"
    echo "in the 'Exported Test Results' field of your certification request."
    exit 0
fi

# --- normal/--only run -------------------------------------------------------
if [[ -z "$DISCOVERY_URL" || -z "$RESOURCE_ENDPOINT" ]]; then
    echo "Usage:"
    echo "  $0 <discoveryUrl> <resourceEndpoint> [--profile fapi1|oidcc] [--only <suffix>]"
    echo "  $0 --list [--profile fapi1|oidcc]"
    echo "  $0 --zip-only"
    exit 1
fi

# Build TS once
echo "==> Building TypeScript..."
npm run build || { echo "Build failed"; exit 1; }

mkdir -p "$LOG_DIR"
# Wipe only on a full run; preserve when --only so logs accumulate per-test
if [[ -z "$ONLY" ]]; then
    rm -f "$LOG_DIR"/*.log "$ZIP_NAME"
fi

# Match an --only value against a TESTS row
match_only() {
    local cli="$1" suffix="$2"
    local fullname="${PREFIX}${suffix}"
    [[ "$ONLY" == "$cli" ]] && return 0
    [[ "$ONLY" == "$suffix" ]] && return 0
    [[ "$ONLY" == "${suffix#-}" ]] && return 0
    [[ "$ONLY" == "$fullname" ]] && return 0
    return 1
}

run_one() {
    local cli="$1"
    local suffix="$2"
    local needs_url="$3"
    local override_fname="$4"
    local fname
    if [[ -n "$override_fname" ]]; then
        fname="${override_fname}.log"
    else
        fname="${PREFIX}${suffix}.log"
    fi
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

ran_any=0
for entry in "${TESTS[@]}"; do
    IFS='|' read -r cli suffix needs_url override_fname <<< "$entry"
    cli="$(trim "$cli")"
    suffix="$(trim "$suffix")"
    needs_url="$(trim "$needs_url")"
    override_fname="$(trim "$override_fname")"

    if [[ -n "$ONLY" ]]; then
        if match_only "$cli" "$suffix"; then
            run_one "$cli" "$suffix" "$needs_url" "$override_fname"
            ran_any=1
            break
        fi
    else
        run_one "$cli" "$suffix" "$needs_url" "$override_fname"
        ran_any=1
    fi
done

if [[ -n "$ONLY" && $ran_any -eq 0 ]]; then
    echo
    echo "ERROR: --only '$ONLY' did not match any test."
    echo "       Run './run-conformance-logs.sh --list' to see valid values."
    exit 1
fi

# Auto-zip only on a full run. For --only runs, the user collects logs
# across many invocations, then explicitly calls --zip-only at the end.
if [[ -z "$ONLY" ]]; then
    echo
    echo "==> Packaging $ZIP_NAME ..."
    (cd "$LOG_DIR" && zip -q "../$ZIP_NAME" ./*.log)
    echo
    echo "Done."
    echo "  Logs : $LOG_DIR/"
    echo "  Zip  : $ZIP_NAME"
    echo
    echo "Upload $ZIP_NAME together with the conformance-suite test-plan export"
    echo "in the 'Exported Test Results' field of your certification request."
else
    echo
    echo "Done. Log written to $LOG_DIR/${PREFIX}<suffix>.log"
    echo "When all per-test logs are collected, run:  $0 --zip-only"
fi
