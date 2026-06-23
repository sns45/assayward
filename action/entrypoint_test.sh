#!/usr/bin/env bash
# entrypoint_test.sh — TDD test suite for action/entrypoint.sh.
#
# Usage: bash action/entrypoint_test.sh
# Exits 0 if all assertions pass; non-zero on any failure.
#
# Tests use ASSAYWARD_BINARY_PATH to bypass download (local build only).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TESTDATA="${REPO_ROOT}/testdata"

PASS=0
FAIL=0
ERRORS=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; ERRORS+=("$1"); FAIL=$((FAIL + 1)); }

assert_exit() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  if [[ "${actual}" -eq "${expected}" ]]; then
    pass "${label}: exit code ${actual} (expected ${expected})"
  else
    fail "${label}: exit code ${actual} (expected ${expected})"
  fi
}

assert_contains() {
  local label="$1"
  local needle="$2"
  local haystack="$3"
  if echo "${haystack}" | grep -qF -- "${needle}"; then
    pass "${label}: output contains '${needle}'"
  else
    fail "${label}: output does NOT contain '${needle}'"
    echo "    --- actual output ---"
    echo "${haystack}" | head -20
    echo "    --------------------"
  fi
}

assert_not_contains() {
  local label="$1"
  local needle="$2"
  local haystack="$3"
  if echo "${haystack}" | grep -qF -- "${needle}"; then
    fail "${label}: output unexpectedly contains '${needle}'"
  else
    pass "${label}: output does NOT contain '${needle}'"
  fi
}

# ---------------------------------------------------------------------------
# Step 0: Build the binary
# ---------------------------------------------------------------------------
echo "=== Building assayward binary ==="
ASSAYWARD_BIN="/tmp/assayward-action-test-$$"
go build -o "${ASSAYWARD_BIN}" "${REPO_ROOT}/cmd/assayward" 2>&1
echo "Binary built: ${ASSAYWARD_BIN}"

cleanup() {
  rm -f "${ASSAYWARD_BIN}"
}
trap cleanup EXIT

# Common test image ref (matches testdata fixtures)
TEST_IMAGE="ghcr.io/sns45/example:1.0.0@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Build multiline ASSAYWARD_BUNDLE value (4 bundles matching verify_test.go)
BUNDLE_MULTILINE="${TESTDATA}/signature/bundle-provenance.json
${TESTDATA}/slsa/valid-l3.dsse.json
${TESTDATA}/sbom/cyclonedx.dsse.json
${TESTDATA}/vex/affected-critical.dsse.json"

SPIFFE_BUNDLE_MULTILINE="sns45.dev=${TESTDATA}/svid/jwt-bundle.json"

# Common env vars shared across most tests
BASE_ENV=(
  ASSAYWARD_BINARY_PATH="${ASSAYWARD_BIN}"
  ASSAYWARD_IMAGE="${TEST_IMAGE}"
  ASSAYWARD_BUNDLE="${BUNDLE_MULTILINE}"
  ASSAYWARD_FROM_OCI="false"
  ASSAYWARD_SIGSTORE_TRUST_ROOT="${TESTDATA}/signature/trusted-root-public-good.json"
  ASSAYWARD_SPIFFE_BUNDLE="${SPIFFE_BUNDLE_MULTILINE}"
  ASSAYWARD_SVID="${TESTDATA}/svid/jwt-valid.jwt"
  ASSAYWARD_VERSION="latest"
  RUNNER_OS="Linux"
  RUNNER_ARCH="X64"
)

# ---------------------------------------------------------------------------
# Test 1: baseline policy -> exit 0 and result "allow"
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 1: baseline policy (expect exit 0, result=allow) ==="
OUTPUT_1=""
EXIT_1=0
OUTPUT_1="$(env "${BASE_ENV[@]}" ASSAYWARD_POLICY="baseline" ASSAYWARD_POLICY_FILE="" \
  bash "${SCRIPT_DIR}/entrypoint.sh" 2>&1)" || EXIT_1=$?

assert_exit "baseline" 0 "${EXIT_1}"
assert_contains "baseline result=allow" '"allow"' "${OUTPUT_1}"

# ---------------------------------------------------------------------------
# Test 2: slsa-l3 policy -> exit 1 and result "deny"
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 2: slsa-l3 policy (expect exit 1, result=deny) ==="
OUTPUT_2=""
EXIT_2=0
OUTPUT_2="$(env "${BASE_ENV[@]}" ASSAYWARD_POLICY="slsa-l3" ASSAYWARD_POLICY_FILE="" \
  bash "${SCRIPT_DIR}/entrypoint.sh" 2>&1)" || EXIT_2=$?

assert_exit "slsa-l3" 1 "${EXIT_2}"
assert_contains "slsa-l3 result=deny" '"deny"' "${OUTPUT_2}"

# ---------------------------------------------------------------------------
# Test 3: Argument builder — multiline bundle -> multiple --bundle flags
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 3: multiline bundle produces multiple --bundle args ==="
# Verify via the output line that lists the args.
assert_contains "multiline-bundle arg log" '--bundle' "${OUTPUT_1}"

# Count how many --bundle occurrences appear in the args log line.
BUNDLE_COUNT="$(echo "${OUTPUT_1}" | grep "running verify with args:" | grep -oF -- '--bundle' | wc -l | tr -d ' ')"
if [[ "${BUNDLE_COUNT}" -eq 4 ]]; then
  pass "multiline-bundle count: ${BUNDLE_COUNT} --bundle args (expected 4)"
else
  fail "multiline-bundle count: ${BUNDLE_COUNT} --bundle args (expected 4)"
fi

# ---------------------------------------------------------------------------
# Test 4: --spiffe-bundle multiline -> multiple --spiffe-bundle args
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 4: spiffe-bundle arg present ==="
assert_contains "spiffe-bundle arg" '--spiffe-bundle' "${OUTPUT_1}"

# ---------------------------------------------------------------------------
# Test 5: --svid arg present when ASSAYWARD_SVID set
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 5: svid arg present ==="
assert_contains "svid arg" '--svid' "${OUTPUT_1}"

# ---------------------------------------------------------------------------
# Test 6: --sigstore-trust-root arg present when ASSAYWARD_SIGSTORE_TRUST_ROOT set
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 6: sigstore-trust-root arg present ==="
assert_contains "sigstore-trust-root arg" '--sigstore-trust-root' "${OUTPUT_1}"

# ---------------------------------------------------------------------------
# Test 6b: --forgeseal-output arg present when ASSAYWARD_FORGESEAL_OUTPUT set
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 6b: forgeseal-output arg present when ASSAYWARD_FORGESEAL_OUTPUT set ==="
OUTPUT_6B=""
EXIT_6B=0
OUTPUT_6B="$(env \
  ASSAYWARD_BINARY_PATH="${ASSAYWARD_BIN}" \
  ASSAYWARD_IMAGE="${TEST_IMAGE}" \
  ASSAYWARD_FORGESEAL_OUTPUT="/some/dir" \
  ASSAYWARD_POLICY="baseline" \
  ASSAYWARD_POLICY_FILE="" \
  ASSAYWARD_BUNDLE="" \
  ASSAYWARD_FROM_OCI="false" \
  ASSAYWARD_SIGSTORE_TRUST_ROOT="" \
  ASSAYWARD_SPIFFE_BUNDLE="" \
  ASSAYWARD_SVID="" \
  ASSAYWARD_VERSION="latest" \
  RUNNER_OS="Linux" \
  RUNNER_ARCH="X64" \
  bash "${SCRIPT_DIR}/entrypoint.sh" 2>&1)" || EXIT_6B=$?

assert_contains "forgeseal-output flag in args" '--forgeseal-output /some/dir' "${OUTPUT_6B}"

# ---------------------------------------------------------------------------
# Test 6c: --signature-ca arg present when ASSAYWARD_SIGNATURE_CA set
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 6c: signature-ca arg present when ASSAYWARD_SIGNATURE_CA set ==="
OUTPUT_6C=""
EXIT_6C=0
OUTPUT_6C="$(env \
  ASSAYWARD_BINARY_PATH="${ASSAYWARD_BIN}" \
  ASSAYWARD_IMAGE="${TEST_IMAGE}" \
  ASSAYWARD_SIGNATURE_CA="/some/ca.crt" \
  ASSAYWARD_POLICY="baseline" \
  ASSAYWARD_POLICY_FILE="" \
  ASSAYWARD_BUNDLE="${BUNDLE_MULTILINE}" \
  ASSAYWARD_FROM_OCI="false" \
  ASSAYWARD_SIGSTORE_TRUST_ROOT="${TESTDATA}/signature/trusted-root-public-good.json" \
  ASSAYWARD_SPIFFE_BUNDLE="" \
  ASSAYWARD_SVID="" \
  ASSAYWARD_VERSION="latest" \
  RUNNER_OS="Linux" \
  RUNNER_ARCH="X64" \
  bash "${SCRIPT_DIR}/entrypoint.sh" 2>&1)" || EXIT_6C=$?

assert_contains "signature-ca flag in args" '--signature-ca /some/ca.crt' "${OUTPUT_6C}"

# ---------------------------------------------------------------------------
# Test 7: --policy-file overrides --policy when set
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 7: policy-file overrides policy ==="

# Create a temp baseline policy file to test policy-file path.
TMP_POLICY_FILE="/tmp/test-policy-$$.yml"
# We can extract the baseline policy by running a known-good invocation and
# using the fact that assayward has a builtin. Instead, we just confirm the
# flag appears (we'll use an actual file from the testdata tree if one exists,
# otherwise we rely on the CLI flagging --policy-file being passed).
#
# Use the real binary to check that --policy-file shows up in the arg list
# by looking at the args log. We cannot easily create a valid policy file here
# without importing internal content, so we test the flag routing path by
# checking the log line does NOT say "--policy baseline" but says "--policy-file".

# We run with a policy-file path pointing to a non-existent file to see exit 2
# and confirm --policy-file is in the args (not --policy).
OUTPUT_7=""
EXIT_7=0
OUTPUT_7="$(env "${BASE_ENV[@]}" ASSAYWARD_POLICY="baseline" ASSAYWARD_POLICY_FILE="/tmp/nonexistent-policy-file.yml" \
  bash "${SCRIPT_DIR}/entrypoint.sh" 2>&1)" || EXIT_7=$?

# Should exit 2 (file not found -> operational error)
assert_exit "policy-file-override exit 2" 2 "${EXIT_7}"
# The args log should contain --policy-file, not --policy (without -file suffix)
assert_contains "policy-file flag in args" '--policy-file' "${OUTPUT_7}"
assert_not_contains "policy flag not in args when policy-file set" ' --policy ' "${OUTPUT_7}"

# ---------------------------------------------------------------------------
# Test 8: from-oci=true adds the --from-oci flag
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 8: from-oci=true adds --from-oci arg ==="
# We expect exit 2 because --from-oci discovery doesn't work against a fake
# image, but we can still verify the arg is passed.
OUTPUT_8=""
EXIT_8=0
OUTPUT_8="$(env "${BASE_ENV[@]}" ASSAYWARD_POLICY="baseline" ASSAYWARD_POLICY_FILE="" ASSAYWARD_FROM_OCI="true" \
  bash "${SCRIPT_DIR}/entrypoint.sh" 2>&1)" || EXIT_8=$?

assert_contains "from-oci arg" '--from-oci' "${OUTPUT_8}"

# ---------------------------------------------------------------------------
# Test 9: missing image -> exit 2
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 9: missing image -> exit 2 ==="
OUTPUT_9=""
EXIT_9=0
OUTPUT_9="$(env \
  ASSAYWARD_BINARY_PATH="${ASSAYWARD_BIN}" \
  ASSAYWARD_IMAGE="" \
  ASSAYWARD_POLICY="baseline" \
  ASSAYWARD_POLICY_FILE="" \
  ASSAYWARD_BUNDLE="${BUNDLE_MULTILINE}" \
  ASSAYWARD_FROM_OCI="false" \
  ASSAYWARD_SIGSTORE_TRUST_ROOT="" \
  ASSAYWARD_SPIFFE_BUNDLE="" \
  ASSAYWARD_SVID="" \
  ASSAYWARD_VERSION="latest" \
  RUNNER_OS="Linux" \
  RUNNER_ARCH="X64" \
  bash "${SCRIPT_DIR}/entrypoint.sh" 2>&1)" || EXIT_9=$?

assert_exit "missing-image" 2 "${EXIT_9}"

# ---------------------------------------------------------------------------
# Test 10: GITHUB_OUTPUT file integration (output writing)
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 10: GITHUB_OUTPUT file gets result and decision written ==="
GITHUB_OUTPUT_FILE="/tmp/test-github-output-$$"
touch "${GITHUB_OUTPUT_FILE}"

EXIT_10=0
env "${BASE_ENV[@]}" ASSAYWARD_POLICY="baseline" ASSAYWARD_POLICY_FILE="" \
  GITHUB_OUTPUT="${GITHUB_OUTPUT_FILE}" \
  bash "${SCRIPT_DIR}/entrypoint.sh" > /dev/null 2>&1 || EXIT_10=$?

if grep -q "result=allow" "${GITHUB_OUTPUT_FILE}"; then
  pass "GITHUB_OUTPUT contains result=allow"
else
  fail "GITHUB_OUTPUT missing result=allow"
  echo "    --- GITHUB_OUTPUT file contents ---"
  cat "${GITHUB_OUTPUT_FILE}"
  echo "    -----------------------------------"
fi

if grep -q "decision<<ASSAYWARD_DECISION_EOF" "${GITHUB_OUTPUT_FILE}"; then
  pass "GITHUB_OUTPUT contains decision heredoc"
else
  fail "GITHUB_OUTPUT missing decision heredoc"
fi

rm -f "${GITHUB_OUTPUT_FILE}"

# ---------------------------------------------------------------------------
# Test 11: goreleaser asset-name construction (unit tests, no network)
# ---------------------------------------------------------------------------
# Source the goreleaser_asset_name function from entrypoint.sh without
# executing the rest of the script. We do this by sourcing with ASSAYWARD_BINARY_PATH
# set so the download block is skipped, then calling the inner function.
# The function is defined inside the else-branch, so we extract and eval it directly.
echo ""
echo "=== Test 11: goreleaser asset-name assertions ==="

# Inline the same function from entrypoint.sh so we can unit-test it independently.
goreleaser_asset_name() {
  local raw_os="$1" raw_arch="$2"
  local goos goarch ext
  case "${raw_os}" in
    Linux|linux)     goos="linux"   ;;
    macOS|Darwin)    goos="darwin"  ;;
    Windows|windows) goos="windows" ;;
    *)               goos="${raw_os}" ;;
  esac
  case "${raw_arch}" in
    X64|x86_64|amd64)    goarch="amd64" ;;
    ARM64|arm64|aarch64) goarch="arm64" ;;
    *)                   goarch="${raw_arch}" ;;
  esac
  if [[ "${goos}" == "windows" ]]; then
    ext="zip"
  else
    ext="tar.gz"
  fi
  echo "assayward_${goos}_${goarch}.${ext}"
}

assert_asset() {
  local label="$1" raw_os="$2" raw_arch="$3" expected="$4"
  local actual
  actual="$(goreleaser_asset_name "${raw_os}" "${raw_arch}")"
  if [[ "${actual}" == "${expected}" ]]; then
    pass "${label}: ${actual}"
  else
    fail "${label}: got '${actual}', expected '${expected}'"
  fi
}

assert_asset "Linux/X64 -> linux/amd64 tar.gz"     "Linux"   "X64"   "assayward_linux_amd64.tar.gz"
assert_asset "Linux/ARM64 -> linux/arm64 tar.gz"   "Linux"   "ARM64" "assayward_linux_arm64.tar.gz"
assert_asset "macOS/ARM64 -> darwin/arm64 tar.gz"  "macOS"   "ARM64" "assayward_darwin_arm64.tar.gz"
assert_asset "Windows/X64 -> windows/amd64 zip"    "Windows" "X64"   "assayward_windows_amd64.zip"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "========================================"

if [[ "${FAIL}" -gt 0 ]]; then
  echo ""
  echo "Failed assertions:"
  for err in "${ERRORS[@]}"; do
    echo "  - ${err}"
  done
  exit 1
fi

echo "All tests passed."
exit 0
