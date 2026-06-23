#!/usr/bin/env bash
# entrypoint.sh — assayward verify composite-action entrypoint.
# Called by action.yml with ASSAYWARD_* env vars set from action inputs.
#
# Exit codes mirror assayward verify:
#   0 = allow or audit (non-blocking)
#   1 = deny
#   2 = usage/operational error
set -euo pipefail

# ---------------------------------------------------------------------------
# 1. Resolve the assayward binary
# ---------------------------------------------------------------------------
ASSAYWARD_BIN=""

if [[ -n "${ASSAYWARD_BINARY_PATH:-}" ]] && [[ -x "${ASSAYWARD_BINARY_PATH}" ]]; then
  ASSAYWARD_BIN="${ASSAYWARD_BINARY_PATH}"
  echo "assayward: using pre-built binary at ${ASSAYWARD_BIN}"
else
  # Download the goreleaser release asset.
  VERSION="${ASSAYWARD_VERSION:-latest}"

  # Normalise RUNNER_OS / RUNNER_ARCH (GitHub Actions) to goreleaser naming.
  # Goreleaser .Os  = lowercase GOOS  (linux / darwin / windows)
  # Goreleaser .Arch = GOARCH         (amd64 / arm64)
  # Archive format : tar.gz for linux/darwin; zip for windows (format_overrides)
  RAW_OS="${RUNNER_OS:-Linux}"
  RAW_ARCH="${RUNNER_ARCH:-X64}"

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

  ARCHIVE_NAME="$(goreleaser_asset_name "${RAW_OS}" "${RAW_ARCH}")"

  # Resolve "latest" to a concrete tag via GitHub API.
  if [[ "${VERSION}" == "latest" ]]; then
    echo "assayward: resolving latest release tag..."
    VERSION="$(curl -fsSL "https://api.github.com/repos/sns45/assayward/releases/latest" \
      | grep '"tag_name"' \
      | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
    echo "assayward: resolved version = ${VERSION}"
  fi

  # Build the goreleaser archive URL.
  # Convention: assayward_<goos>_<goarch>.<ext>
  # Examples: assayward_linux_amd64.tar.gz, assayward_darwin_arm64.tar.gz,
  #           assayward_windows_amd64.zip
  DOWNLOAD_URL="https://github.com/sns45/assayward/releases/download/${VERSION}/${ARCHIVE_NAME}"

  TMPDIR="$(mktemp -d)"
  trap 'rm -rf "${TMPDIR}"' EXIT

  echo "assayward: downloading ${DOWNLOAD_URL}"
  curl -fsSL "${DOWNLOAD_URL}" -o "${TMPDIR}/${ARCHIVE_NAME}"

  # Extract: tar.gz for linux/darwin; unzip for windows.
  if [[ "${ARCHIVE_NAME}" == *.zip ]]; then
    unzip -q "${TMPDIR}/${ARCHIVE_NAME}" -d "${TMPDIR}"
  else
    tar -xzf "${TMPDIR}/${ARCHIVE_NAME}" -C "${TMPDIR}"
  fi

  ASSAYWARD_BIN="${TMPDIR}/assayward"
  chmod +x "${ASSAYWARD_BIN}"
  echo "assayward: installed ${VERSION} at ${ASSAYWARD_BIN}"
fi

# ---------------------------------------------------------------------------
# 2. Build the argument list
# ---------------------------------------------------------------------------
VERIFY_ARGS=()

# --image (required)
if [[ -z "${ASSAYWARD_IMAGE:-}" ]]; then
  echo "::error::assayward-action: 'image' input is required" >&2
  exit 2
fi
VERIFY_ARGS+=("--image" "${ASSAYWARD_IMAGE}")

# --policy-file takes precedence over --policy
if [[ -n "${ASSAYWARD_POLICY_FILE:-}" ]]; then
  VERIFY_ARGS+=("--policy-file" "${ASSAYWARD_POLICY_FILE}")
else
  VERIFY_ARGS+=("--policy" "${ASSAYWARD_POLICY:-slsa-l3}")
fi

# --bundle (one flag per non-empty line)
if [[ -n "${ASSAYWARD_BUNDLE:-}" ]]; then
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    VERIFY_ARGS+=("--bundle" "${line}")
  done <<< "${ASSAYWARD_BUNDLE}"
fi

# --from-oci (boolean flag; only pass the image value when true)
if [[ "${ASSAYWARD_FROM_OCI:-false}" == "true" ]]; then
  VERIFY_ARGS+=("--from-oci" "${ASSAYWARD_IMAGE}")
fi

# --sigstore-trust-root
if [[ -n "${ASSAYWARD_SIGSTORE_TRUST_ROOT:-}" ]]; then
  VERIFY_ARGS+=("--sigstore-trust-root" "${ASSAYWARD_SIGSTORE_TRUST_ROOT}")
fi

# --forgeseal-output
if [[ -n "${ASSAYWARD_FORGESEAL_OUTPUT:-}" ]]; then
  VERIFY_ARGS+=("--forgeseal-output" "${ASSAYWARD_FORGESEAL_OUTPUT}")
fi

# --signature-ca
if [[ -n "${ASSAYWARD_SIGNATURE_CA:-}" ]]; then
  VERIFY_ARGS+=("--signature-ca" "${ASSAYWARD_SIGNATURE_CA}")
fi

# --spiffe-bundle (one flag per non-empty line; each line is td=path)
if [[ -n "${ASSAYWARD_SPIFFE_BUNDLE:-}" ]]; then
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    VERIFY_ARGS+=("--spiffe-bundle" "${line}")
  done <<< "${ASSAYWARD_SPIFFE_BUNDLE}"
fi

# --svid
if [[ -n "${ASSAYWARD_SVID:-}" ]]; then
  VERIFY_ARGS+=("--svid" "${ASSAYWARD_SVID}")
fi

echo "assayward: running verify with args: ${VERIFY_ARGS[*]}"

# ---------------------------------------------------------------------------
# 3. Run verify and capture output + exit code
# ---------------------------------------------------------------------------
DECISION_JSON=""
VERIFY_EXIT=0

# Single invocation: capture stdout (the decision JSON); stderr flows through to the action log.
DECISION_JSON="$("${ASSAYWARD_BIN}" verify "${VERIFY_ARGS[@]}")" || VERIFY_EXIT=$?

# ---------------------------------------------------------------------------
# 4. Parse the result field from the JSON decision
# ---------------------------------------------------------------------------
RESULT=""
if [[ -n "${DECISION_JSON}" ]]; then
  # Extract .result using basic JSON parsing (no jq dependency required).
  RESULT="$(echo "${DECISION_JSON}" | grep -o '"result" *: *"[^"]*"' | sed 's/.*: *"\([^"]*\)"/\1/' || true)"
fi

echo "assayward: decision result = ${RESULT:-<empty>}"
echo "${DECISION_JSON}"

# ---------------------------------------------------------------------------
# 5. Emit GitHub Actions outputs
# ---------------------------------------------------------------------------
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "result=${RESULT}" >> "${GITHUB_OUTPUT}"
  # Multi-line output uses the heredoc delimiter syntax.
  {
    echo "decision<<ASSAYWARD_DECISION_EOF"
    echo "${DECISION_JSON}"
    echo "ASSAYWARD_DECISION_EOF"
  } >> "${GITHUB_OUTPUT}"
fi

# ---------------------------------------------------------------------------
# 6. Annotate on deny
# ---------------------------------------------------------------------------
if [[ "${VERIFY_EXIT}" -eq 1 ]]; then
  # Extract reason codes from the JSON decision for the error annotation.
  REASONS=""
  if [[ -n "${DECISION_JSON}" ]]; then
    REASONS="$(echo "${DECISION_JSON}" | grep -o '"code" *: *"[^"]*"' | sed 's/.*: *"\([^"]*\)"/\1/' | tr '\n' ',' | sed 's/,$//' || true)"
  fi
  echo "::error::assayward verify DENIED. Reason codes: ${REASONS:-see decision JSON above}"
fi

# ---------------------------------------------------------------------------
# 7. Exit with verify's exit code (propagates deny/error to the job)
# ---------------------------------------------------------------------------
exit "${VERIFY_EXIT}"
