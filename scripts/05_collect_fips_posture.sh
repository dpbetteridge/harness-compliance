#!/usr/bin/env bash
set -euo pipefail

# Resolve repo root relative to this script (works from any cwd)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
OUTDIR="$ROOT/out"
JSON="$OUTDIR/host_fips.json"

# Options:
#   --verbose : include extra context in "verbose" block
#   STRICT=1  : require kernel FIPS mode for compliance (default: 0)
VERBOSE=0
[[ "${1:-}" == "--verbose" ]] && VERBOSE=1
STRICT="${STRICT:-0}"

mkdir -p "$OUTDIR"

read_file_or() { local p="$1" fallback="$2"; [[ -r "$p" ]] && cat "$p" || echo -n "$fallback"; }
json_escape() { sed -e ':a' -e 'N;$!ba' -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\n/\\n/g'; }

# -------- Minimal indicators
PROC_FIPS="$(read_file_or /proc/sys/crypto/fips_enabled 0)"
CMDLINE_FIPS="$(grep -qo 'fips=1' /proc/cmdline && echo 1 || echo 0)"

# OpenSSL FIPS provider (OpenSSL 3.x) — we consider "status: active" as a strong signal
OPENSSL_FIPS_ACTIVE="false"
if openssl list -providers >/dev/null 2>&1; then
  if openssl list -providers 2>/dev/null | grep -qi 'name:\s*fips' \
     && openssl list -providers 2>/dev/null | grep -qi 'status:\s*active'; then
    OPENSSL_FIPS_ACTIVE="true"
  fi
fi

# openssl.cnf include of fipsmodule.cnf (boolean only)
OPENSSL_CONF_PATHS=("/etc/ssl/openssl.cnf" "/usr/lib/ssl/openssl.cnf")
OPENSSL_CONF_PATH=""
for p in "${OPENSSL_CONF_PATHS[@]}"; do
  [[ -r "$p" ]] && OPENSSL_CONF_PATH="$p" && break
done
OPENSSL_CONF_HAS_FIPS_INCLUDE="false"
if [[ -n "$OPENSSL_CONF_PATH" ]]; then
  if grep -iE '^\s*\.include\s+.*fipsmodule\.cnf' "$OPENSSL_CONF_PATH" 2>/dev/null \
     | grep -vq '^\s*#'; then
    OPENSSL_CONF_HAS_FIPS_INCLUDE="true"
  fi
fi

# -------- Algorithm audit (disallowed set)
BAD_ALGS=(md5 rc2 rc4 des 3des blowfish chacha20 poly1305 idea seed cast camellia)
FOUND=()

# Kernel crypto registry
if [[ -r /proc/crypto ]]; then
  for a in "${BAD_ALGS[@]}"; do
    if grep -qi "\b${a}\b" /proc/crypto; then
      FOUND+=("${a}:kernel")
    fi
  done
fi

# OpenSSL listings (names normalized to lowercase)
if command -v openssl >/dev/null 2>&1; then
  # ciphers
  if openssl list -cipher-algorithms >/dev/null 2>&1; then
    ALLC=$(openssl list -cipher-algorithms 2>/dev/null | awk '{print tolower($1)}')
    for a in "${BAD_ALGS[@]}"; do
      if echo "$ALLC" | grep -qx "$a"; then FOUND+=("${a}:openssl-cipher"); fi
    done
  fi
  # digests
  if openssl list -digest-algorithms >/dev/null 2>&1; then
    ALLD=$(openssl list -digest-algorithms 2>/dev/null | awk '{print tolower($1)}')
    if echo "$ALLD" | grep -qx "md5"; then FOUND+=("md5:openssl-digest"); fi
  fi
  # MACs (catch poly1305 if exposed as a MAC)
  if openssl list -mac-algorithms >/dev/null 2>&1; then
    ALLM=$(openssl list -mac-algorithms 2>/dev/null | awk '{print tolower($1)}')
    if echo "$ALLM" | grep -qx "poly1305"; then FOUND+=("poly1305:openssl-mac"); fi
  fi
fi

DISALLOWED_COUNT="${#FOUND[@]}"

# -------- Compliance decision
# Default rule (STRICT=0): compliant if
#   - OpenSSL FIPS provider active, AND
#   - (kernel FIPS enabled OR fips include present), AND
#   - no disallowed algorithms found
# Strict rule (STRICT=1): compliant if
#   - kernel FIPS enabled (proc or cmdline),
#   - OpenSSL FIPS provider active,
#   - fips include present,
#   - no disallowed algorithms found
KERNEL_FIPS_ACTIVE=$(( PROC_FIPS == 1 || CMDLINE_FIPS == 1 ? 1 : 0 ))

if [[ "$STRICT" == "1" ]]; then
  COMPLIANT=$(
    [[ "$KERNEL_FIPS_ACTIVE" -eq 1 ]] \
    && [[ "$OPENSSL_FIPS_ACTIVE" == "true" ]] \
    && [[ "$OPENSSL_CONF_HAS_FIPS_INCLUDE" == "true" ]] \
    && [[ "$DISALLOWED_COUNT" -eq 0 ]] && echo "true" || echo "false"
  )
  REASON="strict"
else
  COMPLIANT=$(
    [[ "$OPENSSL_FIPS_ACTIVE" == "true" ]] \
    && { [[ "$KERNEL_FIPS_ACTIVE" -eq 1 ]] || [[ "$OPENSSL_CONF_HAS_FIPS_INCLUDE" == "true" ]]; } \
    && [[ "$DISALLOWED_COUNT" -eq 0 ]] && echo "true" || echo "false"
  )
  REASON="default"
fi

PRETTY_NAME="$(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || true)"

# -------- Output JSON (minimal, single file)
{
  echo "{"
  echo "  \"fips_compliant\": $COMPLIANT,"
  echo "  \"decision_reason\": \"${REASON}\","
  echo "  \"checks\": {"
  echo "    \"proc_fips_enabled\": $PROC_FIPS,"
  echo "    \"kernel_cmdline_fips\": $CMDLINE_FIPS,"
  echo "    \"openssl_fips_provider_active\": ${OPENSSL_FIPS_ACTIVE},"
  echo "    \"openssl_conf_has_fips_include\": ${OPENSSL_CONF_HAS_FIPS_INCLUDE},"
  echo "    \"disallowed_algorithms_count\": ${DISALLOWED_COUNT}"
  echo "  },"
  echo "  \"disallowed_algorithms_detected\": ["
  if (( DISALLOWED_COUNT > 0 )); then
    for i in "${!FOUND[@]}"; do
      printf '    "%s"%s\n' "${FOUND[$i]}" $([[ $i -lt $((DISALLOWED_COUNT-1)) ]] && echo "," || true)
    done
  fi
  echo "  ],"
  echo "  \"evidence\": {"
  echo "    \"os_pretty\": \"${PRETTY_NAME}\","
  echo "    \"openssl_conf_path\": \"${OPENSSL_CONF_PATH}\""
  echo "  },"
  echo "  \"collected_at\": \"$(date -Iseconds)\""

  if [[ "$VERBOSE" -eq 1 ]]; then
    OPENSSL_VERSION="$(openssl version 2>/dev/null | json_escape || true)"
    echo "  ,\"verbose\": {"
    echo "    \"openssl_version\": \"${OPENSSL_VERSION}\""
    echo "  }"
  fi
  echo "}"
} > "$JSON"

echo "[*] Wrote: $JSON"

