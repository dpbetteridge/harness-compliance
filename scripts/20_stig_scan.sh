#!/usr/bin/env bash
set -euo pipefail

# --- Paths ---
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
OUTDIR="$ROOT/out"
FACTS="$OUTDIR/os_facts.json"

# --- Auto LIGHT if <2GB RAM (override with LIGHT=0/1) ---
if [[ -r /proc/meminfo ]]; then MEM_KB=$(awk '/MemTotal:/ {print $2}' /proc/meminfo); else MEM_KB=0; fi
DEFAULT_LIGHT=$([[ "$MEM_KB" -lt 2000000 ]] && echo 1 || echo 0)
LIGHT="${LIGHT:-$DEFAULT_LIGHT}"

# --- OS key (e.g., debian-13) ---
OS_KEY="$(jq -r '.os_key // empty' "$FACTS" 2>/dev/null || true)"
if [[ -z "$OS_KEY" ]]; then
  echo "[!] Missing or invalid $FACTS. Run scripts/00_detect_os.py first." >&2
  exit 2
fi

SCAN_DIR="$OUTDIR/stig_${OS_KEY}"
mkdir -p "$SCAN_DIR"
RESULTS="$SCAN_DIR/results.xml"
REPORT="$SCAN_DIR/report.html"
SUMMARY="$SCAN_DIR/summary.json"

# --- Datastream selection (prefer native; fall back to older Debian if needed) ---
case "$OS_KEY" in
  debian-13) CONTENT="/usr/share/xml/scap/ssg/content/ssg-debian13-ds.xml" ;;
  debian-12) CONTENT="/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml" ;;
  debian-11) CONTENT="/usr/share/xml/scap/ssg/content/ssg-debian11-ds.xml" ;;
  *)         CONTENT="" ;;
esac

if [[ -z "$CONTENT" || ! -r "$CONTENT" ]]; then
  echo "[!] No SCAP content found for $OS_KEY" >&2
  jq -n --arg os "$OS_KEY" '{error:"no_scap_content_found", os:$os, stig_alignment_score:0.0}' > "$SUMMARY"
  exit 0
fi

# --- Profile discovery & selection (ANSSI strict → standard) ---
PROFILES="$(oscap info --profiles "$CONTENT" 2>/dev/null || true)"
if [[ -z "$PROFILES" ]]; then
  echo "[!] No profiles in $CONTENT" >&2
  jq -n --arg os "$OS_KEY" --arg content "$CONTENT" '{error:"no_profiles_in_content", os:$os, content:$content, stig_alignment_score:0.0}' > "$SUMMARY"
  exit 0
fi

PROFILE_ID="$(printf "%s\n" "$PROFILES" | awk -F: '
  /anssi_bp28_high/         {print $1; exit}
  /anssi_bp28_enhanced/     {print $1; exit}
  /anssi_bp28_intermediary/ {print $1; exit}
  /anssi_bp28_minimal/      {print $1; exit}
  /standard/                {print $1; exit}
')"

if [[ -z "$PROFILE_ID" ]]; then
  PROFILE_ID="$(printf "%s\n" "$PROFILES" | head -n1 | cut -d: -f1)"
fi

echo "[*] Using content: $CONTENT"
echo "[*] Using profile: $PROFILE_ID"

# --- Eval helpers (full vs. lean) ---
run_full() {
  sudo oscap xccdf eval \
    --fetch-remote-resources \
    --oval-results \
    --profile "$PROFILE_ID" \
    --results "$RESULTS" \
    --report  "$REPORT" \
    "$CONTENT"
}

run_light() {
  # Lean: skip validation, avoid syschars, smaller results
  sudo oscap xccdf eval \
    --skip-validation \
    --thin-results \
    --without-syschar \
    --profile "$PROFILE_ID" \
    --results "$RESULTS" \
    --report  "$REPORT" \
    "$CONTENT"
}

# --- Evaluation with auto-fallback to LIGHT if needed ---
rm -f "$RESULTS" "$REPORT"
set +e
if [[ "$LIGHT" == "1" ]]; then
  echo "[*] LIGHT=1 — running lean evaluation."
  run_light
  RC=$?
else
  echo "[*] Running full evaluation…"
  run_full
  RC=$?
  if [[ "$RC" -ne 0 || ! -s "$RESULTS" ]]; then
    echo "[!] Full eval failed (rc=$RC) or results empty; retrying in LIGHT mode…"
    rm -f "$RESULTS" "$REPORT"
    run_light
    RC=$?
  fi
fi
set -e

# --- Summarize to 0–10 on evaluated rules (pass/fixed/fail/error/unknown) ---
python3 - "$RESULTS" "$PROFILE_ID" "$CONTENT" > "$SUMMARY" << 'PY'
import sys, json, os, xml.etree.ElementTree as ET
res_xml, profile, content = sys.argv[1], sys.argv[2], sys.argv[3]
out = {"profile_used": profile, "content_path": content, "run_mode": "strict"}
def done(o): print(json.dumps(o, indent=2)); sys.exit(0)

if not os.path.exists(res_xml) or os.path.getsize(res_xml)==0:
    out.update({"error":"no_results_xml","stig_alignment_score":0.0})
    done(out)

try:
    ns={'x':'http://checklists.nist.gov/xccdf/1.2'}
    tree=ET.parse(res_xml); root=tree.getroot()
    rs=[e.get('result') for e in root.findall('.//x:rule-result', ns)]
    counts={}
    for r in rs: counts[r]=counts.get(r,0)+1
    total=len(rs)
    passed=sum(counts.get(k,0) for k in ('pass','fixed'))
    eval_total=sum(counts.get(k,0) for k in ('pass','fixed','fail','error','unknown'))
    score= round((passed/max(eval_total,1))*10.0, 2) if eval_total else 0.0
    out.update({
        "result_counts": counts,
        "stig_rules_total": total,
        "stig_eval_total": eval_total,
        "stig_passed": passed,
        "stig_alignment_score": score
    })
    done(out)
except Exception as e:
    out.update({"error":"parse_failed","reason":str(e),"stig_alignment_score":0.0})
    done(out)
PY

echo "[*] Results:"
jq -r '. | {stig_alignment_score, profile_used, content_path, error} | to_entries[] | "\(.key): \(.value)"' "$SUMMARY" || true

