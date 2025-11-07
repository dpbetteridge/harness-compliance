#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
OUTDIR="$ROOT/out"
FACTS="$OUTDIR/os_facts.json"

mkdir -p "$OUTDIR/oval"

# Read codename from os_facts
if [[ ! -r "$FACTS" ]]; then
  echo "[!] Missing $FACTS – run scripts/00_detect_os.py first." >&2
  exit 2
fi
CODENAME="$(jq -r '.os_release.VERSION_CODENAME // empty' "$FACTS" 2>/dev/null || true)"
if [[ -z "$CODENAME" ]]; then
  echo "[!] Could not determine VERSION_CODENAME from $FACTS" >&2
  exit 2
fi

BASE_URL="https://www.debian.org/security/oval"
BZ="$OUTDIR/oval/oval-definitions-${CODENAME}.xml.bz2"
XML="${BZ%.bz2}"
HTML="$OUTDIR/oval/oval-${CODENAME}.html"
RESULTS="$OUTDIR/oval/results-${CODENAME}.xml"
SUMMARY="$OUTDIR/oval/summary-${CODENAME}.json"

echo "[*] Fetching OVAL: $BASE_URL/oval-definitions-${CODENAME}.xml.bz2"
curl -fsSL "$BASE_URL/oval-definitions-${CODENAME}.xml.bz2" -o "$BZ"
bunzip2 -f "$BZ"  # produces $XML

# Evaluate OVAL
echo "[*] Running oscap oval eval…"
# --results to get machine-readable XML; --report for human HTML
oscap oval eval --results "$RESULTS" --report "$HTML" "$XML" || true

# Summarize to 0–10 (false = not vulnerable, true = vulnerable)
python3 - "$RESULTS" "$CODENAME" > "$SUMMARY" << 'PY'
import sys, json, os, xml.etree.ElementTree as ET
res, codename = sys.argv[1], sys.argv[2]
out = {"mode":"oval_only","codename":codename,"oval_results_xml":os.path.basename(res)}
if not os.path.exists(res) or os.path.getsize(res)==0:
    out.update({"error":"no_results_xml","oval_score":0.0})
    print(json.dumps(out,indent=2)); sys.exit(0)

ns = {"o":"http://oval.mitre.org/XMLSchema/oval-results-5"}
try:
    tree = ET.parse(res); root = tree.getroot()
    defs = root.findall(".//o:definition", ns)
    counts = {"true":0,"false":0,"unknown":0,"error":0}
    for d in defs:
        r = d.get("result","unknown").lower()
        counts[r] = counts.get(r,0)+1
    total = sum(counts.values())
    safe = counts.get("false",0)   # false => definition not satisfied => typically "not vulnerable"
    # 0–10 score as the proportion of "safe" among true/false (ignore unknown/error)
    denom = counts.get("true",0) + counts.get("false",0)
    score = round((safe/max(denom,1))*10.0, 2) if denom else 0.0
    out.update({
        "definition_counts": counts,
        "definitions_total": total,
        "definitions_eval": denom,
        "oval_score": score
    })
except Exception as e:
    out.update({"error":"parse_failed","reason":str(e),"oval_score":0.0})
print(json.dumps(out,indent=2))
PY

echo "[*] Wrote:"
echo "  - $SUMMARY"
echo "  - $HTML"
