#!/usr/bin/env python3
import json, pathlib, sys, re

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "cert_evidence.json"

URL_RE = re.compile(r'^https?://')

def main():
    data = json.load(open(DATA))
    issues = []
    for osk, ce in data.items():
        for u in ce.get("niap", {}).get("pcl_entries", []):
            if not URL_RE.match(u): issues.append((osk, "niap.pcl_entries", u))
        for u in ce.get("fips", {}).get("cmvp_modules", []):
            if not URL_RE.match(u): issues.append((osk, "fips.cmvp_modules", u))
        for u in ce.get("claims", {}).get("urls", []):
            if not URL_RE.match(u): issues.append((osk, "claims.urls", u))
        for u in ce.get("provenance", {}).get("sources", []):
            if not URL_RE.match(u): issues.append((osk, "provenance.sources", u))
    if issues:
        print("[!] URL format issues found:")
        for osk, field, url in issues:
            print(f"  - {osk} :: {field} :: {url}")
        sys.exit(1)
    print("[✓] All evidence URLs look syntactically OK.")

if __name__ == "__main__":
    main()
