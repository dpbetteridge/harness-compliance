#!/usr/bin/env python3
"""
Reads /etc/os-release and emits out/os_facts.json with a canonical os_key.
os_key format: "<id>-<version_id>", e.g., "debian-13"
"""
import json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUTDIR = ROOT / "out"
OUT = OUTDIR / "os_facts.json"
OS_RELEASE = pathlib.Path("/etc/os-release")

def parse_os_release():
    facts = {}
    if not OS_RELEASE.exists():
        raise SystemExit("[!] /etc/os-release not found")
    for line in OS_RELEASE.read_text().splitlines():
        if not line or "=" not in line: continue
        k, v = line.split("=", 1)
        v = v.strip().strip('"')
        facts[k.strip()] = v
    return facts

def canon_key(f):
    _id = f.get("ID","").lower().strip()
    _ver = f.get("VERSION_ID","").lower().strip()
    if not _id or not _ver:
        return None
    # keep only major for keys like debian-13.1 -> debian-13
    major = _ver.split(".")[0]
    return f"{_id}-{major}"

def main():
    facts = parse_os_release()
    key = canon_key(facts)
    OUTDIR.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"os_key": key, "os_release": facts}, indent=2))
    if "--echo-key" in sys.argv:
        print(key or "")
    else:
        print(json.dumps({"os_key": key, "os_release": facts}, indent=2))

if __name__ == "__main__":
    main()
