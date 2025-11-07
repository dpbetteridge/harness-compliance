#!/usr/bin/env python3
import json, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "cert_evidence.json"
OUTDIR = ROOT / "out"
OUT = OUTDIR / "cert_status.json"
FACTS = OUTDIR / "os_facts.json"
HOSTFIPS = OUTDIR / "host_fips.json"

def norm(x): return (x or "none").strip().lower()

def derive_score(niap_status, fips_status):
    niap = norm(niap_status); fips = norm(fips_status)
    if niap == "current" and fips == "current": return 10
    if fips == "current" and niap in ("previous","in_process"): return 8
    if fips in ("current","module_vendor") or niap == "current": return 5
    if niap == "claim_only" or fips == "claim_only": return 2
    return 0

def detected_os_key():
    if FACTS.exists():
        try:
            return json.loads(FACTS.read_text()).get("os_key")
        except Exception:
            pass
    return None

def derive_host_fips_status(hf: dict) -> str:
    """Map host_fips.json → effective fips_status used for scoring."""
    if not hf: return "none"
    c = hf.get("checks", {})
    provider_active = bool(str(c.get("openssl_fips_provider_active","false")).lower() == "true")
    conf_include   = bool(str(c.get("openssl_conf_has_fips_include","false")).lower() == "true")
    proc           = int(c.get("proc_fips_enabled", 0)) == 1
    cmdline        = int(c.get("kernel_cmdline_fips", 0)) == 1
    bad_algs       = int(c.get("disallowed_algorithms_count", 0)) > 0
    kernel_active  = proc or cmdline

    # current = FIPS provider active AND (kernel FIPS OR conf include) AND no disallowed algs
    if provider_active and (kernel_active or conf_include) and not bad_algs:
        return "current"
    # config_present = any signals present but not fully enforced
    if provider_active or conf_include or kernel_active:
        return "config_present"
    return "none"

def main():
    # OS key optional; default to detection
    os_name = sys.argv[1] if len(sys.argv) > 1 else detected_os_key()
    if not os_name:
        print("[!] No OS key. Run scripts/00_detect_os.py first or pass <os_key>.")
        sys.exit(2)

    # Load analyst evidence (if present)
    evidence_db = {}
    if DATA.exists():
        try:
            evidence_db = json.loads(DATA.read_text())
        except Exception:
            pass
    ce = evidence_db.get(os_name, {})

    niap_declared = ce.get("niap", {}).get("status", ce.get("niap_status", "none"))
    fips_declared = ce.get("fips", {}).get("status", ce.get("fips_status", "none"))

    # Load host FIPS facts from step 05
    host_fips = {}
    if HOSTFIPS.exists():
        try:
            host_fips = json.loads(HOSTFIPS.read_text())
        except Exception:
            host_fips = {}

    # Use host-observed FIPS if available; otherwise fall back to declared
    fips_observed = derive_host_fips_status(host_fips) if host_fips else "none"
    fips_used = fips_observed if fips_observed != "none" or host_fips else fips_declared

    # Note any mismatch (useful in audits/policy)
    mismatch = None
    if fips_declared and fips_declared != fips_used:
        mismatch = {"declared": fips_declared, "observed": fips_observed}

    score = derive_score(niap_declared, fips_used)

    result = {
        "os": os_name,
        "cert_status_score": score,
        "evidence": {
            "niap_status": niap_declared,
            "fips_status_used": fips_used,
            "fips_status_source": "host" if host_fips else "declared",
            "fips_declared": fips_declared or "none",
            "host_fips_snapshot": {
                "fips_compliant": host_fips.get("fips_compliant"),
                "checks": host_fips.get("checks"),
                "collected_at": host_fips.get("collected_at")
            } if host_fips else None,
            "niap_pcl_entries": ce.get("niap", {}).get("pcl_entries", ce.get("niap_ids", [])) or [],
            "cmvp_modules": ce.get("fips", {}).get("cmvp_modules", ce.get("fips_cert_ids", [])) or [],
            "provenance": ce.get("provenance", {})
        }
    }
    if mismatch:
        result["evidence"]["fips_status_mismatch"] = mismatch

    OUTDIR.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()

