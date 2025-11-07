# Analyst SOP (add to your internal README)

- Identify the candidate OS key (e.g., debian-12).
- For NIAP (PCL), paste product entry URLs into niap.pcl_entries and set niap.status.
- For FIPS/CMVP, paste module certificate pages into fips.cmvp_modules and set fips.status.
- If relying on vendor-provided crypto modules, set fips.status: "module_vendor" and list the exact module certificates used.
- Record who verified and when in provenance.analyst and provenance.verified_at (ISO date).
- Add any supporting references to provenance.sources.
