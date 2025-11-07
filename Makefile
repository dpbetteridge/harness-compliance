.PHONY: gather detect fips cert
gather:
	./scripts/hc gather

detect:
	./scripts/hc detect

fips:
	./scripts/hc fips

stig:
	./scripts/hc stig

cert:
	./scripts/hc cert

