# 3GPP Public Domain Discovery Roadmap

This roadmap records the next capabilities for the `pub.3gppnetwork.org`
research toolkit. The project’s differentiator is a historical, evidence-backed
graph of public mobile-core discovery nodes by PLMN.

## Similar tools

These tools provide useful building blocks but are not focused on MCC/MNC-aware
3GPP naming or mobile-core service semantics:

| Tool | Useful capability | Project gap it leaves |
|---|---|---|
| [dnsx](https://github.com/projectdiscovery/dnsx) | Fast multi-record DNS, resolver profiles, DoH/DoT, wildcard filtering, resumable scans | No PLMN model or telecom node classification |
| [puredns](https://github.com/d3mondev/puredns) | Resolver validation and wildcard/poisoned-answer filtering | Generic subdomain enumeration |
| [OWASP Amass](https://github.com/owasp-amass/amass) | Historical asset graph and OSINT-backed attack-surface mapping | No 3GPP service and operator model |
| [RIPE Atlas](https://atlas.ripe.net/docs/apis/rest-api-reference/measurements/) | Distributed DNS, TLS, HTTP, ping, and traceroute measurements | Measurements without a PLMN discovery data model |
| [ZMap](https://github.com/zmap/zmap) | Internet-scale research scanning | Broader and more intrusive than targeted DNS discovery |

## Priority features

1. **Node graph and relationship explorer** — **implemented**

   Model `PLMN → service → FQDN → CNAME/SRV target → IP → ASN → provider`,
   including infrastructure shared across operators. Use
   `epdg/3gpppub-graph.py` or the dashboard’s Relationship Graph tab.

2. **Resolver and geography comparison**

   Store resolver, source ASN/country, DNSSEC result, TTL, response code, and
   answer set for public, DoH/DoT, authoritative, and authorized RIPE Atlas
   vantage points.

3. **Authoritative DNS and delegation health**

   Track NS, SOA, DNSSEC delegation, CNAME chains, TTLs, lame/dead
   nameservers, and inconsistent authoritative answers.

4. **3GPP naming-template registry**

   Maintain versioned service templates with specification reference, expected
   record types, public versus GRX/IPX visibility, and node role. See 3GPP TS
   23.003, including the public N3IWF naming rules.

5. **DNS posture scorecard**

   Score DNSSEC, IPv6, TTL stability, authoritative redundancy, resolver
   consistency, stale targets, and DANE/TLSA where applicable.

6. **5G non-3GPP access discovery**

   Probe operator-identifier, 2-byte and 5GS 3-byte TAI, visited-country, and
   onboarding N3IWF names. Follow visited-country NAPTR replacements and label
   each result as public or GRX/IPX sourced. This item is implemented in
   `epdg/3gpppub-5g-discovery.py`.

7. **Change intelligence and alerts**

   Alert on first appearance, confirmed removal, ASN/provider migration,
   DNSSEC downgrade, IPv6 regression, TTL collapse, and resolver divergence.

8. **Reproducible research exports**

   Export timestamps, resolver/vantage point, raw DNS evidence, normalized node
   graph, prior changes, and machine-readable JSON bundles.

## References

- [3GPP TS 23.003](https://www.etsi.org/deliver/etsi_ts/123000_123099/123003/19.05.00_60/ts_123003v190500p.pdf)
- [RIPE Atlas measurements](https://atlas.ripe.net/docs/apis/rest-api-reference/measurements/)
- [RIPE Atlas measurement model](https://www.ripe.net/analyse/internet-measurements/ripe-atlas/how-ripe-atlas-works/)
