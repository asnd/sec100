# Test coverage

The repository uses the standard-library `unittest` runner so the same suite
runs locally, in Docker, and in GitHub Actions:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
docker build --tag 3gpp-explorer:test .
```

The test modules cover:

| Module | Coverage |
|---|---|
| `test_5g_discovery.py` | Operator, TAI, visited-country and onboarding N3IWF names; TAC validation; NAPTR follow-up; public/GRX source persistence |
| `test_graph.py` | Shared IP/ASN/provider relationships; NAPTR/SRV targets; 5G graph nodes; idempotent rebuilds; JSON/CSV export |
| `test_core_queries.py` | Service SQL mapping; scanner upsert semantics; timeout preservation; filtered queries; capability scoring; snapshot IP/removal diffs |
| `test_dns_features.py` | IP classification; ANSWERED/NODATA resolution; NAPTR-to-SRV filtering; idempotent NAPTR/SRV persistence |
| `test_cli_and_graph.py` | Graph CLI help, JSON and filtered CSV exports, temporary SQLite database integration |
| `test_resolver_compare.py` | Resolver response normalization, TTL/DNSSEC/source metadata, latest-per-resolver comparison |
| `test_dns_health.py` | NS/SOA/CNAME checks, nameserver reachability and persisted delegation health |

The Dockerfile runs the complete discovery suite during image construction.
GitHub Actions additionally runs Python syntax checks, the same unit suite,
CLI help smoke tests, Go tests, and the container build.
