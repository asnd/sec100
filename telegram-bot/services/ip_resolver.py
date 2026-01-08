"""
FQDN to IP address resolution service.

This module provides concurrent DNS resolution for 3GPP FQDNs.
Ported and adapted from the MCP server implementation.
"""

import socket
import concurrent.futures
from typing import List, Dict, Tuple
import time


def resolve_fqdn(fqdn: str, timeout: int = 5) -> List[str]:
    """
    Resolve an FQDN to a list of IP addresses.

    Args:
        fqdn: Fully qualified domain name to resolve
        timeout: DNS resolution timeout in seconds

    Returns:
        List of IP addresses (both IPv4 and IPv6), sorted and deduplicated.
        Returns empty list if resolution fails.
    """
    try:
        # Set socket timeout
        socket.setdefaulttimeout(timeout)

        # Get all info (IPv4 and IPv6)
        # AF_UNSPEC allows both, SOCK_STREAM is arbitrary as we just want IPs
        addr_info = socket.getaddrinfo(
            fqdn, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )

        # Extract and deduplicate IPs
        ips = sorted(list(set(info[4][0] for info in addr_info)))
        return ips
    except socket.timeout:
        return []
    except socket.gaierror:
        # DNS resolution failed (NXDOMAIN, etc.)
        return []
    except Exception:
        # Catch any other errors (network issues, etc.)
        return []


def resolve_multiple_fqdns(
    fqdns: List[str],
    max_workers: int = 10,
    timeout: int = 5
) -> Dict[str, List[str]]:
    """
    Resolve multiple FQDNs concurrently.

    Args:
        fqdns: List of FQDNs to resolve
        max_workers: Maximum number of concurrent resolution workers
        timeout: DNS resolution timeout per FQDN in seconds

    Returns:
        Dictionary mapping FQDN to list of IPs.
        FQDNs that failed to resolve are included with empty lists.
    """
    results = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all resolution tasks
        future_to_fqdn = {
            executor.submit(resolve_fqdn, fqdn, timeout): fqdn
            for fqdn in fqdns
        }

        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_fqdn):
            fqdn = future_to_fqdn[future]
            try:
                ips = future.result()
                results[fqdn] = ips
            except Exception:
                # If worker itself fails, return empty list
                results[fqdn] = []

    return results


def get_operator_infrastructure(
    operator_name: str,
    fqdns: List[str],
    mnc_mcc_pairs: List[Tuple[int, int]],
    max_workers: int = 10,
    timeout: int = 5
) -> Dict:
    """
    Get active infrastructure details for an operator.

    This function resolves all FQDNs for an operator and returns structured data
    about their active infrastructure.

    Args:
        operator_name: Name of the operator
        fqdns: List of FQDNs associated with this operator
        mnc_mcc_pairs: List of (MNC, MCC) tuples for this operator
        max_workers: Maximum concurrent DNS workers
        timeout: DNS timeout per FQDN

    Returns:
        Dictionary with structure:
        {
            "operator": str,
            "mnc_mcc_pairs": [(mnc, mcc), ...],
            "total_fqdns": int,
            "active_fqdns": [
                {
                    "fqdn": str,
                    "ips": [str, ...],
                    "resolved": bool
                },
                ...
            ],
            "resolution_time_ms": int
        }
    """
    start_time = time.time()

    # Resolve all FQDNs concurrently
    resolution_results = resolve_multiple_fqdns(fqdns, max_workers, timeout)

    # Build active FQDNs list (only those with IPs)
    active_fqdns = []
    for fqdn in sorted(fqdns):
        ips = resolution_results.get(fqdn, [])
        if ips:
            active_fqdns.append({
                "fqdn": fqdn,
                "ips": ips,
                "resolved": True
            })

    # Calculate resolution time
    resolution_time_ms = int((time.time() - start_time) * 1000)

    return {
        "operator": operator_name,
        "mnc_mcc_pairs": mnc_mcc_pairs,
        "total_fqdns": len(fqdns),
        "active_fqdns": active_fqdns,
        "resolution_time_ms": resolution_time_ms
    }


def get_operator_infrastructure_with_all_fqdns(
    operator_name: str,
    fqdns: List[str],
    mnc_mcc_pairs: List[Tuple[int, int]],
    max_workers: int = 10,
    timeout: int = 5
) -> Dict:
    """
    Get infrastructure details including both active and inactive FQDNs.

    Similar to get_operator_infrastructure but includes all FQDNs
    regardless of whether they resolved.

    Args:
        operator_name: Name of the operator
        fqdns: List of FQDNs associated with this operator
        mnc_mcc_pairs: List of (MNC, MCC) tuples for this operator
        max_workers: Maximum concurrent DNS workers
        timeout: DNS timeout per FQDN

    Returns:
        Dictionary with all FQDNs (resolved and unresolved)
    """
    start_time = time.time()

    # Resolve all FQDNs concurrently
    resolution_results = resolve_multiple_fqdns(fqdns, max_workers, timeout)

    # Build complete FQDNs list
    all_fqdns = []
    for fqdn in sorted(fqdns):
        ips = resolution_results.get(fqdn, [])
        all_fqdns.append({
            "fqdn": fqdn,
            "ips": ips,
            "resolved": len(ips) > 0
        })

    # Calculate resolution time
    resolution_time_ms = int((time.time() - start_time) * 1000)

    # Count active vs inactive
    active_count = sum(1 for f in all_fqdns if f["resolved"])

    return {
        "operator": operator_name,
        "mnc_mcc_pairs": mnc_mcc_pairs,
        "total_fqdns": len(fqdns),
        "active_count": active_count,
        "inactive_count": len(fqdns) - active_count,
        "all_fqdns": all_fqdns,
        "resolution_time_ms": resolution_time_ms
    }
