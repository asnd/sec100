"""Shared TLS peer-certificate decoding helpers (stdlib-first).

With ssl.CERT_NONE, SSLSocket.getpeercert() returns {} even when a cert was
presented. binary_form=True still yields DER bytes; this module turns those
into the nested-tuple dict shape used by getpeercert().

Prefer the optional ``cryptography`` package when installed. Otherwise fall
back to CPython's private PEM decode helper (verified on CPython 3.11–3.13).
"""

from __future__ import annotations

import logging
import os
import ssl
import tempfile
from typing import Any

log = logging.getLogger(__name__)


def decode_peer_cert(cert_bin: bytes) -> dict[str, Any]:
    """Decode DER-encoded peer certificate into getpeercert()-style dict."""
    if not cert_bin:
        return {}

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_der_x509_certificate(cert_bin, default_backend())
        subject = tuple(
            ((attr.oid._name, attr.value),)  # type: ignore[attr-defined]
            for attr in cert.subject
        )
        issuer = tuple(
            ((attr.oid._name, attr.value),)  # type: ignore[attr-defined]
            for attr in cert.issuer
        )
        san: list[tuple[str, str]] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in ext.value.get_values_for_type(x509.DNSName):
                san.append(("DNS", name))
        except x509.ExtensionNotFound:
            pass
        return {
            "subject": subject,
            "issuer": issuer,
            "subjectAltName": tuple(san),
            "notBefore": cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT")
            if hasattr(cert, "not_valid_before_utc")
            else cert.not_valid_before.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT")
            if hasattr(cert, "not_valid_after_utc")
            else cert.not_valid_after.strftime("%b %d %H:%M:%S %Y GMT"),
        }
    except ImportError:
        pass
    except Exception as exc:
        log.debug("cryptography decode failed, falling back: %s", exc)

    # CPython fallback (private API; used only when cryptography is absent).
    pem = ssl.DER_cert_to_PEM_cert(cert_bin)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(pem)
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception as exc:
        log.debug("Failed to decode peer certificate DER: %s", exc)
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
