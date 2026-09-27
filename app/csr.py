"""PKCS#10 CSR inspection for POST /v1/issuance/check-csr.

Loads a PEM-encoded certificate signing request with the ``cryptography``
package, verifies its self-signature and extracts the DNS identifiers the
authorization engine must check:

* the CSR must be a well-formed PEM PKCS#10 of at most 64 KiB and its
  signature must verify against the embedded public key;
* the subjectAltName extension is the *only* source of identifiers — the
  subject CN is never used as a fallback; the extension must be present,
  carry 1-20 GeneralNames and every one of them must be a DNSName;
* each DNS name is normalized case-insensitively with a single trailing
  dot stripped; a wildcard is only allowed as the leftmost ``*.`` label
  and is later queried with the ``*.`` removed and ``wildcard=True``;
  any other illegal name is rejected, as are names that collide after
  normalization.

All failures raise :class:`CSRError`, a 422-grade :class:`CAAError`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

from .engine import CAAError, normalize_name

MAX_CSR_BYTES = 64 * 1024
MAX_SAN_NAMES = 20


class CSRError(CAAError):
    """CSR parse/signature/SAN failure; maps to HTTP 422."""


@dataclass(frozen=True)
class SANIdentifier:
    """One normalized SAN DNSName.

    ``name`` keeps the ``*.`` marker of a wildcard; ``domain`` is the
    name the CAA lookup is run against (``*.`` stripped).
    """

    name: str
    domain: str
    wildcard: bool


@dataclass(frozen=True)
class CSRInfo:
    """Verified CSR fingerprint plus its normalized SAN identifiers."""

    sha256: str
    names: tuple[SANIdentifier, ...]


def _normalize_san(raw: str) -> SANIdentifier:
    """Normalize one SAN DNSName and split off a leftmost wildcard.

    A wildcard is only accepted as the leftmost ``*.`` label; everything
    else goes through the engine's usual name rules, which ignore case
    and exactly one trailing dot but reject empty/root names, overlong
    labels, illegal characters and any ``*``. The wildcard prefix is
    removed *before* that single trailing-dot strip, so a second dot is
    not silently consumed (422-grade :class:`InvalidNameError`).
    """
    name = raw.strip().lower()
    wildcard = name.startswith("*.")
    domain = name[2:] if wildcard else name
    domain = normalize_name(domain, field="san")
    normalized = f"*.{domain}" if wildcard else domain
    return SANIdentifier(name=normalized, domain=domain, wildcard=wildcard)


def inspect_csr(pem: str) -> CSRInfo:
    """Verify a PEM PKCS#10 CSR and extract its SAN DNS identifiers.

    Raises :class:`CSRError` when the PEM does not parse, the signature
    does not verify against the embedded public key, the subjectAltName
    extension is missing/duplicated/undecodable, carries anything but
    DNSName entries, holds zero or more than 20 names, or two names
    normalize to the same value.
    """
    try:
        csr = x509.load_pem_x509_csr(pem.encode("utf-8"))
    except Exception as exc:
        raise CSRError(f"invalid PEM PKCS#10 CSR: {exc}") from exc

    try:
        signature_valid = csr.is_signature_valid
    except Exception as exc:  # unsupported key/signature algorithms
        raise CSRError(f"CSR signature cannot be verified: {exc}") from exc
    if not signature_valid:
        raise CSRError("CSR signature is invalid")

    try:
        extension = csr.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        raise CSRError(
            "CSR carries no subjectAltName extension; "
            "the subject CN is not used as a fallback"
        ) from None
    except x509.DuplicateExtension as exc:
        raise CSRError(
            f"CSR carries duplicate subjectAltName extensions: {exc}"
        ) from exc
    try:
        general_names = list(extension.value)
    except Exception as exc:
        raise CSRError(f"subjectAltName cannot be decoded: {exc}") from exc

    if len(general_names) > MAX_SAN_NAMES:
        raise CSRError(
            f"subjectAltName carries {len(general_names)} identifiers; "
            f"at most {MAX_SAN_NAMES} allowed"
        )

    names: list[SANIdentifier] = []
    seen: set[str] = set()
    for general in general_names:
        if not isinstance(general, x509.DNSName):
            raise CSRError(
                "subjectAltName carries a non-DNS identifier "
                f"({type(general).__name__})"
            )
        try:
            raw = general.value
        except Exception as exc:
            raise CSRError(f"SAN DNS name cannot be decoded: {exc}") from exc
        identifier = _normalize_san(raw)
        if identifier.name in seen:
            raise CSRError(
                f"duplicate DNS name {identifier.name!r} after normalization"
            )
        seen.add(identifier.name)
        names.append(identifier)

    if not names:
        raise CSRError("subjectAltName carries no DNSName entries")

    der = csr.public_bytes(serialization.Encoding.DER)
    return CSRInfo(sha256=hashlib.sha256(der).hexdigest(), names=tuple(names))
