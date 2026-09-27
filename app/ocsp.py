"""Offline OCSP response verification for POST /v1/issuance/check-ocsp.

Parses a caller-supplied, DER-encoded OCSP response (RFC 6960) and
verifies it against the also-supplied leaf and issuer certificates, so
no network access and no certificate store are required:

* the response must be ``successful`` and carry **exactly one**
  SingleResponse;
* the single CertID must describe the supplied leaf: serial number,
  issuer name hash and issuer key hash, the last two recomputed from the
  supplied issuer certificate with the hash algorithm named in the
  CertID (SHA-1/SHA-2 family, anything else rejected);
* the responder must be the supplied issuer itself (byName equal to the
  issuer subject, or byKey equal to the SHA-1 hash of the issuer public
  key) and the signature over tbsResponseData must verify with the
  issuer key (RSA PKCS#1 v1.5 or ECDSA; other algorithms rejected);
* at the caller-supplied verification instant, producedAt and
  thisUpdate must not lie in the future and nextUpdate must be present
  and not have passed.

Malformed input — bad PEM, bad base64, unparsable DER, a non-basic
response, zero or multiple SingleResponses, unsupported CertID hash or
unsupported signature algorithm — raises an :class:`OCSPError`, a
422-grade :class:`~app.engine.CAAError`. A response that parses but
does not pertain to the leaf, is not signed by the named issuer or is
stale is a *verification failure* (``verified=False`` with a reason),
not a malformed request. The conclusion only binds the supplied
issuer; no certificate chain is built or trusted.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp

from .engine import CAAError

MAX_PEM_BYTES = 64 * 1024
MAX_OCSP_BYTES = 64 * 1024

_BASIC_OCSP_OID = "1.3.6.1.5.5.7.48.1.1"

# CertID hash algorithms accepted when recomputing issuerNameHash /
# issuerKeyHash, keyed by their cryptography hash name. MD2/MD5/SHA-3
# are absent: the backing library cannot parse their algorithm OIDs, so
# such responses surface as unsupported-algorithm 422s.
_CERTID_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}

# Signature algorithms accepted for signature-over-tbsResponseData.
# RSA is PKCS#1 v1.5 only (RSASSA-PSS is not used by OCSP responders);
# DSA, Ed25519/Ed448 and everything else is rejected.
_RSA_SIG_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "1.2.840.113549.1.1.5": hashes.SHA1,
    "1.2.840.113549.1.1.11": hashes.SHA256,
    "1.2.840.113549.1.1.12": hashes.SHA384,
    "1.2.840.113549.1.1.13": hashes.SHA512,
    "1.2.840.113549.1.1.14": hashes.SHA224,
}
_ECDSA_SIG_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "1.2.840.10045.4.1": hashes.SHA1,
    "1.2.840.10045.4.3.1": hashes.SHA224,
    "1.2.840.10045.4.3.2": hashes.SHA256,
    "1.2.840.10045.4.3.3": hashes.SHA384,
    "1.2.840.10045.4.3.4": hashes.SHA512,
}


class OCSPError(CAAError):
    """Malformed OCSP request material (PEM/DER/algorithm); maps to 422."""


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        raise OCSPError("timestamp carries no timezone (UTC offset required)")
    return dt.astimezone(timezone.utc)


def rfc3339(dt: Optional[datetime]) -> Optional[str]:
    """Render a timezone-aware datetime as RFC 3339 UTC ('...Z')."""
    if dt is None:
        return None
    dt = _utc(dt)
    text = dt.isoformat()
    if text.endswith("+00:00"):
        text = text[:-6] + "Z"
    return text


@dataclass(frozen=True)
class OCSPVerdict:
    """Outcome of verifying one OCSP response against one leaf/issuer pair."""

    verified: bool
    reason: str
    cert_status: Optional[str] = None
    produced_at: Optional[str] = None
    this_update: Optional[str] = None
    next_update: Optional[str] = None
    revocation_time: Optional[str] = None
    revocation_reason: Optional[str] = None


def _failed(reason: str) -> OCSPVerdict:
    return OCSPVerdict(verified=False, reason=reason)


def _load_certificate(pem: str, *, label: str, size: int) -> x509.Certificate:
    if len(pem.encode("utf-8")) > size:
        raise OCSPError(f"{label} exceeds {size} bytes ({size // 1024} KiB)")
    try:
        return x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except Exception as exc:  # ValueError, UnsupportedAlgorithm, ...
        raise OCSPError(f"invalid {label} PEM: {exc}") from exc


def _decode_ocsp_der(b64: str) -> bytes:
    if len(b64.encode("utf-8")) > MAX_OCSP_BYTES * 4 // 3 + 8:
        raise OCSPError(
            f"OCSP response exceeds {MAX_OCSP_BYTES // 1024} KiB after decoding"
        )
    compact = "".join(b64.split())
    try:
        der = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise OCSPError(f"invalid Base64 OCSP response: {exc}") from exc
    if not der:
        raise OCSPError("OCSP response DER is empty")
    if len(der) > MAX_OCSP_BYTES:
        raise OCSPError(
            f"OCSP response exceeds {MAX_OCSP_BYTES // 1024} KiB ({MAX_OCSP_BYTES} bytes)"
        )
    return der


def _issuer_public_key_bits(cert: x509.Certificate) -> Optional[bytes]:
    """Contents of the issuer SubjectPublicKeyInfo BIT STRING.

    Per RFC 6960 §4.2.1 CertID.issuerKeyHash (and RFC 5280 §4.2.1.9
    method 1) this is the subjectPublicKey BIT STRING *value*: the
    DER-encoded RSAPublicKey for RSA, the uncompressed point octets
    (``04 || X || Y``) for EC keys.
    """
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return pub.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1
        )
    if isinstance(pub, ec.EllipticCurvePublicKey):
        numbers = pub.public_numbers()
        size = (pub.curve.key_size + 7) // 8
        return b"\x04" + numbers.x.to_bytes(size, "big") + numbers.y.to_bytes(
            size, "big"
        )
    return None


def _digest(algorithm: hashes.HashAlgorithm, data: bytes) -> bytes:
    return hashlib.new(algorithm.name, data).digest()


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    """Parse one DER TLV at ``offset``; return (content_start, end, tag)."""
    try:
        tag = data[offset]
        first = data[offset + 1]
    except IndexError:
        raise OCSPError("truncated DER element in OCSP response") from None
    start = offset + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if not count:
            raise OCSPError("indefinite-length DER is not allowed")
        length = int.from_bytes(data[start : start + count], "big")
        start += count
    end = start + length
    if end > len(data):
        raise OCSPError("DER element runs past the end of the response")
    return start, end, tag


def _read_response_type_oid(der: bytes) -> str:
    """Extract responseBytes.responseType as a dotted OID from raw DER."""
    start, end, _ = _read_tlv(der, 0)  # OCSPResponse SEQUENCE
    # responseStatus ENUMERATED
    st_start, st_end, st_tag = _read_tlv(der, start)
    if st_tag != 0x0A:
        raise OCSPError("expected an ENUMERATED responseStatus")
    # responseBytes [0] EXPLICIT
    ex_start, ex_end, ex_tag = _read_tlv(der, st_end)
    if ex_tag != 0xA0 or ex_end > end:
        raise OCSPError("expected an explicit [0] responseBytes")
    # SEQUENCE { OID, OCTET STRING }
    rb_start, _, _ = _read_tlv(der, ex_start)
    oid_start, oid_end, oid_tag = _read_tlv(der, rb_start)
    if oid_tag != 0x06:
        raise OCSPError("expected an OBJECT IDENTIFIER responseType")
    return _decode_oid(der[oid_start:oid_end])


def _decode_oid(raw: bytes) -> str:
    if not raw:
        raise OCSPError("empty OID")
    first = raw[0]
    arcs = [str(first // 40), str(first % 40)] if first < 80 else ["2", str(first - 80)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(str(value))
            value = 0
    return ".".join(arcs)


def verify_ocsp(
    leaf_pem: str,
    issuer_pem: str,
    response_b64: str,
    verification_time: datetime,
) -> OCSPVerdict:
    """Verify a Base64 DER OCSP response for ``leaf_pem`` signed by ``issuer_pem``.

    Raises :class:`OCSPError` for malformed PEM/DER or unsupported
    algorithms (HTTP 422); returns an
    ``verified=False`` :class:`OCSPVerdict` for a parseable response
    that fails any semantic check (mismatch, bad signature, staleness).
    """
    check_at = _utc(verification_time)
    leaf = _load_certificate(leaf_pem, label="leaf certificate", size=MAX_PEM_BYTES)
    issuer = _load_certificate(
        issuer_pem, label="issuer certificate", size=MAX_PEM_BYTES
    )
    der = _decode_ocsp_der(response_b64)

    try:
        response = ocsp.load_der_ocsp_response(der)
    except Exception as exc:
        raise OCSPError(f"invalid DER OCSP response: {exc}") from exc

    if response.response_status is not ocsp.OCSPResponseStatus.SUCCESSFUL:
        return _failed(
            "OCSP response status is "
            f"{response.response_status.name.lower()}, not successful"
        )

    # ``OCSPResponse.response_type`` is not exposed by cryptography, so
    # the responseBytes OID is read straight off the DER. Layout:
    # OCSPResponse SEQUENCE { responseStatus ENUMERATED,
    #   responseBytes [0] EXPLICIT SEQUENCE { responseType OID, response OCTET STRING } }
    try:
        response_type_oid = _read_response_type_oid(der)
    except OCSPError:
        raise
    except Exception as exc:
        raise OCSPError(f"OCSP response structure cannot be parsed: {exc}") from exc
    if response_type_oid != _BASIC_OCSP_OID:
        return _failed(
            f"unsupported OCSP response type OID {response_type_oid}; only basic "
            "OCSP responses (id-pkix-ocsp-basic) are accepted"
        )

    # Exactly one SingleResponse: RFC 6960 allows several, but this API
    # only vouches for the single leaf/issuer pair in the request.
    try:
        singles = list(response.responses)
    except Exception as exc:
        raise OCSPError(f"OCSP SingleResponse cannot be decoded: {exc}") from exc
    if len(singles) != 1:
        raise OCSPError(
            f"OCSP response must contain exactly one SingleResponse, got {len(singles)}"
        )

    produced_attr = response.produced_at_utc
    this_attr = response.this_update_utc
    next_attr = response.next_update_utc
    if produced_attr is None or this_attr is None:
        raise OCSPError("OCSP response is missing producedAt/thisUpdate")
    produced_at = _utc(produced_attr)
    this_update = _utc(this_attr)
    next_update = _utc(next_attr) if next_attr is not None else None

    # --- the response must be about the supplied leaf certificate ---
    if response.serial_number != leaf.serial_number:
        return _failed(
            f"CertID serial {response.serial_number} does not match leaf certificate "
            f"serial {leaf.serial_number}"
        )
    if leaf.issuer.public_bytes() != issuer.subject.public_bytes():
        return _failed(
            "leaf certificate issuer name does not match the issuer certificate subject"
        )

    try:
        certid_alg_obj = response.hash_algorithm
    except UnsupportedAlgorithm as exc:
        raise OCSPError(f"unsupported CertID hash algorithm: {exc}") from exc
    certid_hash_cls = _CERTID_HASHES.get(certid_alg_obj.name)
    if certid_hash_cls is None:
        raise OCSPError(
            f"unsupported CertID hash algorithm {certid_alg_obj.name!r}"
        )
    certid_alg = certid_hash_cls()

    key_bits = _issuer_public_key_bits(issuer)
    if key_bits is None:
        raise OCSPError(
            "issuer certificate carries an unsupported public key type "
            "(only RSA and EC keys are accepted)"
        )
    expected_name_hash = _digest(certid_alg, issuer.subject.public_bytes())
    expected_key_hash = _digest(certid_alg, key_bits)
    if response.issuer_name_hash != expected_name_hash:
        return _failed("CertID issuerNameHash does not match the issuer certificate")
    if response.issuer_key_hash != expected_key_hash:
        return _failed("CertID issuerKeyHash does not match the issuer certificate")

    # --- the responder must be the issuer itself (no delegated responders) ---
    if response.responder_name is not None:
        if response.responder_name.public_bytes() != issuer.subject.public_bytes():
            return _failed(
                "OCSP responder byName does not equal the issuer certificate subject"
            )
    elif response.responder_key_hash is not None:
        responder_sha1 = hashlib.sha1(key_bits).digest()
        if response.responder_key_hash != responder_sha1:
            return _failed(
                "OCSP responder byKey hash does not match the issuer public key"
            )
    else:
        return _failed("OCSP response carries no responder ID")

    # --- signature over tbsResponseData with the issuer key ---
    try:
        sig_oid = response.signature_algorithm_oid
    except UnsupportedAlgorithm as exc:
        raise OCSPError(f"unsupported OCSP signature algorithm: {exc}") from exc
    issuer_pub = issuer.public_key()

    def _rsa_hash() -> hashes.HashAlgorithm:
        return _RSA_SIG_HASHES[sig_oid.dotted_string]()

    def _ecdsa_hash() -> hashes.HashAlgorithm:
        return _ECDSA_SIG_HASHES[sig_oid.dotted_string]()

    if sig_oid.dotted_string in _RSA_SIG_HASHES:
        if not isinstance(issuer_pub, rsa.RSAPublicKey):
            return _failed(
                f"OCSP signature algorithm {sig_oid.dotted_string} requires an "
                "RSA issuer key"
            )

        def _verify_signature() -> None:
            issuer_pub.verify(
                response.signature,
                response.tbs_response_bytes,
                padding.PKCS1v15(),
                _rsa_hash(),
            )
    elif sig_oid.dotted_string in _ECDSA_SIG_HASHES:
        if not isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            return _failed(
                f"OCSP signature algorithm {sig_oid.dotted_string} requires an "
                "EC issuer key"
            )

        def _verify_signature() -> None:
            issuer_pub.verify(
                response.signature,
                response.tbs_response_bytes,
                ec.ECDSA(_ecdsa_hash()),
            )
    else:
        raise OCSPError(
            "unsupported OCSP signature algorithm OID "
            f"{sig_oid.dotted_string} (only RSA PKCS#1 v1.5 and ECDSA are accepted)"
        )

    # The response DER parsed, so anything that goes wrong while checking
    # the signature itself (wrong signer, malformed ECDSA integers, ...)
    # is a signature failure rather than a malformed request.
    try:
        _verify_signature()
    except (InvalidSignature, ValueError, TypeError) as exc:
        return _failed(
            f"OCSP signature does not verify with the issuer certificate ({exc})"
        )

    # --- freshness at the caller-supplied instant ---
    if produced_at > check_at:
        return _failed(
            f"OCSP producedAt {rfc3339(produced_at)} is later than the verification "
            f"time {rfc3339(check_at)}"
        )
    if this_update > check_at:
        return _failed(
            f"OCSP thisUpdate {rfc3339(this_update)} is later than the verification "
            f"time {rfc3339(check_at)}"
        )
    if next_update is None:
        return _failed("OCSP response carries no nextUpdate; freshness cannot be proven")
    if next_update < check_at:
        return _failed(
            f"OCSP response is expired: nextUpdate {rfc3339(next_update)} is before the "
            f"verification time {rfc3339(check_at)}"
        )

    cert_status = response.certificate_status.name.lower()
    revocation_time = response.revocation_time_utc
    revocation_reason = response.revocation_reason
    return OCSPVerdict(
        verified=True,
        reason=f"OCSP response verified; certificate status is {cert_status}",
        cert_status=cert_status,
        produced_at=rfc3339(produced_at),
        this_update=rfc3339(this_update),
        next_update=rfc3339(next_update),
        revocation_time=rfc3339(revocation_time) if revocation_time else None,
        revocation_reason=(
            revocation_reason.name if revocation_reason is not None else None
        ),
    )
