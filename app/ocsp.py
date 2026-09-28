"""Offline OCSP response verification for POST /v1/issuance/check-ocsp.

Implements the responder-side verification checks of RFC 6960 against a
caller-supplied, Base64-DER OCSP response, with **no network access**:

* both certificates must parse from a single PEM ``CERTIFICATE`` block;
* the response must parse from DER, report ``responseStatus=successful``
  and carry exactly one ``SingleResponse``;
* the leaf certificate's issuer DN must equal the issuer certificate's
  subject DN, and the ``CertID`` (issuer name hash, issuer key hash and
  serial number) must match the leaf after recomputing both hashes with
  the issuer certificate and the hash algorithm named in the response;
* the responder ID must name that same issuer (``byName``) or carry the
  SHA-1 key hash of its public key (``byKey``) -- delegated responders
  are never trusted;
* the signature on ``tbsResponseData`` must verify against the issuer
  public key with RSA PKCS#1 v1.5 or ECDSA;
* ``producedAt`` and ``thisUpdate`` must not be later than the supplied
  verification instant, and ``nextUpdate`` must be present and not yet
  past at that instant.

Malformed PEM/DER, unknown/unsupported hash or signature algorithms and
unsupported responder key types raise :class:`OCSPError`, a 422-grade
:class:`CAAError`. Every other failure (non-successful response, wrong
certificate/CertID, foreign responder, bad signature, stale/freshness
failure) is a well-formed response that simply does not verify and is
returned with ``verified=False`` plus a human reason. The conclusion is
strictly scoped to the supplied issuer certificate: no certificate chain
is built and no trust anchor is consulted.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ObjectIdentifier

from .engine import CAAError

MAX_CERT_PEM_BYTES = 64 * 1024
MAX_OCSP_RESPONSE_BYTES = 64 * 1024

# RFC 8017: id-RSASSA-PSS (1.2.840.113549.1.1.10); PKCS#1 v1.5 is the only
# accepted RSA signature algorithm.
_RSA_PSS_OID = ObjectIdentifier("1.2.840.113549.1.1.10")

_PEM_BLOCK_RE = re.compile(rb"-----BEGIN CERTIFICATE-----")

_STATUS_NAMES = {
    ocsp.OCSPCertStatus.GOOD: "good",
    ocsp.OCSPCertStatus.REVOKED: "revoked",
    ocsp.OCSPCertStatus.UNKNOWN: "unknown",
}


class OCSPError(CAAError):
    """Malformed PEM/DER or unsupported algorithm; maps to HTTP 422."""


@dataclass(frozen=True)
class OCSPVerdict:
    """Verification outcome plus the response fields when parsed."""

    verified: bool
    reason: str
    status: Optional[str] = None
    produced_at: Optional[datetime] = None
    this_update: Optional[datetime] = None
    next_update: Optional[datetime] = None
    revocation_time: Optional[datetime] = None


def _failed(reason: str) -> OCSPVerdict:
    return OCSPVerdict(verified=False, reason=reason)


def _load_certificate(pem: str, *, field: str, limit: int) -> x509.Certificate:
    """Decode exactly one PEM ``CERTIFICATE`` block; malformed input is 422."""
    data = pem.encode("utf-8")
    if len(data) > limit:
        raise OCSPError(f"{field} exceeds 64 KiB (65536 bytes)")
    if len(_PEM_BLOCK_RE.findall(data)) != 1:
        raise OCSPError(
            f"{field} must contain exactly one PEM CERTIFICATE block"
        )
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception as exc:
        raise OCSPError(f"invalid {field}: {exc}") from exc


def _decode_ocsp_der(b64: str) -> bytes:
    """Strictly decode the standard Base64 OCSP response; bad text is 422."""
    if len(b64.encode("utf-8")) > MAX_OCSP_RESPONSE_BYTES:
        raise OCSPError("ocsp_response exceeds 64 KiB (65536 bytes)")
    text = "".join(b64.split())
    if not text or len(text) % 4 != 0 or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text) is None:
        raise OCSPError("ocsp_response must be standard Base64 (with padding)")
    try:
        der = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise OCSPError(f"ocsp_response is not valid Base64: {exc}") from exc
    # validate=True plus the regex above is strict, but guard anyway against
    # an implementation accepting a non-round-tripping encoding.
    if base64.b64encode(der).decode("ascii") != text:
        raise OCSPError("ocsp_response is not canonical padded Base64")
    return der


def _spki_public_key_bytes(cert: x509.Certificate) -> bytes:
    """Return the DER content of the SubjectPublicKeyInfo BIT STRING.

    RFC 6960 computes the CertID issuerKeyHash (and the ``byKey``
    responder ID) over the public key octets *without* the BIT STRING
    tag/length or the leading "unused bits" byte, i.e. for RSA the
    DER RSAPublicKey and for EC the DER ECPoint.
    """
    spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        # SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
        #                                       subjectPublicKey BIT STRING }
        assert spki[0] == 0x30
        pos = _tlv_content_start(spki, 0)
        assert spki[pos] == 0x30  # AlgorithmIdentifier
        _, pos = _tlv_span(spki, pos)  # skip it entirely
        assert spki[pos] == 0x03  # subjectPublicKey BIT STRING
        content_start, end = _tlv_span(spki, pos)
        assert spki[content_start] == 0  # zero unused bits
        return spki[content_start + 1 : end]
    except (AssertionError, IndexError) as exc:
        raise OCSPError("issuer certificate has an undecodable SubjectPublicKeyInfo") from exc


def _tlv_span(data: bytes, offset: int) -> tuple[int, int]:
    """Return ``(content_start, end)`` offsets of the TLV at ``offset``."""
    first = data[offset + 1]
    if first < 0x80:
        return offset + 2, offset + 2 + first
    n = first & 0x7F
    length = int.from_bytes(data[offset + 2 : offset + 2 + n], "big")
    content_start = offset + 2 + n
    return content_start, content_start + length


def _tlv_content_start(data: bytes, offset: int) -> int:
    return _tlv_span(data, offset)[0]


def _hash(algorithm: hashes.HashAlgorithm, data: bytes) -> bytes:
    try:
        digest = hashes.Hash(algorithm)
    except UnsupportedAlgorithm as exc:
        raise OCSPError(f"unsupported hash algorithm: {exc}") from exc
    digest.update(data)
    return digest.finalize()


def _verify_signature(
    issuer: x509.Certificate, response: ocsp.OCSPResponse
) -> None:
    """Verify response signature with RSA PKCS#1 v1.5 or ECDSA.

    Bad signatures return ``False``; unsupported key types or signature
    algorithms (incl. RSA-PSS) are 422-grade :class:`OCSPError`.
    """
    public_key = issuer.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        if response.signature_algorithm_oid == _RSA_PSS_OID:
            raise OCSPError("RSASSA-PSS OCSP signatures are not supported")
    elif not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise OCSPError(
            "issuer public key type is not RSA or ECDSA; only those "
            "signatures are verified"
        )

    try:
        hash_algorithm = response.signature_hash_algorithm
    except UnsupportedAlgorithm as exc:
        raise OCSPError(f"unsupported signature algorithm: {exc}") from exc

    if isinstance(public_key, rsa.RSAPublicKey):
        try:
            public_key.verify(
                response.signature,
                response.tbs_response_bytes,
                padding.PKCS1v15(),
                hash_algorithm,
            )
        except InvalidSignature:
            return None
        except UnsupportedAlgorithm as exc:
            raise OCSPError(f"unsupported signature hash algorithm: {exc}") from exc
        return True

    try:
        public_key.verify(
            response.signature,
            response.tbs_response_bytes,
            ec.ECDSA(hash_algorithm),
        )
    except InvalidSignature:
        return None
    except UnsupportedAlgorithm as exc:
        raise OCSPError(f"unsupported signature hash algorithm: {exc}") from exc
    return True


def check_ocsp(
    leaf_pem: str, issuer_pem: str, response_b64: str, verification_time: datetime
) -> OCSPVerdict:
    """Verify one Base64 OCSP response for the leaf against its issuer.

    See the module docstring for the full rule set.
    """
    leaf = _load_certificate(
        leaf_pem, field="leaf_certificate", limit=MAX_CERT_PEM_BYTES
    )
    issuer = _load_certificate(
        issuer_pem, field="issuer_certificate", limit=MAX_CERT_PEM_BYTES
    )
    der = _decode_ocsp_der(response_b64)
    try:
        response = ocsp.load_der_ocsp_response(der)
    except Exception as exc:
        raise OCSPError(f"invalid DER OCSP response: {exc}") from exc

    # Only successful responses carry a responseBytes payload; anything
    # else (malformedRequest, internalError, tryLater, ...) is a perfectly
    # parseable envelope that simply cannot assert status.
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return _failed(
            "OCSP responseStatus is "
            f"{response.response_status.name.lower()}, not successful"
        )

    try:
        single_responses = list(response.responses)
    except Exception as exc:
        raise OCSPError(f"OCSP response carries no decodable SingleResponse: {exc}") from exc
    if len(single_responses) != 1:
        return _failed(
            f"OCSP response contains {len(single_responses)} SingleResponse "
            "entries; exactly one required"
        )
    sr = single_responses[0]

    # Leaf issuer DN must equal the supplied issuer subject DN.
    if leaf.issuer.public_bytes() != issuer.subject.public_bytes():
        return _failed(
            "leaf certificate issuer does not match the issuer certificate "
            "subject"
        )

    # CertID.serialNumber must name the leaf.
    if sr.serial_number != leaf.serial_number:
        return _failed(
            f"CertID serial number {sr.serial_number} does not match leaf "
            f"certificate serial number {leaf.serial_number}"
        )

    # Recompute both CertID hashes from the issuer with the response's
    # algorithm and compare against the carried CertID.
    try:
        algorithm = response.hash_algorithm
        expected_name_hash = _hash(algorithm, issuer.subject.public_bytes())
        expected_key_hash = _hash(
            algorithm, _spki_public_key_bytes(issuer)
        )
    except OCSPError:
        raise
    except Exception as exc:
        raise OCSPError(f"cannot compute CertID with response hash: {exc}") from exc
    if sr.issuer_name_hash != expected_name_hash:
        return _failed("CertID issuerNameHash does not match the issuer certificate")
    if sr.issuer_key_hash != expected_key_hash:
        return _failed("CertID issuerKeyHash does not match the issuer certificate")

    # The responder must be the issuer itself, either byName or byKey.
    # Delegated responders (any other name/key) are not trusted because no
    # certificate chain is evaluated.
    if response.responder_name is not None:
        if response.responder_name.public_bytes() != issuer.subject.public_bytes():
            return _failed("OCSP responder byName is not the issuer certificate")
    elif response.responder_key_hash is not None:
        expected_responder_key_hash = hashlib.sha1(
            _spki_public_key_bytes(issuer)
        ).digest()
        if response.responder_key_hash != expected_responder_key_hash:
            return _failed(
                "OCSP responder byKey is not the issuer certificate public key"
            )
    else:  # pragma: no cover - a parsed ResponderID always sets one field
        return _failed("OCSP response carries no responder ID")

    if _verify_signature(issuer, response) is None:
        return _failed("OCSP response signature does not verify with the issuer key")

    # Freshness against the caller-supplied instant (all *_utc fields are
    # timezone-aware UTC datetimes).
    check_at = verification_time.astimezone(timezone.utc)
    produced_at = response.produced_at_utc
    this_update = sr.this_update_utc
    next_update = sr.next_update_utc

    if produced_at > check_at:
        return _failed(
            f"producedAt {produced_at.isoformat()} is later than the "
            f"verification time {check_at.isoformat()}"
        )
    if this_update > check_at:
        return _failed(
            f"thisUpdate {this_update.isoformat()} is later than the "
            f"verification time {check_at.isoformat()}"
        )
    if next_update is None:
        return _failed("SingleResponse has no nextUpdate")
    if next_update < check_at:
        return _failed(
            f"nextUpdate {next_update.isoformat()} is already past at the "
            f"verification time {check_at.isoformat()}"
        )

    status = _STATUS_NAMES.get(sr.certificate_status)
    if status is None:  # pragma: no cover - only the three statuses exist
        raise OCSPError(f"unsupported certificate status {sr.certificate_status}")

    return OCSPVerdict(
        verified=True,
        reason=f"OCSP response verified: certificate status is {status}",
        status=status,
        produced_at=produced_at,
        this_update=this_update,
        next_update=next_update,
        revocation_time=sr.revocation_time_utc,
    )
