"""End-to-end tests for POST /v1/issuance/check-ocsp."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

UTC = dt.timezone.utc
# producedAt is stamped at signing wall-clock time, so the verification
# instant must lie after the test run while still within the validity window.
THIS = dt.datetime(2026, 9, 20, tzinfo=UTC)
NEXT = dt.datetime(2030, 10, 20, tzinfo=UTC)
REVTIME = dt.datetime(2026, 9, 10, tzinfo=UTC)
CHECK_AT = "2028-01-01T00:00:00Z"


# ---------- fixtures ----------

def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(cn="Test CA", *, key=None, key_type="ec", serial=1):
    if key is None:
        key = (
            ec.generate_private_key(ec.SECP256R1())
            if key_type == "ec"
            else rsa.generate_private_key(65537, 2048)
        )
    subject = _name(cn)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(THIS - dt.timedelta(days=10))
        .not_valid_after(THIS + dt.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(issuer_key, issuer_name, *, serial=0x1234, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("leaf.test"))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(THIS)
        .not_valid_after(THIS + dt.timedelta(days=90))
        .sign(issuer_key, hashes.SHA256())
    )
    return key, cert


def build_ocsp(
    leaf,
    issuer_cert,
    issuer_key,
    *,
    status=ocsp.OCSPCertStatus.GOOD,
    certid_hash=hashes.SHA1(),
    sig_hash=hashes.SHA256(),
    this_update=THIS,
    next_update=NEXT,
    encoding=ocsp.OCSPResponderEncoding.HASH,
    responder_cert=None,
):
    revoked = status is ocsp.OCSPCertStatus.REVOKED
    builder = ocsp.OCSPResponseBuilder().add_response(
        leaf,
        issuer_cert,
        certid_hash,
        status,
        this_update,
        next_update,
        REVTIME if revoked else None,
        x509.ReasonFlags.key_compromise if revoked else None,
    )
    builder = builder.responder_id(encoding, responder_cert or issuer_cert)
    return builder.sign(issuer_key, sig_hash).public_bytes(serialization.Encoding.DER)


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def b64(der):
    return base64.b64encode(der).decode()


def request_body(leaf, issuer, der, *, verification_time=CHECK_AT):
    return {
        "leaf_certificate": pem(leaf),
        "issuer_certificate": pem(issuer),
        "ocsp_response": b64(der),
        "verification_time": verification_time,
    }


def check(body):
    return client.post("/v1/issuance/check-ocsp", json=body)


@pytest.fixture
def ec_pair():
    ca_key, ca_cert = make_ca("EC CA")
    _, leaf = make_leaf(ca_key, ca_cert.subject)
    return ca_key, ca_cert, leaf


@pytest.fixture
def rsa_pair():
    ca_key, ca_cert = make_ca("RSA CA", key_type="rsa")
    _, leaf = make_leaf(ca_key, ca_cert.subject, key=rsa.generate_private_key(65537, 2048))
    return ca_key, ca_cert, leaf


# ---------- DER surgery helpers (self-contained TLV editing) ----------
#
# The cryptography OCSP builder only emits one SingleResponse and a
# SHA-2 signature, and refuses MD5 CertIDs. A handful of tests therefore
# edit the response DER directly; this tiny TLV walker is all that is
# needed for the fixed shapes cryptography produces.


def _tlv(data, offset):
    """Parse one DER TLV at offset; return (content_start, end, tag)."""
    tag = data[offset]
    first = data[offset + 1]
    start = offset + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        length = int.from_bytes(data[start : start + count], "big")
        start += count
    end = start + length
    assert end <= len(data)
    return start, end, tag


def _der_tlv(tag, content):
    """Wrap content in a DER TLV with the given universal/context tag."""
    length = len(content)
    if length < 0x80:
        prefix = bytes([tag, length])
    else:
        encoded = b""
        while length:
            encoded = bytes([length & 0xFF]) + encoded
            length >>= 8
        prefix = bytes([tag, 0x80 | len(encoded)]) + encoded
    return prefix + content


# OIDs the surgery helpers inject (dotted string -> content bytes).
_OID_BYTES = {
    "md5": bytes.fromhex("2a864886f70d0205"),
    "sha3-256": bytes.fromhex("608648016503040208"),
    "ed25519": bytes.fromhex("2b6570"),
    "sha1_ecdsa": bytes.fromhex("2a8648ce3d0401"),
    "sha1_rsa": bytes.fromhex("2a864886f70d010105"),
    "sha256_ecdsa": bytes.fromhex("2a8648ce3d040302"),
    "sha256_rsa": bytes.fromhex("2a864886f70d01010b"),
}


def _algid(oid_name):
    """Build an AlgorithmIdentifier; RSA-style OIDs carry NULL params, EC/Ed do not."""
    params = b"\x05\x00" if oid_name.endswith("_rsa") else b""
    return _der_tlv(0x30, _der_tlv(0x06, _OID_BYTES[oid_name]) + params)


def _parse_ocsp(der):
    """Split a basic OCSPResponse DER into the slices the tests edit."""
    vs, end, _ = _tlv(der, 0)  # OCSPResponse
    outer = der[vs:end]
    vs, status_end, _ = _tlv(outer, 0)  # responseStatus ENUMERATED
    vs, ex_end, _ = _tlv(outer, status_end)  # responseBytes [0] EXPLICIT
    explicit = outer[vs:ex_end]
    vs, rb_end, _ = _tlv(explicit, 0)  # ResponseBytes SEQUENCE
    rb = explicit[vs:rb_end]
    ovs, oid_end, _ = _tlv(rb, 0)  # responseType OID
    qvs, oct_end, _ = _tlv(rb, oid_end)  # response OCTET STRING
    basic = rb[qvs:oct_end]
    bvs, b_end, _ = _tlv(basic, 0)  # BasicOCSPResponse SEQUENCE
    basic_content = basic[bvs:b_end]
    dvs, d_end, _ = _tlv(basic_content, 0)  # ResponseData
    rd_content = basic_content[dvs:d_end]
    return SimpleNamespace(
        der=der,
        outer=outer,
        status_end=status_end,
        rb=rb,
        oid_end=oid_end,
        basic_content=basic_content,
        rd_content=rd_content,
        rd_end=d_end,
    )


def _tbs_entries(rd_content):
    """Return (entry tuples, tbs content) in ResponseData order."""
    entries = []
    pos = 0
    while pos < len(rd_content):
        vs, end, tag = _tlv(rd_content, pos)
        entries.append((pos, vs, end, tag))
        pos = end
    return entries


def _rebuild(ctx, new_rd_content, new_alg_tlv=None, new_signature=None):
    rest = ctx.basic_content[ctx.rd_end:]
    if new_alg_tlv is not None:
        # rest = AlgorithmIdentifier TLV + signature BIT STRING TLV (+ certs)
        _, alg_end, _ = _tlv(rest, 0)
        _, sig_end, _ = _tlv(rest, alg_end)
        after_signature = rest[sig_end:]
        rest = (
            new_alg_tlv
            + _der_tlv(0x03, b"\x00" + new_signature)
            + after_signature
        )
    new_basic = _der_tlv(
        0x30, _der_tlv(0x30, new_rd_content) + rest
    )
    new_rb = ctx.rb[: ctx.oid_end] + _der_tlv(0x04, new_basic)
    new_explicit = _der_tlv(0xA0, _der_tlv(0x30, new_rb))
    return _der_tlv(0x30, ctx.outer[: ctx.status_end] + new_explicit)


def _single_certid_slices(rd_content):
    """Locate CertID internals for the single SingleResponse.

    Returns TLV boundaries (start/end include the tag+length header).
    """
    entries = _tbs_entries(rd_content)
    # responderID, producedAt, responses SEQUENCE[, [1] extensions]
    rs_pos, _, rs_end, _ = entries[2]
    rs_content, _, _ = _tlv(rd_content, rs_pos)
    sr_pos = rs_content
    sr_start, sr_end, _ = _tlv(rd_content, sr_pos)
    cid_content, cid_end, _ = _tlv(rd_content, sr_start)
    alg_content, alg_end, _ = _tlv(rd_content, cid_content)
    nh_pos = alg_end
    nh_content, nh_end, _ = _tlv(rd_content, nh_pos)
    kh_pos = nh_end
    kh_content, kh_end, _ = _tlv(rd_content, kh_pos)
    ser_pos = kh_end
    ser_content, ser_end, _ = _tlv(rd_content, ser_pos)
    return SimpleNamespace(
        rs_pos=rs_pos,
        rs_end=rs_end,
        sr_pos=sr_pos,
        sr_end=sr_end,
        cid_pos=sr_start,
        cid_end=cid_end,
        nh_pos=nh_pos,
        nh_end=nh_end,
        serial_tlv=rd_content[ser_pos:ser_end],
    )


def _ec_key_bits(cert):
    nums = cert.public_key().public_numbers()
    size = (cert.public_key().curve.key_size + 7) // 8
    return b"\x04" + nums.x.to_bytes(size, "big") + nums.y.to_bytes(size, "big")


def _key_bits(cert):
    if isinstance(cert.public_key(), rsa.RSAPublicKey):
        return cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1
        )
    return _ec_key_bits(cert)


def _sign(signer_key, key_kind, hash_algorithm, tbs_der):
    if key_kind == "rsa":
        return signer_key.sign(tbs_der, padding.PKCS1v15(), hash_algorithm)
    return signer_key.sign(tbs_der, ec.ECDSA(hash_algorithm))


def resign(der, signer_key, key_kind, sig_oid_name, *, hash_algorithm=None):
    """Re-sign tbsResponseData with a different signature AlgorithmIdentifier."""
    hash_algorithm = hash_algorithm or hashes.SHA1()
    ctx = _parse_ocsp(der)
    alg_tlv = _algid(sig_oid_name)
    signature = _sign(signer_key, key_kind, hash_algorithm, _der_tlv(0x30, ctx.rd_content))
    return _rebuild(ctx, ctx.rd_content, alg_tlv, signature)


def recertid(der, issuer_cert, signer_key, key_kind, hash_name):
    """Replace CertID hashAlgorithm/hashes and re-sign (SHA-256 sig kept)."""
    ctx = _parse_ocsp(der)
    slices = _single_certid_slices(ctx.rd_content)
    digest = lambda data: hashlib.new(hash_name, data).digest()
    new_certid = _der_tlv(
        0x30,
        _der_tlv(0x30, _der_tlv(0x06, _OID_BYTES[hash_name]) + b"\x05\x00")
        + _der_tlv(0x04, digest(issuer_cert.subject.public_bytes()))
        + _der_tlv(0x04, digest(_key_bits(issuer_cert)))
        + slices.serial_tlv,
    )
    new_single = _der_tlv(
        0x30, new_certid + ctx.rd_content[slices.cid_end:slices.sr_end]
    )
    new_rd = (
        ctx.rd_content[: slices.rs_pos] + _der_tlv(0x30, new_single)
        + ctx.rd_content[slices.rs_end:]
    )
    tbs_der = _der_tlv(0x30, new_rd)
    signature = _sign(signer_key, key_kind, hashes.SHA256(), tbs_der)
    sig_alg = "sha256_rsa" if key_kind == "rsa" else "sha256_ecdsa"
    return _rebuild(ctx, new_rd, _algid(sig_alg), signature)


def set_produced_at(der, signer_key, key_kind, produced):
    ctx = _parse_ocsp(der)
    entries = _tbs_entries(ctx.rd_content)
    gt_pos, _, gt_end, _ = entries[1]  # producedAt GeneralizedTime
    encoded = produced.astimezone(UTC).strftime("%Y%m%d%H%M%SZ").encode("ascii")
    new_rd = (
        ctx.rd_content[:gt_pos]
        + _der_tlv(0x18, encoded)
        + ctx.rd_content[gt_end:]
    )
    tbs_der = _der_tlv(0x30, new_rd)
    signature = _sign(signer_key, key_kind, hashes.SHA256(), tbs_der)
    sig_alg = "sha256_rsa" if key_kind == "rsa" else "sha256_ecdsa"
    return _rebuild(ctx, new_rd, _algid(sig_alg), signature)


def set_signature_algorithm_oid(der, oid_name):
    """Swap the signature AlgorithmIdentifier only (signature stays stale).

    The injected OID (Ed25519) canonically carries no parameters.
    """
    ctx = _parse_ocsp(der)
    rest = ctx.basic_content[ctx.rd_end:]
    _, alg_end, _ = _tlv(rest, 0)
    new_alg = _der_tlv(0x30, _der_tlv(0x06, _OID_BYTES[oid_name]))
    new_rest = new_alg + rest[alg_end:]
    new_basic = _der_tlv(0x30, _der_tlv(0x30, ctx.rd_content) + new_rest)
    new_rb = ctx.rb[: ctx.oid_end] + _der_tlv(0x04, new_basic)
    new_explicit = _der_tlv(0xA0, _der_tlv(0x30, new_rb))
    return _der_tlv(0x30, ctx.outer[: ctx.status_end] + new_explicit)


def corrupt_issuer_name_hash(der):
    """Flip one issuerNameHash byte (re-encodes, but is not re-signed)."""
    ctx = _parse_ocsp(der)
    slices = _single_certid_slices(ctx.rd_content)
    # nh_pos/nh_end bracket the complete OCTET STRING TLV.
    nh_tlv = ctx.rd_content[slices.nh_pos:slices.nh_end]
    nh_content, _, _ = _tlv(nh_tlv, 0)
    flipped = bytearray(nh_tlv)
    flipped[nh_content] ^= 0x01
    new_rd = (
        ctx.rd_content[: slices.nh_pos] + bytes(flipped)
        + ctx.rd_content[slices.nh_end:]
    )
    return _rebuild(ctx, new_rd)


def duplicate_single_responses(der):
    ctx = _parse_ocsp(der)
    slices = _single_certid_slices(ctx.rd_content)
    single = ctx.rd_content[slices.sr_pos:slices.sr_end]
    new_responses = _der_tlv(0x30, single + single)
    new_rd = (
        ctx.rd_content[: slices.rs_pos] + new_responses
        + ctx.rd_content[slices.rs_end:]
    )
    return _rebuild(ctx, new_rd)


def empty_single_responses(der):
    ctx = _parse_ocsp(der)
    slices = _single_certid_slices(ctx.rd_content)
    new_rd = (
        ctx.rd_content[: slices.rs_pos] + _der_tlv(0x30, b"")
        + ctx.rd_content[slices.rs_end:]
    )
    return _rebuild(ctx, new_rd)


def set_responder_name(der, issuer_key, name_der):
    """Replace responderID [1] Name and re-sign with the EC issuer key."""
    ctx = _parse_ocsp(der)
    entries = _tbs_entries(ctx.rd_content)
    rid_pos, _, rid_end, _ = entries[0]
    new_rd = (
        ctx.rd_content[:rid_pos] + _der_tlv(0xA1, name_der)
        + ctx.rd_content[rid_end:]
    )
    tbs_der = _der_tlv(0x30, new_rd)
    return _rebuild(ctx, new_rd, _algid("sha256_ecdsa"),
                    issuer_key.sign(tbs_der, ec.ECDSA(hashes.SHA256())))


# ---------- happy paths ----------

def test_ec_good_response(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key)
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is True
    assert data["cert_status"] == "good"
    assert data["this_update"] == "2026-09-20T00:00:00Z"
    assert data["next_update"] == "2030-10-20T00:00:00Z"
    assert data["produced_at"].endswith("Z")
    assert data["revocation_time"] is None
    assert data["revocation_reason"] is None


def test_rsa_good_response(rsa_pair):
    ca_key, ca_cert, leaf = rsa_pair
    der = build_ocsp(
        leaf, ca_cert, ca_key, certid_hash=hashes.SHA256(), sig_hash=hashes.SHA256()
    )
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    assert r.json()["verified"] is True
    assert r.json()["cert_status"] == "good"


@pytest.mark.parametrize(
    "sig_hash",
    [hashes.SHA224(), hashes.SHA256(), hashes.SHA384(), hashes.SHA512()],
)
def test_ecdsa_signature_hashes(ec_pair, sig_hash):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key, sig_hash=sig_hash)
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    assert r.json()["verified"] is True


@pytest.mark.parametrize(
    "sig_hash",
    [hashes.SHA224(), hashes.SHA256(), hashes.SHA384(), hashes.SHA512()],
)
def test_rsa_signature_hashes(rsa_pair, sig_hash):
    ca_key, ca_cert, leaf = rsa_pair
    der = build_ocsp(leaf, ca_cert, ca_key, sig_hash=sig_hash)
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    assert r.json()["verified"] is True


def test_sha1_rsa_signature_still_verified(rsa_pair):
    # The local OpenSSL refuses to *create* SHA-1 signatures, but real
    # OCSP responders still emit them; the verifier must accept them.
    ca_key, ca_cert, leaf = rsa_pair
    der = build_ocsp(leaf, ca_cert, ca_key, sig_hash=hashes.SHA256())
    der = resign(der, ca_key, "rsa", "sha1_rsa")
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    assert r.json()["verified"] is True


def test_sha1_ecdsa_signature_still_verified(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key, sig_hash=hashes.SHA256())
    der = resign(der, ca_key, "ec", "sha1_ecdsa")
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    assert r.json()["verified"] is True


@pytest.mark.parametrize(
    "certid_hash",
    [
        hashes.SHA1(),
        hashes.SHA224(),
        hashes.SHA256(),
        hashes.SHA384(),
        hashes.SHA512(),
    ],
)
def test_certid_hash_algorithms(ec_pair, certid_hash):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key, certid_hash=certid_hash)
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    assert r.json()["verified"] is True


def test_responder_by_name(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key, encoding=ocsp.OCSPResponderEncoding.NAME)
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    assert r.json()["verified"] is True


def test_revoked_status_with_time_and_reason(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key, status=ocsp.OCSPCertStatus.REVOKED)
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is True
    assert data["cert_status"] == "revoked"
    assert data["revocation_time"] == "2026-09-10T00:00:00Z"
    assert data["revocation_reason"] == "key_compromise"


def test_unknown_cert_status(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key, status=ocsp.OCSPCertStatus.UNKNOWN)
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is True
    assert data["cert_status"] == "unknown"


def test_boundary_check_at_next_update_is_not_expired(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    boundary = dt.datetime(2028, 6, 1, tzinfo=UTC)
    der = build_ocsp(leaf, ca_cert, ca_key, next_update=boundary)
    r = check(request_body(leaf, ca_cert, der, verification_time="2028-06-01T00:00:00Z"))
    assert r.status_code == 200
    assert r.json()["verified"] is True


def test_verification_time_with_explicit_offset(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key)
    r = check(request_body(leaf, ca_cert, der, verification_time="2028-01-01T02:00:00+02:00"))
    assert r.status_code == 200
    assert r.json()["verified"] is True


def test_base64_with_newlines_and_whitespace(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key)
    raw = base64.encodebytes(der).decode()  # line-wrapped standard base64
    body = request_body(leaf, ca_cert, b"")
    body["ocsp_response"] = raw
    r = check(body)
    assert r.status_code == 200
    assert r.json()["verified"] is True


def test_ec_curve_p384():
    ca_key, ca_cert = make_ca("P384 CA", key=ec.generate_private_key(ec.SECP384R1()))
    _, leaf = make_leaf(ca_key, ca_cert.subject)
    der = build_ocsp(leaf, ca_cert, ca_key, sig_hash=hashes.SHA384())
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    assert r.json()["verified"] is True


# ---------- semantic verification failures (200, verified=false) ----------

def test_serial_number_mismatch(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    _, other_leaf = make_leaf(ca_key, ca_cert.subject, serial=9999)
    der = build_ocsp(other_leaf, ca_cert, ca_key)
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert data["cert_status"] is None
    assert "serial" in data["reason"]


def test_leaf_issued_by_different_ca(rsa_pair):
    ca_key, ca_cert, leaf = rsa_pair
    _, other_ca = make_ca("Other CA", key_type="rsa", serial=2)
    der = build_ocsp(leaf, ca_cert, ca_key)
    r = check(request_body(leaf, other_ca, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "issuer name" in data["reason"]


def test_issuer_name_hash_mismatch(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    other_key, other_ca = make_ca("Other CA", serial=2)
    _, leaf2 = make_leaf(other_key, other_ca.subject, serial=leaf.serial_number)
    der = build_ocsp(leaf2, other_ca, other_key)
    r = check(request_body(leaf, other_ca, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "issuer name" in data["reason"]


def test_certid_key_hash_recomputed_from_supplied_issuer(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    # Same issuer name but a different key: CertID was computed with the
    # first key, the supplied issuer carries a fresh key under the same subject.
    same_subject = ca_cert.subject
    new_key = ec.generate_private_key(ec.SECP256R1())
    new_cert = (
        x509.CertificateBuilder()
        .subject_name(same_subject)
        .issuer_name(same_subject)
        .public_key(new_key.public_key())
        .serial_number(1)
        .not_valid_before(THIS - dt.timedelta(days=10))
        .not_valid_after(THIS + dt.timedelta(days=3650))
        .sign(new_key, hashes.SHA256())
    )
    der = build_ocsp(leaf, ca_cert, ca_key)
    r = check(request_body(leaf, new_cert, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "issuerKeyHash" in data["reason"]


def test_certid_name_hash_tamper_fails(ec_pair):
    # Corrupt only issuerNameHash (still parseable, wrong digest):
    # recomputation against the supplied issuer must disagree.
    ca_key, ca_cert, leaf = ec_pair
    der = corrupt_issuer_name_hash(build_ocsp(leaf, ca_cert, ca_key))
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "issuerNameHash" in data["reason"]


def test_responder_key_hash_not_issuer(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    other_key, other_cert = make_ca("Other CA", serial=2)
    # Response describes the leaf under ca_cert but claims the other CA
    # as responder (signed by the other CA key); CertID still names ca_cert.
    der = build_ocsp(leaf, ca_cert, other_key, responder_cert=other_cert)
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "responder" in data["reason"]


def test_responder_name_not_issuer(ec_pair):
    # Valid signature by the issuer key, but the responder byName claims
    # another CA (crafted via DER edit; the cryptography builder itself
    # refuses this combination).
    ca_key, ca_cert, leaf = ec_pair
    _, other_cert = make_ca("Other CA", serial=2)
    der = build_ocsp(leaf, ca_cert, ca_key, encoding=ocsp.OCSPResponderEncoding.NAME)
    der = set_responder_name(der, ca_key, other_cert.subject.public_bytes())
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "responder byName" in data["reason"]


def test_bad_signature_is_not_trusted(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = bytearray(build_ocsp(leaf, ca_cert, ca_key))
    der[-4] ^= 0x01
    r = check(request_body(leaf, ca_cert, bytes(der)))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "signature" in data["reason"]


def test_malformed_signature_blob_is_not_422(ec_pair):
    # A parseable response whose signature BIT STRING is not a valid
    # ECDSA signature fails verification (verified=false); it is not a
    # malformed request, so it must not become a 422.
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key)
    ctx = _parse_ocsp(der)
    rest = ctx.basic_content[ctx.rd_end:]
    _, alg_end, _ = _tlv(rest, 0)
    new_bit = _der_tlv(0x03, b"\x00\x03\x03\x03")
    new_rest = rest[:alg_end] + new_bit
    new_basic = _der_tlv(
        0x30, _der_tlv(0x30, ctx.rd_content) + new_rest
    )
    new_rb = ctx.rb[: ctx.oid_end] + _der_tlv(0x04, new_basic)
    new_explicit = _der_tlv(0xA0, _der_tlv(0x30, new_rb))
    broken = _der_tlv(0x30, ctx.outer[: ctx.status_end] + new_explicit)
    r = check(request_body(leaf, ca_cert, broken))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "signature" in data["reason"]


def test_expired_next_update(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(
        leaf, ca_cert, ca_key, next_update=dt.datetime(2026, 9, 24, tzinfo=UTC)
    )
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "expired" in data["reason"]


def test_missing_next_update(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key, next_update=None)
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "nextUpdate" in data["reason"]


def test_this_update_in_future(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(
        leaf, ca_cert, ca_key, this_update=dt.datetime(2029, 1, 1, tzinfo=UTC)
    )
    r = check(request_body(leaf, ca_cert, der, verification_time="2028-06-01T00:00:00Z"))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "thisUpdate" in data["reason"]


def test_produced_at_in_future(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key)
    der = set_produced_at(
        der, ca_key, "ec", dt.datetime(2030, 1, 1, tzinfo=UTC)
    )
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "producedAt" in data["reason"]


def test_unsuccessful_response_unauthorized(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = (
        ocsp.OCSPResponseBuilder()
        .build_unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED)
        .public_bytes(serialization.Encoding.DER)
    )
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "successful" in data["reason"]


@pytest.mark.parametrize(
    "status",
    [
        ocsp.OCSPResponseStatus.MALFORMED_REQUEST,
        ocsp.OCSPResponseStatus.INTERNAL_ERROR,
        ocsp.OCSPResponseStatus.TRY_LATER,
        ocsp.OCSPResponseStatus.SIG_REQUIRED,
    ],
)
def test_other_unsuccessful_statuses(ec_pair, status):
    ca_key, ca_cert, leaf = ec_pair
    der = (
        ocsp.OCSPResponseBuilder()
        .build_unsuccessful(status)
        .public_bytes(serialization.Encoding.DER)
    )
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 200
    assert r.json()["verified"] is False
    assert "successful" in r.json()["reason"]


# ---------- malformed input (422, error_type=OCSPError) ----------

def test_bad_leaf_pem_is_422(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    body = request_body(leaf, ca_cert, build_ocsp(leaf, ca_cert, ca_key))
    body["leaf_certificate"] = "not a certificate"
    r = check(body)
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"
    assert "leaf certificate" in r.json()["detail"]


def test_bad_issuer_pem_is_422(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    body = request_body(leaf, ca_cert, build_ocsp(leaf, ca_cert, ca_key))
    body["issuer_certificate"] = (
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    )
    r = check(body)
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"
    assert "issuer certificate" in r.json()["detail"]


def test_csr_pem_in_leaf_field_is_422(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_name("x"))
        .sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
    )
    body = request_body(leaf, ca_cert, build_ocsp(leaf, ca_cert, ca_key))
    body["leaf_certificate"] = csr.public_bytes(serialization.Encoding.PEM).decode()
    r = check(body)
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"


def test_bad_base64_is_422(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    body = request_body(leaf, ca_cert, build_ocsp(leaf, ca_cert, ca_key))
    body["ocsp_response"] = "@@@not base64@@@"
    r = check(body)
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"
    assert "Base64" in r.json()["detail"]


def test_garbage_der_is_422(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    body = request_body(leaf, ca_cert, b"\x00" * 10)
    r = check(body)
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"


def test_empty_base64_is_422(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    body = request_body(leaf, ca_cert, build_ocsp(leaf, ca_cert, ca_key))
    body["ocsp_response"] = ""
    r = check(body)
    assert r.status_code == 422


def test_multiple_single_responses_is_422(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = duplicate_single_responses(build_ocsp(leaf, ca_cert, ca_key))
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 422
    assert "exactly one SingleResponse" in r.json()["detail"]


def test_zero_single_responses_is_422(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = empty_single_responses(build_ocsp(leaf, ca_cert, ca_key))
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 422
    assert "exactly one SingleResponse" in r.json()["detail"]


def test_dsa_issuer_key_is_422():
    # A DSA issuer key cannot be used to recompute the CertID key hash
    # nor to verify the response signature; it must surface as 422.
    from cryptography.hazmat.primitives.asymmetric import dsa

    dsa_key = dsa.generate_private_key(key_size=2048)
    subject = _name("DSA CA")
    dsa_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(dsa_key.public_key())
        .serial_number(1)
        .not_valid_before(THIS - dt.timedelta(days=10))
        .not_valid_after(THIS + dt.timedelta(days=3650))
        .sign(dsa_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name("leaf.test"))
        .issuer_name(subject)
        .public_key(leaf_key.public_key())
        .serial_number(5)
        .not_valid_before(THIS)
        .not_valid_after(THIS + dt.timedelta(days=90))
        .sign(dsa_key, hashes.SHA256())
    )
    der = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            leaf, dsa_cert, hashes.SHA1(), ocsp.OCSPCertStatus.GOOD, THIS, NEXT, None, None
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, dsa_cert)
        .sign(dsa_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    r = check(request_body(leaf, dsa_cert, der))
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"
    assert "unsupported" in r.json()["detail"]


def test_unknown_signature_oid_is_422(ec_pair):
    # An algorithm OID the verifier does not know (Ed25519): 422,
    # regardless of the stale signature bytes.
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key)
    der = set_signature_algorithm_oid(der, "ed25519")
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"
    assert "signature algorithm" in r.json()["detail"]


def test_md5_certid_hash_is_422(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    der = build_ocsp(leaf, ca_cert, ca_key, certid_hash=hashes.SHA256())
    der = recertid(der, ca_cert, ca_key, "ec", "md5")
    r = check(request_body(leaf, ca_cert, der))
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"
    assert "CertID hash" in r.json()["detail"]


def test_naive_verification_time_is_422(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    body = request_body(leaf, ca_cert, build_ocsp(leaf, ca_cert, ca_key))
    body["verification_time"] = "2026-09-25T00:00:00"
    r = check(body)
    assert r.status_code == 422


def test_oversized_leaf_pem_is_422(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    body = request_body(leaf, ca_cert, build_ocsp(leaf, ca_cert, ca_key))
    body["leaf_certificate"] = "x" * (64 * 1024 + 1)
    r = check(body)
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"


def test_oversized_ocsp_der_is_422(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    body = request_body(leaf, ca_cert, build_ocsp(leaf, ca_cert, ca_key))
    body["ocsp_response"] = base64.b64encode(b"a" * (64 * 1024 + 1)).decode()
    r = check(body)
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"


def test_missing_field_is_422(ec_pair):
    ca_key, ca_cert, leaf = ec_pair
    body = request_body(leaf, ca_cert, build_ocsp(leaf, ca_cert, ca_key))
    del body["ocsp_response"]
    r = check(body)
    assert r.status_code == 422
