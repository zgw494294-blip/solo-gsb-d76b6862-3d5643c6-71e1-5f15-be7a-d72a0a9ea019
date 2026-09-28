"""End-to-end tests for POST /v1/issuance/check-ocsp."""

import base64
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

NOW = datetime.datetime(2026, 9, 28, 12, 0, 0, tzinfo=datetime.timezone.utc)


# ---------- DER splicing helpers (for structures the builder cannot emit) ----------

def _enc_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _wrap(tag, content):
    return bytes([tag]) + _enc_len(len(content)) + content


def _parse_tlv(blob, pos):
    tag = blob[pos]
    b = blob[pos + 1]
    if b < 0x80:
        start, length = pos + 2, b
    else:
        n = b & 0x7F
        length = int.from_bytes(blob[pos + 2 : pos + 2 + n], "big")
        start = pos + 2 + n
    return tag, start, blob[start : start + length], start + length


def _children(content):
    out, pos = [], 0
    while pos < len(content):
        tag, start, value, pos = _parse_tlv(content, pos)
        out.append((tag, value))
    return out


def _dissect_basic(der):
    """Return (response-type OID, BasicOCSPResponse children) from DER."""
    _, _, top, _ = _parse_tlv(der, 0)
    _, _, _, pos = _parse_tlv(top, 0)  # responseStatus ENUMERATED
    _, _, a0, _ = _parse_tlv(top, pos)  # [0] EXPLICIT ResponseBytes
    _, _, response_bytes, _ = _parse_tlv(a0, 0)
    rb_children = _children(response_bytes)
    _, _, basic, _ = _parse_tlv(rb_children[1][1], 0)  # OCTET STRING
    return rb_children[0][1], _children(basic)


def _build_response(oid, tbs_content, sigalg_content, bitsig_content):
    basic = _wrap(
        0x30,
        _wrap(0x30, tbs_content)
        + _wrap(0x30, sigalg_content)
        + _wrap(0x03, bitsig_content),
    )
    response_bytes = _wrap(
        0x30, _wrap(0x06, oid) + _wrap(0x04, basic)
    )
    return _wrap(0x30, _wrap(0x0A, b"\x00") + _wrap(0xA0, response_bytes))


def _is_responses_sequence(value):
    """True for the tbs 'responses' SEQUENCE OF SingleResponse."""
    entries = _children(value)
    if not entries or entries[0][0] != 0x30:
        return False
    # SingleResponse ::= SEQUENCE { certID CertID, certStatus, ... }
    single_children = _children(entries[0][1])
    if not single_children or single_children[0][0] != 0x30:
        return False
    # CertID ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
    #                       issuerNameHash OCTET STRING,
    #                       issuerKeyHash OCTET STRING, serialNumber INTEGER }
    certid_fields = _children(single_children[0][1])
    return (
        len(certid_fields) >= 4
        and certid_fields[0][0] == 0x30  # AlgorithmIdentifier
        and certid_fields[1][0] == 0x04
        and certid_fields[2][0] == 0x04
        and certid_fields[3][0] == 0x02
    )


def _der_with_two_single_responses(der_a, der_b):
    """Splice both responses' SingleResponse entries into one response."""
    oid, fa = _dissect_basic(der_a)
    _, fb = _dissect_basic(der_b)

    def first_entry(basic_kids):
        for tag, value in _children(basic_kids[0][1]):
            if tag == 0x30 and _is_responses_sequence(value):
                # value is the SEQUENCE OF; return its first child TLV whole
                first_tag, _, first_value, _ = _parse_tlv(value, 0)
                return _wrap(first_tag, first_value)
        raise AssertionError("responses sequence not found")

    entry_a, entry_b = first_entry(fa), first_entry(fb)
    parts = []
    for tag, value in _children(fa[0][1]):
        if tag == 0x30 and _is_responses_sequence(value):
            value = entry_a + entry_b
        parts.append(_wrap(tag, value))
    return _build_response(oid, b"".join(parts), fa[1][1], fa[2][1])


def _der_resigned_pss(der, ca_key):
    """Re-sign tbsResponseData with RSASSA-PSS (sha256/MGF1/saltLen=32)."""
    oid, basic_kids = _dissect_basic(der)
    tbs_tlv = _wrap(basic_kids[0][0], basic_kids[0][1])

    sha256_oid = bytes.fromhex("608648016503040201")
    mgf1_oid = bytes.fromhex("2a864886f70d010108")
    sha_algid = _wrap(0x30, _wrap(0x06, sha256_oid) + _wrap(0x05, b""))
    pss_params = _wrap(
        0x30,
        _wrap(0xA0, sha_algid)
        + _wrap(0xA1, _wrap(0x30, _wrap(0x06, mgf1_oid) + sha_algid))
        + _wrap(0xA2, _wrap(0x02, b"\x20")),
    )
    sigalg = _wrap(0x06, bytes.fromhex("2a864886f70d01010a")) + pss_params
    signature = ca_key.sign(
        tbs_tlv,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return _build_response(oid, basic_kids[0][1], sigalg, b"\x00" + signature)


def _sign_tbs(tbs_tlv, sign_key, sign_alg):
    if isinstance(sign_key, rsa.RSAPrivateKey):
        return sign_key.sign(tbs_tlv, padding.PKCS1v15(), sign_alg)
    return sign_key.sign(tbs_tlv, ec.ECDSA(sign_alg))


def _der_resign(der, sign_key, sign_alg=hashes.SHA256()):
    """Re-sign an otherwise-valid response with a different key."""
    oid, basic_kids = _dissect_basic(der)
    tbs_tlv = _wrap(basic_kids[0][0], basic_kids[0][1])
    return _build_response(
        oid,
        basic_kids[0][1],
        basic_kids[1][1],
        b"\x00" + _sign_tbs(tbs_tlv, sign_key, sign_alg),
    )


def _der_with_produced_at(der, produced_at, sign_key, sign_alg=hashes.SHA256()):
    """Replace the GeneralizedTime producedAt and re-sign."""
    oid, basic_kids = _dissect_basic(der)
    parts = []
    for tag, value in _children(basic_kids[0][1]):
        if tag == 0x18:  # GeneralizedTime producedAt
            value = produced_at.astimezone(datetime.timezone.utc).strftime(
                "%Y%m%d%H%M%SZ"
            ).encode("ascii")
        parts.append(_wrap(tag, value))
    tbs_content = b"".join(parts)
    tbs_tlv = _wrap(basic_kids[0][0], tbs_content)
    signature = _sign_tbs(tbs_tlv, sign_key, sign_alg)
    return _build_response(
        oid, tbs_content, basic_kids[1][1], b"\x00" + signature
    )


# ---------- fixture builders ----------

def make_ca(*, key=None, cn="ca.test", alg=hashes.SHA256()):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(NOW - datetime.timedelta(days=365))
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .sign(key, alg)
    )
    return key, cert


def make_leaf(issuer_cert, issuer_key, *, serial=0x1234, cn="leaf.test",
              key=None, sig_alg=hashes.SHA256()):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOW - datetime.timedelta(days=30))
        .not_valid_after(NOW + datetime.timedelta(days=60))
        .sign(issuer_key, sig_alg)
    )
    return cert


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def build_ocsp(
    leaf_cert,
    issuer_cert,
    issuer_key,
    *,
    status=ocsp.OCSPCertStatus.GOOD,
    algorithm=hashes.SHA1(),
    responder=ocsp.OCSPResponderEncoding.NAME,
    this_update=None,
    next_update=NOW + datetime.timedelta(days=7),
    produced_at=None,
    sign_key=None,
    sign_alg=hashes.SHA256(),
    revocation_time=None,
    revocation_reason=None,
):
    this_update = this_update or NOW - datetime.timedelta(hours=1)
    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf_cert,
            issuer=issuer_cert,
            algorithm=algorithm,
            cert_status=status,
            this_update=this_update,
            next_update=next_update,
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )
        .responder_id(responder, issuer_cert)
        .sign(sign_key or issuer_key, sign_alg)
    )
    # The builder always stamps producedAt with the wall clock; rewrite it
    # (and re-sign) so tests can pin/future-date it deterministically.
    target = produced_at or NOW - datetime.timedelta(minutes=1)
    der = response.public_bytes(serialization.Encoding.DER)
    der = _der_with_produced_at(
        der, target, sign_key or issuer_key, sign_alg=sign_alg
    )
    return ocsp.load_der_ocsp_response(der)


def b64_der(response):
    return base64.b64encode(
        response.public_bytes(serialization.Encoding.DER)
    ).decode()


def build_ocsp_for(
    leaf_cert, issuer_for_certid, *, responder_cert, responder_key,
    algorithm=hashes.SHA1(), status=ocsp.OCSPCertStatus.GOOD,
    this_update=None, next_update=NOW + datetime.timedelta(days=7),
    produced_at=None, sign_alg=hashes.SHA256(),
    revocation_time=None, revocation_reason=None,
):
    """Build a response with a CertID for issuer_for_certid but an
    independently chosen responder (and signing key)."""
    this_update = this_update or NOW - datetime.timedelta(hours=1)
    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf_cert, issuer=issuer_for_certid, algorithm=algorithm,
            cert_status=status, this_update=this_update,
            next_update=next_update, revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, responder_cert)
        .sign(responder_key, sign_alg)
    )
    der = response.public_bytes(serialization.Encoding.DER)
    der = _der_with_produced_at(
        der, produced_at or NOW - datetime.timedelta(minutes=1),
        responder_key, sign_alg=sign_alg,
    )
    return ocsp.load_der_ocsp_response(der)


def check(body):
    return client.post("/v1/issuance/check-ocsp", json=body)


def req(leaf_cert, issuer_cert, response_b64, *, at=NOW, overrides=None):
    body = {
        "leaf_certificate": pem(leaf_cert),
        "issuer_certificate": pem(issuer_cert),
        "ocsp_response": response_b64,
        "verification_time": at.isoformat(),
    }
    if overrides:
        body.update(overrides)
    return body


def make_happy(*, ca_alg=hashes.SHA256(), leaf_sig=hashes.SHA256(),
               ocsp_hash=hashes.SHA1(), ocsp_sign=hashes.SHA256(),
               responder=ocsp.OCSPResponderEncoding.NAME,
               status=ocsp.OCSPCertStatus.GOOD,
               this_update=None, next_update=NOW + datetime.timedelta(days=7),
               produced_at=None,
               revocation_time=None, revocation_reason=None,
               **leaf_kw):
    ca_key, ca_cert = make_ca(alg=ca_alg)
    leaf_cert = make_leaf(ca_cert, ca_key, sig_alg=leaf_sig, **leaf_kw)
    response = build_ocsp(
        leaf_cert, ca_cert, ca_key,
        algorithm=ocsp_hash, responder=responder, sign_alg=ocsp_sign,
        status=status, this_update=this_update, next_update=next_update,
        produced_at=produced_at, revocation_time=revocation_time,
        revocation_reason=revocation_reason,
    )
    return ca_key, ca_cert, leaf_cert, response


# ---------- happy paths ----------

def test_good_rsa_sha1_certid_by_name():
    _, ca, leaf, response = make_happy(ocsp_hash=hashes.SHA1())
    data = check(req(leaf, ca, b64_der(response))).json()
    assert data["verified"] is True
    assert data["status"] == "good"
    assert data["revocation_time"] is None
    assert data["produced_at"].startswith("2026-09-28T11:59:00")
    assert data["this_update"].startswith("2026-09-28T11:00:00")
    assert data["next_update"].startswith("2026-10-05T12:00:00")
    assert data["reason"].endswith("good")


def test_good_sha256_certid_by_key():
    _, ca, leaf, response = make_happy(
        ocsp_hash=hashes.SHA256(), responder=ocsp.OCSPResponderEncoding.HASH
    )
    assert check(req(leaf, ca, b64_der(response))).json()["verified"] is True


def test_ecdsa_issuer_and_ecdsa_ocsp_signature():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    _, ca_cert = make_ca(key=ca_key)
    leaf_cert = make_leaf(
        ca_cert, ca_key, key=ec.generate_private_key(ec.SECP384R1()),
        sig_alg=hashes.SHA384(),
    )
    response = build_ocsp(
        leaf_cert, ca_cert, ca_key,
        algorithm=hashes.SHA256(), sign_alg=hashes.SHA384(),
        responder=ocsp.OCSPResponderEncoding.HASH,
    )
    data = check(req(leaf_cert, ca_cert, b64_der(response))).json()
    assert data["verified"] is True


def test_ecdsa_p384_sha384():
    ca_key = ec.generate_private_key(ec.SECP384R1())
    _, ca_cert = make_ca(key=ca_key, alg=hashes.SHA384())
    leaf_cert = make_leaf(ca_cert, ca_key, sig_alg=hashes.SHA384())
    response = build_ocsp(
        leaf_cert, ca_cert, ca_key,
        algorithm=hashes.SHA384(), sign_alg=hashes.SHA384(),
    )
    assert check(req(leaf_cert, ca_cert, b64_der(response))).json()["verified"] is True


def test_revoked_status_reports_revocation_time():
    _, ca, leaf, response = make_happy(
        status=ocsp.OCSPCertStatus.REVOKED,
        revocation_time=NOW - datetime.timedelta(days=2),
        revocation_reason=x509.ReasonFlags.key_compromise,
    )
    data = check(req(leaf, ca, b64_der(response))).json()
    assert data["verified"] is True
    assert data["status"] == "revoked"
    assert data["revocation_time"].startswith("2026-09-26T12:00:00")


def test_unknown_status_verifies():
    _, ca, leaf, response = make_happy(status=ocsp.OCSPCertStatus.UNKNOWN)
    data = check(req(leaf, ca, b64_der(response))).json()
    assert data["verified"] is True
    assert data["status"] == "unknown"


def test_boundary_times_accepted():
    _, ca, leaf, response = make_happy(
        this_update=NOW, next_update=NOW, produced_at=NOW
    )
    assert check(req(leaf, ca, b64_der(response))).json()["verified"] is True


def test_offset_verification_time_normalized_to_utc():
    _, ca, leaf, response = make_happy()
    at = NOW.astimezone(datetime.timezone(datetime.timedelta(hours=2)))
    assert check(req(leaf, ca, b64_der(response), at=at)).json()["verified"] is True


# ---------- verification failures (200, verified=false) ----------

def test_non_successful_response_try_later():
    _, ca, leaf, _ = make_happy()
    # OCSPResponse SEQUENCE { responseStatus ENUMERATED tryLater(3) }
    payload = base64.b64encode(bytes.fromhex("30030a0103")).decode()
    r = check(req(leaf, ca, payload))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "successful" in data["reason"]
    assert data["status"] is None
    assert data["produced_at"] is None
    assert data["next_update"] is None


def test_wrong_serial_certid():
    ca_key, ca_cert = make_ca()
    submitted = make_leaf(ca_cert, ca_key, serial=111)
    target = make_leaf(ca_cert, ca_key, serial=222)
    response = build_ocsp(target, ca_cert, ca_key)
    r = check(req(submitted, ca_cert, b64_der(response)))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "serial" in data["reason"]


def test_certid_name_hash_mismatch_same_serial():
    ca1_key, ca1 = make_ca(cn="one.test")
    ca2_key, ca2 = make_ca(cn="two.test")
    leaf1 = make_leaf(ca1, ca1_key, serial=7)
    leaf2 = make_leaf(ca2, ca2_key, serial=7)
    response = build_ocsp(leaf2, ca2, ca2_key)
    r = check(req(leaf1, ca1, b64_der(response)))
    assert r.status_code == 200
    # responder byName is ca2's subject, which is neither the leaf issuer DN
    reason = r.json()["reason"]
    assert "issuer" in reason or "responder" in reason
    assert r.json()["verified"] is False


def test_responder_name_is_foreign_ca():
    ca_key, ca = make_ca()
    rogue_key, rogue = make_ca(cn="responder-rogue.test")
    leaf = make_leaf(ca, ca_key, serial=3)
    response = build_ocsp_for(
        leaf, ca, responder_cert=rogue, responder_key=rogue_key
    )
    r = check(req(leaf, ca, b64_der(response)))
    assert r.status_code == 200
    assert r.json()["verified"] is False
    assert "responder" in r.json()["reason"]


def test_responder_key_hash_is_foreign():
    ca_key, ca = make_ca()
    rogue_key, rogue = make_ca(cn="responder-rogue.test")
    leaf = make_leaf(ca, ca_key, serial=4)
    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf, issuer=ca, algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=NOW - datetime.timedelta(hours=1),
            next_update=NOW + datetime.timedelta(days=1),
            revocation_time=None, revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, rogue)
        .sign(rogue_key, hashes.SHA256())
    )
    der = _der_with_produced_at(
        response.public_bytes(serialization.Encoding.DER),
        NOW - datetime.timedelta(minutes=1), rogue_key,
    )
    r = check(req(leaf, ca, base64.b64encode(der).decode()))
    assert r.status_code == 200
    assert r.json()["verified"] is False
    assert "byKey" in r.json()["reason"]


def test_bad_signature_tampered():
    _, ca, leaf, response = make_happy()
    der = bytearray(response.public_bytes(serialization.Encoding.DER))
    der[-5] ^= 0xFF
    payload = base64.b64encode(bytes(der)).decode()
    r = check(req(leaf, ca, payload))
    assert r.status_code == 200
    data = r.json()
    assert data["verified"] is False
    assert "signature" in data["reason"]


def test_signature_by_wrong_key_but_responder_name_matches():
    ca_key, ca, leaf, response = make_happy(serial=5)
    rogue_key, _ = make_ca(cn="rogue.test")
    # Keep a response that names our CA (byName, correct CertID, fresh times)
    # but replace the signature with one made by an unrelated key.
    der = _der_resign(
        response.public_bytes(serialization.Encoding.DER), rogue_key
    )
    r = check(req(leaf, ca, base64.b64encode(der).decode()))
    assert r.status_code == 200
    assert r.json()["verified"] is False
    assert "signature" in r.json()["reason"]


def test_ecdsa_bad_signature():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    _, ca = make_ca(key=ca_key)
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    leaf = make_leaf(ca, ca_key)
    response = build_ocsp(
        leaf, ca, ca_key, algorithm=hashes.SHA256(),
        responder=ocsp.OCSPResponderEncoding.NAME,
    )
    der = _der_resign(
        response.public_bytes(serialization.Encoding.DER), rogue_key
    )
    r = check(req(leaf, ca, base64.b64encode(der).decode()))
    assert r.json()["verified"] is False
    assert "signature" in r.json()["reason"]


def test_produced_at_in_future():
    _, ca, leaf, response = make_happy(
        produced_at=NOW + datetime.timedelta(seconds=1)
    )
    data = check(req(leaf, ca, b64_der(response))).json()
    assert data["verified"] is False
    assert "producedAt" in data["reason"]
    assert data["status"] is None


def test_this_update_in_future():
    _, ca, leaf, response = make_happy(
        this_update=NOW + datetime.timedelta(minutes=1)
    )
    data = check(req(leaf, ca, b64_der(response))).json()
    assert data["verified"] is False
    assert "thisUpdate" in data["reason"]


def test_next_update_missing():
    _, ca, leaf, response = make_happy(next_update=None)
    data = check(req(leaf, ca, b64_der(response))).json()
    assert data["verified"] is False
    assert "nextUpdate" in data["reason"]


def test_next_update_expired():
    _, ca, leaf, response = make_happy(
        this_update=NOW - datetime.timedelta(days=14),
        next_update=NOW - datetime.timedelta(seconds=1),
    )
    data = check(req(leaf, ca, b64_der(response))).json()
    assert data["verified"] is False
    assert "past" in data["reason"]


def test_leaf_issuer_dn_mismatch():
    ca_key, ca = make_ca()
    other_key, other = make_ca(cn="different.test")
    leaf = make_leaf(other, other_key, serial=8)
    response = build_ocsp(leaf, other, other_key)
    r = check(req(leaf, ca, b64_der(response)))
    assert r.status_code == 200
    assert r.json()["verified"] is False
    assert "issuer" in r.json()["reason"]


def test_two_single_responses_not_accepted():
    ca_key, ca = make_ca()
    leaf1 = make_leaf(ca, ca_key, serial=1, cn="leaf1.test")
    leaf2 = make_leaf(ca, ca_key, serial=2, cn="leaf2.test")
    der_a = build_ocsp(leaf1, ca, ca_key).public_bytes(serialization.Encoding.DER)
    der_b = build_ocsp(leaf2, ca, ca_key).public_bytes(serialization.Encoding.DER)
    multi = _der_with_two_single_responses(der_a, der_b)
    # The spliced response must still parse as DER.
    parsed = ocsp.load_der_ocsp_response(multi)
    assert len(list(parsed.responses)) == 2
    r = check(req(leaf1, ca, base64.b64encode(multi).decode()))
    assert r.status_code == 200
    assert r.json()["verified"] is False
    assert "2 SingleResponse" in r.json()["reason"]


# ---------- malformed input / unsupported algorithms (422) ----------

def test_malformed_leaf_pem_is_422():
    _, ca, leaf, response = make_happy()
    r = check(req(leaf, ca, b64_der(response),
                  overrides={"leaf_certificate": "not a pem"}))
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"


def test_leaf_pem_with_two_blocks_is_422():
    _, ca, leaf, response = make_happy()
    r = check(req(leaf, ca, b64_der(response),
                  overrides={"leaf_certificate": pem(leaf) + pem(ca)}))
    assert r.status_code == 422


def test_malformed_issuer_pem_is_422():
    _, ca, leaf, response = make_happy()
    bogus = (
        "-----BEGIN CERTIFICATE-----\nAAAA\n"
        "-----END CERTIFICATE-----\n"
    )
    r = check(req(leaf, ca, b64_der(response),
                  overrides={"issuer_certificate": bogus}))
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"


def test_oversize_leaf_pem_is_422():
    _, ca, leaf, response = make_happy()
    r = check(req(leaf, ca, b64_der(response),
                  overrides={"leaf_certificate": "A" * (64 * 1024 + 1)}))
    assert r.status_code == 422
    assert "64 KiB" in r.json()["detail"]


@pytest.mark.parametrize("bad", ["@@@@", "A", "AAA=", "AA=A", "YWJj#A=="])
def test_malformed_base64_is_422(bad):
    _, ca, leaf, _ = make_happy()
    r = check(req(leaf, ca, bad, overrides={"ocsp_response": bad}))
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"


def test_empty_base64_is_422():
    _, ca, leaf, _ = make_happy()
    r = check(req(leaf, ca, "", overrides={"ocsp_response": ""}))
    assert r.status_code == 422


def test_malformed_der_is_422():
    _, ca, leaf, _ = make_happy()
    payload = base64.b64encode(b"garbage not der").decode()
    r = check(req(leaf, ca, payload))
    assert r.status_code == 422
    assert "DER" in r.json()["detail"]


def test_oversize_base64_is_422():
    _, ca, leaf, _ = make_happy()
    payload = base64.b64encode(b"x" * (64 * 1024 + 1)).decode()
    r = check(req(leaf, ca, payload))
    assert r.status_code == 422
    assert "64 KiB" in r.json()["detail"]


def test_unknown_status_enumerated_is_422():
    _, ca, leaf, _ = make_happy()
    # responseStatus=9 is an illegal enumerated value for this ASN.1 module
    payload = base64.b64encode(bytes.fromhex("30030a0109")).decode()
    assert check(req(leaf, ca, payload)).status_code == 422


def test_naive_verification_time_is_422():
    _, ca, leaf, response = make_happy()
    r = check(req(leaf, ca, b64_der(response),
                  overrides={"verification_time": "2026-09-28T12:00:00"}))
    assert r.status_code == 422


def test_missing_fields_422():
    r = check({"leaf_certificate": "x"})
    assert r.status_code == 422


def test_rsa_pss_signature_algorithm_unsupported():
    ca_key, ca, leaf, response = make_happy()
    der = response.public_bytes(serialization.Encoding.DER)
    pss_der = _der_resigned_pss(der, ca_key)
    # Sanity: the splice parses and reports the PSS OID.
    parsed = ocsp.load_der_ocsp_response(pss_der)
    assert parsed.signature_algorithm_oid.dotted_string == "1.2.840.113549.1.1.10"
    r = check(req(leaf, ca, base64.b64encode(pss_der).decode()))
    assert r.status_code == 422
    assert r.json()["error_type"] == "OCSPError"
    assert "PSS" in r.json()["detail"]
