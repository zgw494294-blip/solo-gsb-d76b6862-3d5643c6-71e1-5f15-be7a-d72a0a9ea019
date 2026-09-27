"""End-to-end tests for POST /v1/issuance/check-csr."""

import base64
import hashlib
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

import app.engine as engine
from app.main import app

client = TestClient(app)

SUBJECT = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "csr.test")])


def caa(owner, tag, value="", flag=0):
    return {"type": "CAA", "owner": owner, "flag": flag, "tag": tag, "value": value}


def cname(owner, target):
    return {"type": "CNAME", "owner": owner, "target": target}


def make_csr(names, *, cn="csr.test", san=True, key=None):
    """Build a signed EC CSR. ``names`` entries: str -> DNSName, otherwise
    a pre-built GeneralName (e.g. x509.IPAddress)."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    if cn is not None:
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        )
    if san:
        general = [x509.DNSName(n) if isinstance(n, str) else n for n in names]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(general), critical=False
        )
    return builder.sign(key, hashes.SHA256())


def pem_of(csr):
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def der_of(csr):
    return csr.public_bytes(serialization.Encoding.DER)


def tampered_pem(csr):
    """Flip one byte inside the signature; the DER still parses."""
    der = bytearray(der_of(csr))
    der[-4] ^= 0x01
    body = base64.encodebytes(bytes(der)).decode()
    return (
        f"-----BEGIN CERTIFICATE REQUEST-----\n{body}"
        "-----END CERTIFICATE REQUEST-----\n"
    )


def check(body):
    return client.post("/v1/issuance/check-csr", json=body)


def req(csr, ca="letsencrypt.org", records=None):
    return {"csr": pem_of(csr) if not isinstance(csr, str) else csr,
            "ca": ca, "records": records or []}


LE = caa("example.com", "issue", "letsencrypt.org")
LE_WILD = caa("example.com", "issuewild", "letsencrypt.org")


# ---------- happy paths ----------

def test_single_name_authorized():
    csr = make_csr(["www.example.com"])
    r = check(req(csr, records=[LE]))
    assert r.status_code == 200
    data = r.json()
    assert data["csr_sha256"] == hashlib.sha256(der_of(csr)).hexdigest()
    assert data["authorized"] is True
    assert len(data["identifiers"]) == 1
    ident = data["identifiers"][0]
    assert ident["name"] == "www.example.com"
    assert ident["wildcard"] is False
    assert ident["domain"] == "www.example.com"
    assert ident["authorized"] is True
    assert ident["effective_owner"] == "example.com"
    assert [s["query"] for s in ident["trace"]] == [
        "www.example.com",
        "example.com",
    ]


def test_multiple_identifiers_follow_san_order():
    csr = make_csr(["www.example.com", "api.example.com", "cdn.example.com"])
    r = check(req(csr, records=[LE]))
    assert r.status_code == 200
    data = r.json()
    assert data["authorized"] is True
    assert [i["name"] for i in data["identifiers"]] == [
        "www.example.com",
        "api.example.com",
        "cdn.example.com",
    ]
    assert all(i["authorized"] for i in data["identifiers"])


def test_one_unauthorized_identifier_fails_the_whole_csr():
    csr = make_csr(["www.example.com", "deny.example.com"])
    records = [
        LE,
        caa("deny.example.com", "issue", "pki.goog"),
    ]
    r = check(req(csr, records=records))
    assert r.status_code == 200
    data = r.json()
    assert data["authorized"] is False
    assert "deny.example.com" in data["reason"]
    auth = {i["name"]: i["authorized"] for i in data["identifiers"]}
    assert auth == {"www.example.com": True, "deny.example.com": False}
    denied = data["identifiers"][1]
    assert denied["effective_owner"] == "deny.example.com"
    assert denied["trace"]


def test_no_caa_records_authorizes_every_identifier():
    csr = make_csr(["a.example.com", "b.example.com"])
    r = check(req(csr, records=[]))
    assert r.status_code == 200
    data = r.json()
    assert data["authorized"] is True
    assert all(i["effective_owner"] is None for i in data["identifiers"])


def test_names_normalized_case_and_trailing_dot():
    csr = make_csr(["WWW.Example.COM.", "API.example.com"])
    r = check(req(csr, ca="LetsEncrypt.ORG.", records=[
        caa("EXAMPLE.com.", "issue", "LETSENCRYPT.org.")
    ]))
    assert r.status_code == 200
    assert [i["name"] for i in r.json()["identifiers"]] == [
        "www.example.com",
        "api.example.com",
    ]


def test_wildcard_name_strips_prefix_and_sets_flag():
    csr = make_csr(["*.example.com"])
    ident = check(req(csr, records=[LE, LE_WILD])).json()["identifiers"][0]
    assert ident["name"] == "*.example.com"
    assert ident["wildcard"] is True
    assert ident["domain"] == "example.com"
    assert ident["authorized"] is True
    assert ident["trace"][0]["query"] == "example.com"


def test_wildcard_uses_issuewild_not_issue():
    # issue allows LE, issuewild explicitly denies everyone.
    csr = make_csr(["*.example.com"])
    r = check(
        req(csr, records=[LE, caa("example.com", "issuewild", "")])
    )
    data = r.json()
    assert data["authorized"] is False
    ident = data["identifiers"][0]
    assert ident["wildcard"] is True
    assert ident["authorized"] is False


def test_wildcard_and_base_name_are_distinct_identifiers():
    csr = make_csr(["*.example.com", "example.com"])
    r = check(req(csr, records=[LE, LE_WILD]))
    assert r.status_code == 200
    data = r.json()
    assert [i["name"] for i in data["identifiers"]] == [
        "*.example.com",
        "example.com",
    ]
    assert data["authorized"] is True


def test_wildcard_case_and_trailing_dot_normalize():
    csr = make_csr(["*.EXAMPLE.com."])
    ident = check(req(csr, records=[LE, LE_WILD])).json()["identifiers"][0]
    assert ident["name"] == "*.example.com"
    assert ident["domain"] == "example.com"
    assert ident["wildcard"] is True


def test_cname_alias_followed_per_identifier():
    csr = make_csr(["www.example.com"])
    records = [
        cname("www.example.com", "edge.cdn.example"),
        caa("edge.cdn.example", "issue", "letsencrypt.org"),
    ]
    r = check(req(csr, records=records))
    assert r.status_code == 200
    ident = r.json()["identifiers"][0]
    assert ident["authorized"] is True
    assert ident["effective_owner"] == "edge.cdn.example"
    assert ident["trace"][0]["kind"] == "cname"
    assert ident["trace"][0]["cname_target"] == "edge.cdn.example"


def test_unknown_critical_tag_denies_identifier():
    csr = make_csr(["www.example.com"])
    r = check(req(csr, records=[
        caa("example.com", "weirdtag", "x", flag=128)
    ]))
    assert r.status_code == 200
    assert r.json()["authorized"] is False


def test_20_names_allowed():
    csr = make_csr([f"h{i:02d}.example.com" for i in range(20)])
    r = check(req(csr, records=[LE]))
    assert r.status_code == 200
    assert len(r.json()["identifiers"]) == 20


# ---------- CSR / SAN validation (422) ----------

def test_missing_san_is_422_even_with_cn():
    csr = make_csr([], cn="www.example.com", san=False)
    r = check(req(csr))
    assert r.status_code == 422
    assert r.json()["error_type"] == "CSRError"
    assert "subjectAltName" in r.json()["detail"]


def test_cn_is_ignored_when_san_present():
    csr = make_csr(["www.example.com"], cn="other.example.com")
    r = check(req(csr, records=[LE]))
    assert r.status_code == 200
    names = [i["name"] for i in r.json()["identifiers"]]
    assert names == ["www.example.com"]


def test_duplicate_names_after_normalization_are_422():
    csr = make_csr(["Example.com", "example.com."])
    r = check(req(csr))
    assert r.status_code == 422
    assert r.json()["error_type"] == "CSRError"
    assert "duplicate" in r.json()["detail"]


def test_duplicate_wildcards_after_normalization_are_422():
    csr = make_csr(["*.example.com", "*.EXAMPLE.COM."])
    r = check(req(csr))
    assert r.status_code == 422
    assert "duplicate" in r.json()["detail"]


def test_non_dns_san_identifier_is_422():
    csr = make_csr([x509.IPAddress(ipaddress.ip_address("192.0.2.1"))])
    r = check(req(csr))
    assert r.status_code == 422
    assert r.json()["error_type"] == "CSRError"
    assert "non-DNS" in r.json()["detail"]


def test_mixed_dns_and_non_dns_san_is_422():
    csr = make_csr(
        ["www.example.com", x509.IPAddress(ipaddress.ip_address("2001:db8::1"))]
    )
    assert check(req(csr)).status_code == 422


def test_empty_san_is_422():
    csr = make_csr([])
    r = check(req(csr))
    assert r.status_code == 422
    assert r.json()["error_type"] == "CSRError"


def test_more_than_20_san_names_is_422():
    csr = make_csr([f"h{i:02d}.example.com" for i in range(21)])
    r = check(req(csr))
    assert r.status_code == 422
    assert "at most 20" in r.json()["detail"]


def test_invalid_signature_is_422():
    csr = make_csr(["www.example.com"])
    r = check(req(tampered_pem(csr)))
    assert r.status_code == 422
    assert r.json()["error_type"] == "CSRError"
    assert "signature" in r.json()["detail"]


def test_garbage_pem_is_422():
    r = check(req("not a pem at all"))
    assert r.status_code == 422
    assert r.json()["error_type"] == "CSRError"


def test_oversize_csr_is_422():
    body = {"csr": "A" * (64 * 1024 + 1), "ca": "a.net", "records": []}
    r = check(body)
    assert r.status_code == 422
    assert r.json()["error_type"] == "CSRError"
    assert "64 KiB" in r.json()["detail"]


@pytest.mark.parametrize(
    "bad_name",
    [
        "ex*.example.com",   # wildcard not leftmost
        "a.*.example.com",   # wildcard in a middle label
        "*.*.example.com",   # more than one wildcard
        "*example.com",      # star without a dot
        "*",                 # bare star
        "*.",                # wildcard above root
        "bad..example.com",  # empty label
        "example.com..",
        "-bad.example.com",  # leading hyphen
        "bad-.example.com",  # trailing hyphen
        "",                  # empty
        ".",                 # root only
    ],
)
def test_illegal_san_name_is_422(bad_name):
    csr = make_csr([bad_name])
    assert check(req(csr)).status_code == 422


# ---------- records / alias errors stay 422 ----------

def test_more_than_100_records_is_422():
    recs = [caa(f"h{i:03d}.example.com", "issue", "a.net") for i in range(101)]
    csr = make_csr(["x.example.com"])
    assert check(req(csr, records=recs)).status_code == 422


def test_bad_record_is_422():
    csr = make_csr(["x.example.com"])
    r = check(req(csr, records=[
        caa("x.example.com", "issue", "a.net", flag=7)
    ]))
    assert r.status_code == 422


def test_mixed_records_is_422():
    csr = make_csr(["x.test"])
    r = check(
        req(csr, records=[cname("x.test", "z.test"), caa("x.test", "issue", "a.net")])
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "MixedRecordsError"


def test_cname_loop_for_one_identifier_is_422():
    csr = make_csr(["x.test", "y.test"])
    records = [
        cname("x.test", "z.test"),
        cname("z.test", "x.test"),
    ]
    r = check(req(csr, records=records))
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_bad_ca_name_is_422():
    csr = make_csr(["www.example.com"])
    r = check(req(csr, ca="bad..ca"))
    assert r.status_code == 422


# ---------- shared record preparation ----------

def test_record_set_prepared_once_for_whole_csr(monkeypatch):
    calls = []
    real_prepare = engine.prepare_records

    def spy(records):
        calls.append(records)
        return real_prepare(records)

    monkeypatch.setattr(engine, "prepare_records", spy)
    csr = make_csr(
        ["www.example.com", "api.example.com", "cdn.example.com"]
    )
    r = check(req(csr, records=[LE]))
    assert r.status_code == 200
    assert r.json()["authorized"] is True
    # The single shared record set is prepared once, not once per SAN.
    assert len(calls) == 1
