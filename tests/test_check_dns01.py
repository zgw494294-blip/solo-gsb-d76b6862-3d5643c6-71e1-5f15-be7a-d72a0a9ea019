"""End-to-end tests for POST /v1/issuance/check-dns01."""

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import app.dns01 as dns01
from app.main import app

client = TestClient(app)

# The RSA JWK from RFC 7638 appendix A.1, whose thumbprint is fixed.
RFC_JWK = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7a"
        "PFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXAr"
        "wl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0"
        "zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2N"
        "cRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    ),
    "e": "AQAB",
}
RFC_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

TOKEN = "DGyRejmCefe7v4NfDGDKfA"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def expected_digest(token: str = TOKEN, thumbprint: str = RFC_THUMBPRINT) -> str:
    return b64url(hashlib.sha256(f"{token}.{thumbprint}".encode()).digest())


def txt(owner, chunks):
    return {"type": "TXT", "owner": owner, "chunks": chunks}


def cname(owner, target):
    return {"type": "CNAME", "owner": owner, "target": target}


def challenge(ch_id="c1", domain="example.com", token=TOKEN, *, wildcard=False):
    return {"id": ch_id, "domain": domain, "wildcard": wildcard, "token": token}


def check(body):
    return client.post("/v1/issuance/check-dns01", json=body)


def body(challenges=None, records=None, jwk=None):
    return {
        "jwk": jwk or RFC_JWK,
        "challenges": challenges if challenges is not None else [challenge()],
        "records": records or [],
    }


def qname_of(domain):
    return f"_acme-challenge.{domain}"


# ---------- happy paths ----------

def test_thumbprint_matches_rfc7638_vector():
    r = check(body(records=[
        txt(qname_of("example.com"), [expected_digest()])
    ]))
    assert r.status_code == 200
    data = r.json()
    assert data["thumbprint"] == RFC_THUMBPRINT
    assert data["valid"] is True


def test_extra_jwk_members_are_ignored():
    jwk = {**RFC_JWK, "alg": "RS256", "kid": "2011-04-29"}
    r = check(body(
        jwk=jwk,
        records=[txt(qname_of("example.com"), [expected_digest()])],
    ))
    assert r.status_code == 200
    assert r.json()["thumbprint"] == RFC_THUMBPRINT


def test_single_challenge_verified():
    r = check(body(records=[
        txt(qname_of("example.com"), [expected_digest()])
    ]))
    data = r.json()
    assert data["valid"] is True
    assert data["reason"].startswith("all 1")
    (res,) = data["results"]
    assert res["id"] == "c1"
    assert res["domain"] == "example.com"
    assert res["wildcard"] is False
    assert res["qname"] == qname_of("example.com")
    assert res["valid"] is True
    assert res["cname_hops"] == 0
    assert res["cname_chain"] == [qname_of("example.com")]
    assert res["txt_owner"] == qname_of("example.com")
    assert res["expected_txt"] == expected_digest()
    assert res["observed_txt"] == [expected_digest()]


def test_wildcard_challenge_uses_same_owner():
    r = check(body(
        challenges=[challenge(wildcard=True)],
        records=[txt(qname_of("example.com"), [expected_digest()])],
    ))
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["wildcard"] is True
    assert res["qname"] == qname_of("example.com")
    assert res["valid"] is True


def test_chunks_are_concatenated_in_order():
    digest = expected_digest()
    cut = len(digest) // 2
    r = check(body(records=[
        txt(qname_of("example.com"), [digest[:cut], digest[cut:]])
    ]))
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["observed_txt"] == [digest]
    assert res["valid"] is True


def test_wrong_chunk_order_fails():
    digest = expected_digest()
    cut = len(digest) // 2
    r = check(body(records=[
        txt(qname_of("example.com"), [digest[cut:], digest[:cut]])
    ]))
    assert r.status_code == 200
    assert r.json()["results"][0]["valid"] is False


def test_any_of_several_txt_rr_sets_matching_passes():
    r = check(body(records=[
        txt(qname_of("example.com"), ["unrelated-value"]),
        txt(qname_of("example.com"), [expected_digest()]),
        txt(qname_of("example.com"), [""]),
    ]))
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["valid"] is True
    assert res["observed_txt"] == ["unrelated-value", expected_digest(), ""]


def test_txt_at_parent_is_not_consulted():
    # Exact-name lookup only: a TXT at the domain itself must not match.
    r = check(body(records=[
        txt("example.com", [expected_digest()])
    ]))
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["valid"] is False
    assert res["txt_owner"] == qname_of("example.com")
    assert res["observed_txt"] == []
    assert "no TXT records" in res["reason"]


def test_missing_txt_fails_the_item_not_the_request():
    r = check(body(records=[]))
    assert r.status_code == 200
    data = r.json()
    assert data["valid"] is False
    (res,) = data["results"]
    assert res["valid"] is False
    assert res["expected_txt"] == expected_digest()


def test_mismatched_txt_fails_with_observed_values():
    r = check(body(records=[
        txt(qname_of("example.com"), ["wrong-digest"])
    ]))
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["valid"] is False
    assert res["observed_txt"] == ["wrong-digest"]
    assert expected_digest() in res["reason"]


def test_multiple_challenges_follow_input_order_and_overall_valid():
    d1, d2, d3 = "a.example.com", "b.example.com", "c.example.com"
    digest2 = expected_digest(token="aaaaaaaaaaaa")
    r = check(body(
        challenges=[
            challenge("1", d1, TOKEN),
            challenge("2", d2, "aaaaaaaaaaaa"),
            challenge("3", d3, TOKEN),
        ],
        records=[
            txt(qname_of(d1), [expected_digest(TOKEN)]),
            txt(qname_of(d2), [digest2]),
            # d3 deliberately missing
        ],
    ))
    assert r.status_code == 200
    data = r.json()
    assert [x["id"] for x in data["results"]] == ["1", "2", "3"]
    assert [x["valid"] for x in data["results"]] == [True, True, False]
    assert data["valid"] is False
    assert "['3']" in data["reason"]


def test_overall_valid_when_every_item_passes():
    r = check(body(
        challenges=[challenge("1", "a.example.com"), challenge("2", "b.example.com")],
        records=[
            txt(qname_of("a.example.com"), [expected_digest()]),
            txt(qname_of("b.example.com"), [expected_digest()]),
        ],
    ))
    assert r.status_code == 200
    data = r.json()
    assert data["valid"] is True
    assert "all 2" in data["reason"]


def test_duplicate_domains_with_distinct_ids_are_separate_items():
    r = check(body(
        challenges=[
            challenge("one", "example.com", TOKEN),
            challenge("two", "example.com", "bbbbbbbbbbbb"),
        ],
        records=[
            txt(qname_of("example.com"), [expected_digest(TOKEN)]),
            txt(qname_of("example.com"), [expected_digest("bbbbbbbbbbbb")]),
        ],
    ))
    assert r.status_code == 200
    data = r.json()
    assert [x["valid"] for x in data["results"]] == [True, True]


def test_20_challenges_allowed():
    chans = [
        challenge(f"c{i:02d}", f"h{i:02d}.example.com", TOKEN)
        for i in range(20)
    ]
    recs = [
        txt(qname_of(f"h{i:02d}.example.com"), [expected_digest()])
        for i in range(20)
    ]
    r = check(body(challenges=chans, records=recs))
    assert r.status_code == 200
    assert len(r.json()["results"]) == 20


# ---------- names / normalization ----------

def test_names_case_insensitive_and_trailing_dot():
    r = check(body(
        challenges=[challenge(domain="EXAMPLE.com.")],
        records=[txt("_ACME-CHALLENGE.Example.COM.", [expected_digest()])],
    ))
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["qname"] == qname_of("example.com")
    assert res["valid"] is True


def test_underscore_allowed_in_cname_targets():
    r = check(body(
        challenges=[challenge(domain="example.com")],
        records=[
            cname(qname_of("example.com"), "_acme-challenge.alias.example.net"),
            txt("_acme-challenge.alias.example.net", [expected_digest()]),
        ],
    ))
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["valid"] is True
    assert res["txt_owner"] == "_acme-challenge.alias.example.net"


def test_domain_with_wildcard_marker_is_422():
    r = check(body(challenges=[challenge(domain="*.example.com")]))
    assert r.status_code == 422


@pytest.mark.parametrize(
    "bad_domain",
    ["", ".", "bad..example.com", "-x.example.com", "x-.example.com",
     "ex*.com", "a b.example.com"],
)
def test_illegal_domain_is_422(bad_domain):
    r = check(body(challenges=[challenge(domain=bad_domain)]))
    assert r.status_code == 422


# ---------- CNAME semantics ----------

def test_cname_redirects_txt_lookup_to_target():
    r = check(body(records=[
        cname(qname_of("example.com"), "challenge.alias.example.net"),
        txt("challenge.alias.example.net", [expected_digest()]),
    ]))
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["valid"] is True
    assert res["cname_hops"] == 1
    assert res["cname_chain"] == [
        qname_of("example.com"), "challenge.alias.example.net"
    ]
    assert res["txt_owner"] == "challenge.alias.example.net"
    assert "CNAME hop" in res["reason"]


def test_txt_at_original_owner_ignored_when_cname_present_is_mixed_422():
    # A TXT and a CNAME at the same owner are a record-set error.
    r = check(body(records=[
        cname(qname_of("example.com"), "alias.example.net"),
        txt(qname_of("example.com"), [expected_digest()]),
    ]))
    assert r.status_code == 422
    assert r.json()["error_type"] == "MixedRecordsError"


def test_txt_at_parent_after_cname_is_not_consulted():
    # No climb: after the alias, only the exact target name is checked.
    r = check(body(records=[
        cname(qname_of("example.com"), "x.alias.example.net"),
        txt("alias.example.net", [expected_digest()]),
    ]))
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["valid"] is False
    assert res["txt_owner"] == "x.alias.example.net"
    assert res["observed_txt"] == []


def test_cname_chain_of_eight_hops_ok():
    records = [
        cname(qname_of("example.com"), "h1.example.net"),
    ]
    for i in range(1, 8):
        records.append(cname(f"h{i}.example.net", f"h{i + 1}.example.net"))
    records.append(txt("h8.example.net", [expected_digest()]))
    r = check(body(records=records))
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["valid"] is True
    assert res["cname_hops"] == 8
    assert len(res["cname_chain"]) == 9


def test_cname_chain_of_nine_hops_is_422():
    records = [cname(qname_of("example.com"), "h1.example.net")]
    for i in range(1, 9):
        records.append(cname(f"h{i}.example.net", f"h{i + 1}.example.net"))
    records.append(txt("h9.example.net", [expected_digest()]))
    r = check(body(records=records))
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELimitError"


def test_cname_loop_is_422():
    r = check(body(records=[
        cname(qname_of("example.com"), "a.example.net"),
        cname("a.example.net", "b.example.net"),
        cname("b.example.net", "a.example.net"),
    ]))
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_cname_self_redirect_is_422():
    r = check(body(records=[
        cname(qname_of("example.com"), qname_of("example.com"))
    ]))
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_alias_error_in_one_challenge_fails_whole_request():
    r = check(body(
        challenges=[
            challenge("ok", "good.example.com", TOKEN),
            challenge("loop", "bad.example.com", TOKEN),
        ],
        records=[
            txt(qname_of("good.example.com"), [expected_digest()]),
            cname(qname_of("bad.example.com"), "x.example.net"),
            cname("x.example.net", qname_of("bad.example.com")),
        ],
    ))
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_cname_is_exact_name_no_wildcard_matching():
    r = check(body(records=[
        cname("example.com", "alias.example.net"),
        txt(qname_of("example.com"), [expected_digest()]),
    ]))
    # The CNAME on the parent domain does not redirect the challenge owner.
    assert r.status_code == 200
    assert r.json()["results"][0]["valid"] is True


def test_multiple_cnames_same_owner_is_422():
    r = check(body(records=[
        cname(qname_of("example.com"), "a.example.net"),
        cname(qname_of("example.com"), "b.example.net"),
    ]))
    assert r.status_code == 422
    assert r.json()["error_type"] == "MultipleCNAMEError"


# ---------- JWK validation ----------

def test_generated_rsa_jwk_roundtrip():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "n": b64url(nums.n.to_bytes(256, "big")),
        "e": b64url(nums.e.to_bytes(3, "big")),
    }
    token = "fresh-token-abc"
    canonical = json.dumps(
        {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
        sort_keys=True, separators=(",", ":"),
    )
    thumb = b64url(hashlib.sha256(canonical.encode()).digest())
    digest = b64url(hashlib.sha256(f"{token}.{thumb}".encode()).digest())
    r = check(body(
        jwk=jwk,
        challenges=[challenge(token=token)],
        records=[txt(qname_of("example.com"), [digest])],
    ))
    assert r.status_code == 200
    assert r.json()["thumbprint"] == thumb
    assert r.json()["valid"] is True


def test_kty_wrong_is_422():
    for bad in ["rsa", "EC"]:
        r = check(body(jwk={**RFC_JWK, "kty": bad}))
        assert r.status_code == 422, r.text
        assert r.json()["error_type"] == "InvalidJWKError"


def test_kty_non_string_is_schema_422():
    for bad in [1, None]:
        r = check(body(jwk={**RFC_JWK, "kty": bad}))
        assert r.status_code == 422


def test_missing_n_or_e_is_422():
    r = check(body(jwk={"kty": "RSA", "e": "AQAB"}))
    assert r.status_code == 422
    r = check(body(jwk={"kty": "RSA", "n": RFC_JWK["n"]}))
    assert r.status_code == 422


def test_jwk_n_with_padding_is_422():
    r = check(body(jwk={**RFC_JWK, "n": RFC_JWK["n"] + "="}))
    assert r.status_code == 422
    assert r.json()["error_type"] == "InvalidJWKError"


def test_jwk_n_non_base64url_is_422():
    r = check(body(jwk={**RFC_JWK, "n": "not base64!!!"}))
    assert r.status_code == 422
    assert r.json()["error_type"] == "InvalidJWKError"


def test_jwk_n_empty_is_422():
    r = check(body(jwk={"kty": "RSA", "n": "", "e": "AQAB"}))
    assert r.status_code == 422
    assert r.json()["error_type"] == "InvalidJWKError"


def test_jwk_n_leading_zero_octet_is_422():
    # Prepend a zero byte: AA + original bytes.
    padded_n = b64url(b"\x00" + base64.urlsafe_b64decode(RFC_JWK["n"] + "==="))
    r = check(body(jwk={"kty": "RSA", "n": padded_n, "e": "AQAB"}))
    assert r.status_code == 422
    assert "leading zero" in r.json()["detail"]


def test_jwk_even_modulus_is_422():
    # A modulus whose last byte is even.
    raw = bytearray(base64.urlsafe_b64decode(RFC_JWK["n"] + "==="))
    raw[-1] &= 0xFE
    jwk = {"kty": "RSA", "n": b64url(bytes(raw)), "e": "AQAB"}
    r = check(body(jwk=jwk))
    assert r.status_code == 422
    assert r.json()["error_type"] == "InvalidJWKError"


def test_jwk_exponent_one_is_422():
    r = check(body(jwk={"kty": "RSA", "n": RFC_JWK["n"], "e": "AQ"}))
    assert r.status_code == 422
    assert "at least 3" in r.json()["detail"]


def test_jwk_not_object_is_422():
    r = client.post(
        "/v1/issuance/check-dns01",
        json={"jwk": "RSA", "challenges": [challenge()], "records": []},
    )
    assert r.status_code == 422


# ---------- token validation ----------

@pytest.mark.parametrize("bad_token", ["", "abc=", "abc.def", "A" * 1 + "???", "x"])
def test_illegal_token_is_422(bad_token):
    r = check(body(challenges=[challenge(token=bad_token)]))
    assert r.status_code == 422
    assert r.json()["error_type"] == "InvalidTokenError"


def test_token_padding_rejected_even_when_txt_absent():
    r = check(
        body(challenges=[challenge(token="aaa=")]),
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "InvalidTokenError"


# ---------- request-shape validation ----------

def test_duplicate_challenge_ids_is_422():
    r = check(body(challenges=[
        challenge("same", "a.example.com"), challenge("same", "b.example.com")
    ]))
    assert r.status_code == 422


def test_blank_challenge_id_is_422():
    r = check(body(challenges=[challenge("   ")]))
    assert r.status_code == 422


def test_more_than_20_challenges_is_422():
    chans = [
        challenge(f"c{i:02d}", f"h{i:02d}.example.com") for i in range(21)
    ]
    assert check(body(challenges=chans)).status_code == 422


def test_empty_challenges_is_422():
    assert check(body(challenges=[])).status_code == 422


def test_more_than_100_records_is_422():
    recs = [
        txt(f"_acme-challenge.h{i:03d}.example.com", ["v"]) for i in range(101)
    ]
    assert check(body(records=recs)).status_code == 422


def test_txt_chunks_must_be_present():
    r = client.post(
        "/v1/issuance/check-dns01",
        json={
            "jwk": RFC_JWK,
            "challenges": [challenge()],
            "records": [{"type": "TXT", "owner": qname_of("example.com")}],
        },
    )
    assert r.status_code == 422


def test_unknown_record_type_is_422():
    r = client.post(
        "/v1/issuance/check-dns01",
        json={
            "jwk": RFC_JWK,
            "challenges": [challenge()],
            "records": [{"type": "A", "owner": "example.com", "value": "192.0.2.1"}],
        },
    )
    assert r.status_code == 422


# ---------- engine-level sanity ----------

def test_prepared_index_is_immutable():
    snapshot = dns01.prepare_dns_records([
        txt(qname_of("example.com"), [expected_digest()])
    ])
    with pytest.raises(TypeError):
        snapshot.txt_map["new"] = ()  # type: ignore[index]


def test_expected_digest_is_base64url_sha256():
    digest = expected_digest()
    raw = base64.urlsafe_b64decode(digest + "=" * (-len(digest) % 4))
    assert len(raw) == 32
