"""End-to-end tests for POST /v1/records/export-zone."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

ORIGIN = "example.com."


def export_zone(records, origin=ORIGIN, default_ttl=3600):
    return client.post(
        "/v1/records/export-zone",
        json={"origin": origin, "default_ttl": default_ttl, "records": records},
    )


def import_zone(zone, origin=ORIGIN):
    return client.post(
        "/v1/records/import-zone", json={"origin": origin, "zone": zone}
    )


def caa(owner, value, flag=0, tag="issue"):
    return {"type": "CAA", "owner": owner, "flag": flag, "tag": tag, "value": value}


def cname(owner, target):
    return {"type": "CNAME", "owner": owner, "target": target}


def roundtrip(records, origin=ORIGIN, default_ttl=3600):
    """Export then re-import; return the imported records without ``line``."""
    r = export_zone(records, origin=origin, default_ttl=default_ttl)
    assert r.status_code == 200
    back = import_zone(r.json()["zone"], origin=origin)
    assert back.status_code == 200
    return [
        {k: v for k, v in rec.items() if k != "line"}
        for rec in back.json()["records"]
    ]


# ---------- happy paths ----------

def test_export_basic_zone_text():
    r = export_zone(
        [
            caa("example.com", "letsencrypt.org"),
            cname("www.example.com", "edge.cdn.example"),
        ]
    )
    assert r.status_code == 200
    assert r.json()["zone"] == (
        "$ORIGIN example.com.\n"
        "$TTL 3600\n"
        '@ IN CAA 0 issue "letsencrypt.org"\n'
        "www IN CNAME edge.cdn.example.\n"
    )


def test_export_response_shape():
    assert set(export_zone([]).json()) == {"zone"}


def test_export_empty_records_has_only_directives():
    assert export_zone([]).json()["zone"] == "$ORIGIN example.com.\n$TTL 3600\n"


def test_export_default_ttl_boundaries():
    ok_min = export_zone([], default_ttl=1)
    assert ok_min.status_code == 200
    assert ok_min.json()["zone"].splitlines()[1] == "$TTL 1"
    ok_max = export_zone([], default_ttl=86400)
    assert ok_max.status_code == 200
    assert ok_max.json()["zone"].splitlines()[1] == "$TTL 86400"


def test_export_subdomain_owner_uses_relative_name():
    r = export_zone([caa("a.b.example.com", "ca.net", tag="iodef")])
    assert r.json()["zone"].splitlines()[2] == 'a.b IN CAA 0 iodef "ca.net"'


def test_export_names_and_tags_normalized():
    r = export_zone(
        [caa("WWW.Example.Com.", "CA.Net.")],
        origin="EXAMPLE.COM.",
    )
    assert r.json()["zone"] == (
        "$ORIGIN example.com.\n"
        "$TTL 3600\n"
        'www IN CAA 0 issue "ca.net"\n'
    )


def test_export_preserves_input_order():
    records = [
        caa("example.com", "one.example", tag="iodef"),
        caa("a.example.com", "ca1.net"),
        caa("example.com", "two.example", tag="iodef"),
        caa("b.example.com", "ca2.net"),
        caa("example.com", "ca.net"),
    ]
    r = export_zone(records)
    assert r.status_code == 200
    assert r.json()["zone"].splitlines()[2:] == [
        '@ IN CAA 0 iodef "one.example"',
        'a IN CAA 0 issue "ca1.net"',
        '@ IN CAA 0 iodef "two.example"',
        'b IN CAA 0 issue "ca2.net"',
        '@ IN CAA 0 issue "ca.net"',
    ]
    assert roundtrip(records) == records


def test_export_flag_128_and_unknown_tag():
    records = [caa("example.com", "x", flag=128, tag="custtag")]
    r = export_zone(records)
    assert r.json()["zone"].splitlines()[2] == '@ IN CAA 128 custtag "x"'
    assert roundtrip(records) == records


def test_export_empty_value_is_quoted_empty():
    records = [caa("example.com", "")]
    r = export_zone(records)
    assert r.json()["zone"].splitlines()[2] == '@ IN CAA 0 issue ""'
    assert roundtrip(records) == records


def test_export_escapes_backslash_quote_semicolon():
    records = [caa("example.com", 'a\\b"c;d', tag="iodef")]
    r = export_zone(records)
    assert r.json()["zone"].splitlines()[2] == '@ IN CAA 0 iodef "a\\\\b\\"c\\;d"'
    assert roundtrip(records) == records


def test_export_control_characters_use_decimal_escape():
    records = [caa("example.com", "a\tb\nc\x01d\x7fe", tag="iodef")]
    r = export_zone(records)
    line = r.json()["zone"].splitlines()[2]
    assert line == '@ IN CAA 0 iodef "a\\009b\\010c\\001d\\127e"'
    assert roundtrip(records) == records


def test_export_value_with_spaces_and_parens_roundtrip():
    records = [caa("example.com", "mailto:a b(c)@x.net", tag="iodef")]
    r = export_zone(records)
    assert r.json()["zone"].splitlines()[2] == '@ IN CAA 0 iodef "mailto:a b(c)@x.net"'
    assert roundtrip(records) == records


def test_export_roundtrip_matches_normalized_input():
    raw = [
        {"type": "CAA", "owner": "EXAMPLE.com.", "flag": 0, "tag": "ISSUE", "value": "CA.Net."},
        {"type": "CNAME", "owner": "WWW.EXAMPLE.COM", "target": "Edge.CDN.Example."},
    ]
    assert roundtrip(raw) == [
        caa("example.com", "ca.net"),
        cname("www.example.com", "edge.cdn.example"),
    ]


def test_export_roundtrip_100_records():
    records = [caa(f"h{i}.example.com", "ca.net") for i in range(100)]
    assert roundtrip(records) == records


def test_export_roundtrip_then_authorize():
    records = [
        cname("www.example.com", "edge.example.com"),
        caa("edge.example.com", "letsencrypt.org"),
    ]
    zone = export_zone(records).json()["zone"]
    imported = import_zone(zone).json()["records"]
    r = client.post(
        "/v1/authorize",
        json={
            "domain": "www.example.com",
            "wildcard": False,
            "ca": "letsencrypt.org",
            "records": imported,
        },
    )
    assert r.status_code == 200
    assert r.json()["authorized"] is True
    assert r.json()["effective_owner"] == "edge.example.com"


def test_export_size_limit_counts_output_bytes():
    # "$ORIGIN example.com.\n$TTL 3600\n" is 31 bytes and the record line
    # adds 20 bytes around the value, so 65485 value bytes land on 64 KiB.
    ok = caa("example.com", "x" * 65485, tag="iodef")
    r = export_zone([ok])
    assert r.status_code == 200
    assert len(r.json()["zone"].encode("utf-8")) == 65536
    assert roundtrip([ok]) == [ok]

    too_big = caa("example.com", "x" * 65486, tag="iodef")
    r = export_zone([too_big])
    assert r.status_code == 422
    assert r.json()["error_type"] == "ZoneExportError"


# ---------- 422: origin ----------

def test_export_origin_must_be_absolute():
    r = export_zone([], origin="example.com")
    assert r.status_code == 422
    assert r.json()["error_type"] == "ZoneExportError"


def test_export_origin_name_validated():
    assert export_zone([], origin="bad..com.").status_code == 422
    assert export_zone([], origin=".").status_code == 422


# ---------- 422: owner outside the zone ----------

def test_export_owner_outside_origin_rejected():
    for owner in ("other.net", "notexample.com", "com", "example.com.evil.net"):
        r = export_zone([caa(owner, "ca.net")])
        assert r.status_code == 422, owner
        assert r.json()["error_type"] == "ZoneExportError"


def test_export_cname_owner_outside_origin_rejected():
    # the CNAME *target* may live anywhere; only the owner is constrained
    r = export_zone([cname("www.other.net", "edge.cdn.example")])
    assert r.status_code == 422
    assert r.json()["error_type"] == "ZoneExportError"


# ---------- 422: reused record validation ----------

def test_export_mixed_owner_rejected():
    r = export_zone([caa("example.com", "ca.net"), cname("example.com", "x.net")])
    assert r.status_code == 422
    assert r.json()["error_type"] == "MixedRecordsError"


def test_export_multiple_cnames_rejected():
    r = export_zone(
        [cname("www.example.com", "a.net"), cname("www.example.com", "b.net")]
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "MultipleCNAMEError"


def test_export_record_validation_reused():
    # flag outside 0/128 fails at the schema layer, like /v1/authorize
    assert export_zone([caa("example.com", "ca.net", flag=1)]).status_code == 422


# ---------- 422: value alphabet ----------

def test_export_non_ascii_value_rejected():
    for value in ("café.net", "用户@example.com", "€"):
        r = export_zone([caa("example.com", value, tag="iodef")])
        assert r.status_code == 422, value
        assert r.json()["error_type"] == "ZoneExportError"


# ---------- 422: limits ----------

def test_export_ttl_out_of_range():
    assert export_zone([], default_ttl=0).status_code == 422
    assert export_zone([], default_ttl=86401).status_code == 422
    assert export_zone([], default_ttl=-5).status_code == 422


def test_export_over_100_records_rejected():
    records = [caa(f"h{i}.example.com", "ca.net") for i in range(101)]
    assert export_zone(records).status_code == 422
