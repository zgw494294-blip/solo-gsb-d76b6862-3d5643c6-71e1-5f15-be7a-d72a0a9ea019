"""End-to-end tests for POST /v1/records/import-zone."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def import_zone(zone, origin="example.com."):
    return client.post(
        "/v1/records/import-zone", json={"origin": origin, "zone": zone}
    )


def authorize(records, domain="www.example.com", ca="letsencrypt.org"):
    return client.post(
        "/v1/authorize",
        json={"domain": domain, "wildcard": False, "ca": ca, "records": records},
    )


# ---------- happy paths ----------

def test_import_basic():
    zone = (
        "$ORIGIN example.com.\n"
        "$TTL 3600\n"
        "@     IN CAA 0 issue \"letsencrypt.org\"\n"
        "www   IN CNAME edge.cdn.example.\n"
    )
    r = import_zone(zone)
    assert r.status_code == 200
    body = r.json()
    assert body["origin"] == "example.com"
    assert body["count"] == 2
    assert body["records"] == [
        {
            "line": 3,
            "type": "CAA",
            "owner": "example.com",
            "flag": 0,
            "tag": "issue",
            "value": "letsencrypt.org",
        },
        {
            "line": 4,
            "type": "CNAME",
            "owner": "www.example.com",
            "target": "edge.cdn.example",
        },
    ]


def test_import_uses_request_origin_by_default():
    r = import_zone("@ CAA 0 issue \"ca.net\"\nwww CNAME @\n")
    body = r.json()
    assert body["records"][0]["owner"] == "example.com"
    assert body["records"][1]["owner"] == "www.example.com"
    assert body["records"][1]["target"] == "example.com"


def test_import_relative_and_absolute_names():
    zone = (
        "www CNAME edge\n"  # relative target
        "api CNAME edge.cdn.example.\n"  # absolute target
        "edge.cdn.example. CAA 0 issue \"ca.net\"\n"  # absolute owner
    )
    body = import_zone(zone).json()
    assert body["records"][0]["target"] == "edge.example.com"
    assert body["records"][1]["target"] == "edge.cdn.example"
    assert body["records"][2]["owner"] == "edge.cdn.example"


def test_import_origin_directive_switches_expansion():
    zone = (
        "@ CAA 0 issue \"one.example\"\n"
        "$ORIGIN sub.example.com.\n"
        "@ CAA 0 issue \"two.example\"\n"
        "api CNAME @\n"
        "$ORIGIN other.net.\n"
        "www CNAME www2\n"
    )
    body = import_zone(zone).json()
    owners = [rec["owner"] for rec in body["records"]]
    assert owners == [
        "example.com",
        "sub.example.com",
        "api.sub.example.com",
        "www.other.net",
    ]
    assert body["records"][2]["target"] == "sub.example.com"
    assert body["records"][3]["target"] == "www2.other.net"


def test_import_origin_directive_relative_argument():
    r = import_zone("$ORIGIN sub\n@ CAA 0 issue \"ca.net\"\n")
    assert r.json()["records"][0]["owner"] == "sub.example.com"


def test_import_ttl_and_class_before_type_any_order():
    zone = (
        "a 3600 IN CAA 0 issue \"ca.net\"\n"
        "b IN 3600 CAA 0 issue \"ca.net\"\n"
        "c CAA 0 issue \"ca.net\"\n"
        "d 1h30m IN CAA 0 issue \"ca.net\"\n"
    )
    body = import_zone(zone).json()
    assert [rec["owner"] for rec in body["records"]] == [
        "a.example.com",
        "b.example.com",
        "c.example.com",
        "d.example.com",
    ]


def test_import_keywords_case_insensitive():
    zone = "@ in caa 0 ISSUE \"CA.Net\"\n$origin Sub.Example.Com.\n@ CAA 0 issue \"x.net\"\n"
    body = import_zone(zone).json()
    assert body["records"][0]["owner"] == "example.com"
    assert body["records"][0]["tag"] == "issue"
    assert body["records"][0]["value"] == "ca.net"
    assert body["records"][1]["owner"] == "sub.example.com"


def test_import_indented_lines_inherit_owner():
    zone = (
        "www 300 IN A 192.0.2.1\n"
        "     IN CAA 0 issue \"letsencrypt.org\"\n"
        "\tCAA 128 issue \"other.net\"\n"
    )
    body = import_zone(zone).json()
    assert body["count"] == 2
    assert body["records"][0]["owner"] == "www.example.com"
    assert body["records"][0]["line"] == 2
    assert body["records"][1]["owner"] == "www.example.com"
    assert body["records"][1]["flag"] == 128


def test_import_other_types_not_exported_but_update_inherited_owner():
    zone = (
        "@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n"
        "@ IN NS ns1\n"
        "www 300 IN A 192.0.2.1\n"
        "       IN CAA 0 issue \"ca.net\"\n"
    )
    body = import_zone(zone).json()
    assert body["count"] == 1
    # the CAA record inherits www.example.com from the skipped A record
    assert body["records"][0]["owner"] == "www.example.com"
    assert body["records"][0]["line"] == 4


def test_import_inheritance_survives_blank_and_comment_lines():
    zone = (
        "www 300 IN A 192.0.2.1\n"
        "; a comment\n"
        "\n"
        "   IN CAA 0 issue \"ca.net\"\n"
    )
    body = import_zone(zone).json()
    assert body["records"][0]["owner"] == "www.example.com"
    assert body["records"][0]["line"] == 4


def test_import_parentheses_span_lines():
    zone = (
        "@ IN CAA 0 issue ( \"letsencrypt.org\" )\n"
        "www IN CNAME (\n"
        "    edge.cdn.example.\n"
        ")\n"
    )
    body = import_zone(zone).json()
    assert body["count"] == 2
    assert body["records"][0]["line"] == 1
    assert body["records"][0]["value"] == "letsencrypt.org"
    assert body["records"][1]["line"] == 2
    assert body["records"][1]["target"] == "edge.cdn.example"


def test_import_parentheses_with_comments_inside():
    zone = "@ CAA 0 issue ( ; opening comment\n  \"ca.net\" ) ; trailing\n"
    body = import_zone(zone).json()
    assert body["records"][0]["value"] == "ca.net"


def test_import_semicolon_in_quotes_is_not_comment():
    zone = '@ CAA 0 iodef "mailto:ops@example.com;cc=sec" ; real comment\n'
    body = import_zone(zone).json()
    assert body["records"][0]["value"] == "mailto:ops@example.com;cc=sec"


def test_import_escaped_semicolon_is_not_comment():
    zone = "@ CAA 0 iodef mailto:a\\;b@example.com\n"
    body = import_zone(zone).json()
    assert body["records"][0]["value"] == "mailto:a;b@example.com"


def test_import_escaped_quotes_and_backslash():
    zone = '@ CAA 0 iodef "say \\"hi\\" \\\\ end"\n'
    body = import_zone(zone).json()
    assert body["records"][0]["value"] == 'say "hi" \\ end'


def test_import_decimal_escape():
    # \097 is 'a', \046 is '.'
    zone = "www CNAME \\097pi\\046cdn\n"
    body = import_zone(zone).json()
    assert body["records"][0]["target"] == "api.cdn.example.com"


def test_import_empty_quoted_value():
    body = import_zone('@ CAA 0 issue ""\n').json()
    assert body["records"][0]["value"] == ""


def test_import_crlf_line_endings():
    zone = "@ CAA 0 issue \"ca.net\"\r\nwww CNAME edge\r\n"
    body = import_zone(zone).json()
    assert [rec["line"] for rec in body["records"]] == [1, 2]


def test_import_empty_zone():
    body = import_zone("").json()
    assert body["count"] == 0
    assert body["records"] == []


def test_import_response_has_no_null_fields():
    body = import_zone("www CNAME edge\n").json()
    assert set(body["records"][0]) == {"line", "type", "owner", "target"}


def test_imported_records_feed_authorize_directly():
    zone = (
        "$ORIGIN example.com.\n"
        "www 300 IN CNAME edge.cdn.example.\n"
        "edge.cdn.example. CAA 0 issue \"letsencrypt.org\"\n"
    )
    records = import_zone(zone).json()["records"]
    r = authorize(records)
    assert r.status_code == 200
    body = r.json()
    assert body["authorized"] is True
    assert body["effective_owner"] == "edge.cdn.example"


def test_imported_full_zone_feeds_authorize():
    zone = (
        "$TTL 3600\n"
        "@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n"
        "@ IN NS ns1\n"
        "@ IN MX 10 mail\n"
        "@ CAA 0 issue \"letsencrypt.org\" ; primary CA\n"
        "@ CAA 0 iodef \"mailto:sec@example.com\"\n"
    )
    records = import_zone(zone).json()["records"]
    r = authorize(records, domain="example.com")
    assert r.status_code == 200
    assert r.json()["authorized"] is True


# ---------- 422: origin ----------

def test_import_origin_must_be_absolute():
    r = import_zone("@ CAA 0 issue \"ca.net\"\n", origin="example.com")
    assert r.status_code == 422
    assert r.json()["error_type"] == "ZoneImportError"


def test_import_origin_name_validated():
    assert import_zone("", origin="bad..com.").status_code == 422
    assert import_zone("", origin=".").status_code == 422


# ---------- 422: directives ----------

def test_import_include_and_generate_rejected():
    for zone in ("$INCLUDE other.zone\n", "$GENERATE 1-9 $ CAA 0 issue \"x\"\n"):
        r = import_zone(zone)
        assert r.status_code == 422, zone
        assert r.json()["error_type"] == "ZoneImportError"
        assert r.json()["line"] == 1


def test_import_unknown_directive():
    r = import_zone("$FOO bar\n")
    assert r.status_code == 422
    assert r.json()["line"] == 1


def test_import_bad_directive_arguments():
    assert import_zone("$ORIGIN\n").status_code == 422
    assert import_zone("$ORIGIN a. b.\n").status_code == 422
    assert import_zone("$TTL\n").status_code == 422
    assert import_zone("$TTL soon\n").status_code == 422
    assert import_zone("$TTL 3600 7200\n").status_code == 422


# ---------- 422: owner inheritance ----------

def test_import_undefined_inherited_owner():
    r = import_zone("   CAA 0 issue \"ca.net\"\n")
    assert r.status_code == 422
    assert r.json()["line"] == 1


def test_import_undefined_inherited_owner_after_directives():
    # directives do not establish an inheritable owner
    r = import_zone("$TTL 3600\n$ORIGIN example.com.\n  CAA 0 issue \"x\"\n")
    assert r.status_code == 422
    assert r.json()["line"] == 3


# ---------- 422: syntax ----------

def test_import_unbalanced_parentheses():
    r = import_zone("@ CAA 0 issue ( \"x\"\n")
    assert r.status_code == 422
    assert r.json()["line"] == 1
    r = import_zone("@ CAA 0 issue \"x\" )\n")
    assert r.status_code == 422
    assert r.json()["line"] == 1


def test_import_unterminated_quote():
    r = import_zone('@ CAA 0 issue "x\n')
    assert r.status_code == 422
    assert r.json()["line"] == 1


def test_import_dangling_backslash():
    assert import_zone("@ CAA 0 issue x\\\n").status_code == 422
    assert import_zone("@ CAA 0 issue x\\").status_code == 422


def test_import_missing_type():
    r = import_zone("www 3600 IN\n")
    assert r.status_code == 422
    assert r.json()["line"] == 1


def test_import_caa_wrong_arity():
    assert import_zone("@ CAA 0 issue\n").status_code == 422
    assert import_zone('@ CAA 0 issue "a" "b"\n').status_code == 422


def test_import_cname_wrong_arity():
    assert import_zone("www CNAME\n").status_code == 422
    assert import_zone("www CNAME a b\n").status_code == 422


def test_import_bad_flag_syntax():
    assert import_zone('@ CAA x issue "a"\n').status_code == 422
    assert import_zone('@ CAA 300 issue "a"\n').status_code == 422


# ---------- 422: reused record/name validation ----------

def test_import_record_validation_error_carries_line():
    zone = '@ CAA 0 issue "ca.net"\n@ CAA 1 issue "ca.net"\n'
    r = import_zone(zone)
    assert r.status_code == 422
    assert r.json()["line"] == 2
    assert "flag" in r.json()["detail"]


def test_import_owner_name_validation_error_carries_line():
    r = import_zone('bad..name CAA 0 issue "ca.net"\n')
    assert r.status_code == 422
    assert r.json()["line"] == 1


def test_import_cname_target_validation_error_carries_line():
    r = import_zone("www CNAME bad..target\n")
    assert r.status_code == 422
    assert r.json()["line"] == 1


def test_import_issue_value_with_params_rejected():
    r = import_zone('@ CAA 0 issue "ca.net; account=uri"\n')
    assert r.status_code == 422
    assert r.json()["line"] == 1


def test_import_validation_error_in_multiline_record_reports_start_line():
    zone = '@ CAA 0 issue (\n  "ca.net; x=1"\n)\n'
    r = import_zone(zone)
    assert r.status_code == 422
    assert r.json()["line"] == 1


# ---------- 422: limits ----------

def test_import_over_100_records_rejected():
    zone = "".join(f'h{i} CAA 0 issue "ca.net"\n' for i in range(101))
    r = import_zone(zone)
    assert r.status_code == 422
    assert r.json()["line"] == 101


def test_import_exactly_100_records_ok():
    zone = "".join(f'h{i} CAA 0 issue "ca.net"\n' for i in range(100))
    r = import_zone(zone)
    assert r.status_code == 200
    assert r.json()["count"] == 100


def test_import_zone_size_limit():
    ok = ";" + "x" * 65534 + "\n"  # exactly 65536 bytes
    assert import_zone(ok).status_code == 200
    too_big = ";" + "x" * 65535 + "\n"  # 65537 bytes
    r = import_zone(too_big)
    assert r.status_code == 422
    assert r.json()["error_type"] == "ZoneImportError"


def test_import_size_limit_counts_utf8_bytes():
    ok = ";" + "é" * 32767 + "\n"  # 1 + 2*32767 + 1 = 65536 bytes
    assert import_zone(ok).status_code == 200
    too_big = ";" + "é" * 32768 + "\n"  # 65538 bytes
    assert import_zone(too_big).status_code == 422
