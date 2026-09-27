"""End-to-end tests for POST /v1/issuance/route."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def caa(owner, tag, value="", flag=0):
    return {"type": "CAA", "owner": owner, "flag": flag, "tag": tag, "value": value}


def cname(owner, target):
    return {"type": "CNAME", "owner": owner, "target": target}


def route(body):
    return client.post("/v1/issuance/route", json=body)


def body(cas, requests_, records=None):
    return {"cas": cas, "requests": requests_, "records": records or []}


LE = {"ca": "letsencrypt.org", "capacity": 2}
GOOG = {"ca": "pki.goog", "capacity": 2}
BOTH = [caa("example.com", "issue", "letsencrypt.org"),
        caa("example.com", "issue", "pki.goog")]


# ---------- happy paths ----------

def test_route_each_to_first_choice():
    r = route(
        body(
            [LE, GOOG],
            [
                {"id": "r1", "domain": "a.example.com",
                 "candidates": ["letsencrypt.org"]},
                {"id": "r2", "domain": "b.example.com",
                 "candidates": ["pki.goog"]},
            ],
            BOTH,
        )
    )
    assert r.status_code == 200
    data = r.json()
    assert data["assigned"] == 2
    assert [(x["id"], x["assigned_ca"], x["reason"]) for x in data["results"]] == [
        ("r1", "letsencrypt.org", None),
        ("r2", "pki.goog", None),
    ]
    assert data["usage"] == [
        {"ca": "letsencrypt.org", "capacity": 2, "used": 1},
        {"ca": "pki.goog", "capacity": 2, "used": 1},
    ]


def test_route_capacity_contention_pushes_to_second_candidate():
    # Both requests authorize both CAs. LE has capacity 1; r2 can only use
    # LE, so the maximum (2 assigned) is reached by giving r1 its second
    # candidate pki.goog and reserving LE for r2.
    r = route(
        body(
            [{"ca": "letsencrypt.org", "capacity": 1},
             {"ca": "pki.goog", "capacity": 2}],
            [
                {"id": "r1", "domain": "a.example.com",
                 "candidates": ["letsencrypt.org", "pki.goog"]},
                {"id": "r2", "domain": "b.example.com",
                 "candidates": ["letsencrypt.org"]},
            ],
            BOTH,
        )
    )
    data = r.json()
    assert data["assigned"] == 2
    assert [x["assigned_ca"] for x in data["results"]] == [
        "pki.goog", "letsencrypt.org"
    ]


def test_route_results_keep_input_order_even_when_unassigned():
    r = route(
        body(
            [{"ca": "letsencrypt.org", "capacity": 1}],
            [
                {"id": "first", "domain": "a.example.com",
                 "candidates": ["letsencrypt.org"]},
                {"id": "second", "domain": "b.example.com",
                 "candidates": ["letsencrypt.org"]},
            ],
            [caa("example.com", "issue", "letsencrypt.org")],
        )
    )
    data = r.json()
    assert data["assigned"] == 1
    assert [x["id"] for x in data["results"]] == ["first", "second"]
    assert data["results"][0]["assigned_ca"] == "letsencrypt.org"
    assert data["results"][1] == {
        "id": "second",
        "assigned_ca": None,
        "reason": "insufficient capacity for every authorized candidate",
    }
    assert data["usage"][0]["used"] == 1


def test_route_zero_capacity_ca_unusable():
    r = route(
        body(
            [{"ca": "a.net", "capacity": 0}, {"ca": "b.net", "capacity": 1}],
            [
                {"id": "x", "domain": "d.test", "candidates": ["a.net"]},
                {"id": "y", "domain": "d.test",
                 "candidates": ["a.net", "b.net"]},
            ],
            [caa("d.test", "issue", "a.net"), caa("d.test", "issue", "b.net")],
        )
    )
    data = r.json()
    assert data["assigned"] == 1
    assert data["results"][0] == {
        "id": "x",
        "assigned_ca": None,
        "reason": "insufficient capacity for every authorized candidate",
    }
    assert data["results"][1]["assigned_ca"] == "b.net"


def test_route_no_authorized_candidate():
    r = route(
        body(
            [{"ca": "letsencrypt.org", "capacity": 5}],
            [{"id": "r1", "domain": "www.example.com",
              "candidates": ["letsencrypt.org"]}],
            [caa("example.com", "issue", "pki.goog")],
        )
    )
    data = r.json()
    assert data["assigned"] == 0
    assert data["results"][0] == {
        "id": "r1",
        "assigned_ca": None,
        "reason": "no authorized candidate",
    }
    assert data["usage"][0]["used"] == 0


def test_route_wildcard_uses_issuewild():
    # issue allows LE but issuewild explicitly denies everyone; the
    # wildcard request therefore has no authorized candidate.
    r = route(
        body(
            [{"ca": "letsencrypt.org", "capacity": 3}],
            [{"id": "w", "domain": "example.com", "wildcard": True,
              "candidates": ["letsencrypt.org"]}],
            [
                caa("example.com", "issue", "letsencrypt.org"),
                caa("example.com", "issuewild", ""),
            ],
        )
    )
    assert r.json()["results"][0]["reason"] == "no authorized candidate"


def test_route_skips_unauthorized_candidate_but_keeps_later_one():
    # Only pki.goog is authorized; LE appears first in the candidate list
    # but must be skipped in favor of the later, authorized pki.goog.
    r = route(
        body(
            [{"ca": "letsencrypt.org", "capacity": 5},
             {"ca": "pki.goog", "capacity": 5}],
            [{"id": "r1", "domain": "www.example.com",
              "candidates": ["letsencrypt.org", "pki.goog"]}],
            [caa("example.com", "issue", "pki.goog")],
        )
    )
    data = r.json()
    assert data["assigned"] == 1
    assert data["results"][0]["assigned_ca"] == "pki.goog"


def test_route_tie_break_prefers_earlier_request_getting_first_choice():
    # Three requests, A cap 2 / B cap 1, all eligible for both. A solution
    # assigning r1->B reaches size 3; r1 must not waste its first choice
    # unless required, so the optimum is r1=B, r2=A, r3=A.
    r = route(
        body(
            [{"ca": "a.net", "capacity": 2}, {"ca": "b.net", "capacity": 1}],
            [
                {"id": "1", "domain": "d.test",
                 "candidates": ["a.net", "b.net"]},
                {"id": "2", "domain": "d.test", "candidates": ["a.net"]},
                {"id": "3", "domain": "d.test", "candidates": ["a.net"]},
            ],
            [caa("d.test", "issue", "a.net"), caa("d.test", "issue", "b.net")],
        )
    )
    assert [x["assigned_ca"] for x in r.json()["results"]] == [
        "b.net", "a.net", "a.net"
    ]


def test_route_cname_authorization_feeds_routing():
    r = route(
        body(
            [{"ca": "letsencrypt.org", "capacity": 1}],
            [{"id": "r1", "domain": "www.example.com",
              "candidates": ["letsencrypt.org"]}],
            [
                cname("www.example.com", "edge.cdn.example"),
                caa("edge.cdn.example", "issue", "letsencrypt.org"),
            ],
        )
    )
    assert r.status_code == 200
    assert r.json()["results"][0]["assigned_ca"] == "letsencrypt.org"


def test_route_normalizes_names_and_case():
    r = route(
        body(
            [{"ca": "LetsEncrypt.ORG.", "capacity": 1}],
            [{"id": "r1", "domain": "WWW.Example.Com.",
              "candidates": ["letsencrypt.org"]}],
            [caa("EXAMPLE.com.", "issue", "LETSENCRYPT.org.")],
        )
    )
    assert r.status_code == 200
    assert r.json()["results"][0]["assigned_ca"] == "letsencrypt.org"


def test_route_no_caa_records_authorizes_everyone():
    r = route(
        body(
            [{"ca": "a.net", "capacity": 1}, {"ca": "b.net", "capacity": 1}],
            [{"id": "r1", "domain": "d.test",
              "candidates": ["a.net", "b.net"]}],
            [],
        )
    )
    data = r.json()
    assert data["assigned"] == 1
    assert data["results"][0]["assigned_ca"] == "a.net"


# ---------- 422 validation ----------

def test_route_duplicate_ca_is_422():
    r = route(
        body(
            [{"ca": "a.net", "capacity": 1}, {"ca": "A.NET.", "capacity": 1}],
            [{"id": "r1", "domain": "d.test", "candidates": ["a.net"]}],
        )
    )
    assert r.status_code == 422


def test_route_duplicate_id_is_422():
    r = route(
        body(
            [{"ca": "a.net", "capacity": 2}],
            [
                {"id": "x", "domain": "d.test", "candidates": ["a.net"]},
                {"id": "x", "domain": "e.test", "candidates": ["a.net"]},
            ],
        )
    )
    assert r.status_code == 422


def test_route_blank_id_is_422():
    r = route(
        body(
            [{"ca": "a.net", "capacity": 1}],
            [{"id": "   ", "domain": "d.test", "candidates": ["a.net"]}],
        )
    )
    assert r.status_code == 422


def test_route_duplicate_candidate_is_422():
    r = route(
        body(
            [{"ca": "a.net", "capacity": 1}],
            [{"id": "r1", "domain": "d.test",
              "candidates": ["a.net", "A.NET."]}],
        )
    )
    assert r.status_code == 422


def test_route_candidate_not_in_cas_is_422():
    r = route(
        body(
            [{"ca": "a.net", "capacity": 1}],
            [{"id": "r1", "domain": "d.test",
              "candidates": ["a.net", "b.net"]}],
        )
    )
    assert r.status_code == 422


def test_route_empty_candidate_list_is_422():
    r = route(
        body(
            [{"ca": "a.net", "capacity": 1}],
            [{"id": "r1", "domain": "d.test", "candidates": []}],
        )
    )
    assert r.status_code == 422


def test_route_capacity_bounds_are_422():
    for cap in (-1, 13):
        r = route(
            body(
                [{"ca": "a.net", "capacity": cap}],
                [{"id": "r1", "domain": "d.test", "candidates": ["a.net"]}],
            )
        )
        assert r.status_code == 422, cap


def test_route_ca_and_request_counts_are_422():
    assert route(
        body(
            [{"ca": f"c{i}.net", "capacity": 1} for i in range(5)],
            [{"id": "r", "domain": "d.test", "candidates": ["c0.net"]}],
        )
    ).status_code == 422
    assert route(
        body(
            [{"ca": "a.net", "capacity": 1}],
            [{"id": f"r{i}", "domain": "d.test", "candidates": ["a.net"]}
             for i in range(13)],
        )
    ).status_code == 422
    assert route({"cas": [], "requests": []}).status_code == 422


def test_route_more_than_100_records_is_422():
    recs = [caa(f"h{i:03d}.example.com", "issue", "a.net") for i in range(101)]
    r = route(
        body(
            [{"ca": "a.net", "capacity": 1}],
            [{"id": "r1", "domain": "d.test", "candidates": ["a.net"]}],
            recs,
        )
    )
    assert r.status_code == 422


def test_route_bad_name_is_422():
    r = route(
        body(
            [{"ca": "a.net", "capacity": 1}],
            [{"id": "r1", "domain": "bad..com", "candidates": ["a.net"]}],
        )
    )
    assert r.status_code == 422


def test_route_bad_record_is_422():
    r = route(
        body(
            [{"ca": "a.net", "capacity": 1}],
            [{"id": "r1", "domain": "d.test", "candidates": ["a.net"]}],
            [caa("d.test", "issue", "a.net", flag=7)],
        )
    )
    assert r.status_code == 422


def test_route_cname_loop_is_422():
    r = route(
        body(
            [{"ca": "a.net", "capacity": 1}],
            [{"id": "r1", "domain": "x.test", "candidates": ["a.net"]}],
            [
                cname("x.test", "y.test"),
                cname("y.test", "x.test"),
            ],
        )
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_route_mixed_records_is_422():
    r = route(
        body(
            [{"ca": "a.net", "capacity": 1}],
            [{"id": "r1", "domain": "x.test", "candidates": ["a.net"]}],
            [
                cname("x.test", "z.test"),
                caa("x.test", "issue", "a.net"),
            ],
        )
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "MixedRecordsError"
