"""End-to-end tests for POST /v1/records/minimize."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def caa(owner, tag, value="", flag=0):
    return {"type": "CAA", "owner": owner, "flag": flag, "tag": tag, "value": value}


def cname(owner, target):
    return {"type": "CNAME", "owner": owner, "target": target}


def minimize(body):
    return client.post("/v1/records/minimize", json=body)


def req(records, queries):
    return {"records": records, "queries": queries}


# ---------- basic minimization ----------

def test_unrelated_record_is_removed():
    records = [
        caa("example.com", "issue", "letsencrypt.org"),
        caa("other.net", "issue", "ca.net"),
    ]
    r = minimize(
        req(records, [{"id": "q", "domain": "www.example.com", "ca": "letsencrypt.org"}])
    )
    assert r.status_code == 200
    body = r.json()
    assert body["kept"] == [0]
    assert body["removed"] == [1]
    assert body["records"] == [records[0]]
    assert body["queries"] == [
        {"id": "q", "authorized": True, "effective_owner": "example.com"}
    ]


def test_all_records_removable_when_no_caa_found():
    # The query never reaches the only record, so the empty subsequence
    # already reproduces the baseline (allowed, no effective owner).
    r = minimize(
        req(
            [caa("a.test", "issue", "")],
            [{"id": "q", "domain": "b.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 200
    body = r.json()
    assert body["kept"] == []
    assert body["removed"] == [0]
    assert body["records"] == []
    assert body["queries"] == [
        {"id": "q", "authorized": True, "effective_owner": None}
    ]


def test_effective_owner_must_be_preserved():
    # [0] alone still authorizes, but the effective owner moves to the
    # parent, so it is rejected; only [1] reproduces the baseline pair.
    r = minimize(
        req(
            [
                caa("example.com", "issue", "letsencrypt.org"),
                caa("www.example.com", "issue", "letsencrypt.org"),
            ],
            [{"id": "q", "domain": "www.example.com", "ca": "letsencrypt.org"}],
        )
    )
    body = r.json()
    assert body["kept"] == [1]
    assert body["removed"] == [0]
    assert body["queries"][0]["effective_owner"] == "www.example.com"


def test_cname_chain_fully_kept():
    # Dropping either record breaks the chain verdict, so nothing is removed.
    records = [
        cname("www.test", "edge.test"),
        caa("edge.test", "issue", "ca.net"),
    ]
    r = minimize(req(records, [{"id": "q", "domain": "www.test", "ca": "ca.net"}]))
    body = r.json()
    assert body["kept"] == [0, 1]
    assert body["removed"] == []
    assert body["records"] == records
    assert body["queries"] == [
        {"id": "q", "authorized": True, "effective_owner": "edge.test"}
    ]


# ---------- shortest-first and tie-breaking ----------

def test_tie_keeps_lexicographically_smallest_indices():
    # Two identical records are each sufficient on their own; [0] wins.
    r = minimize(
        req(
            [
                caa("example.com", "issue", "letsencrypt.org"),
                caa("example.com", "issue", "letsencrypt.org"),
            ],
            [{"id": "q", "domain": "example.com", "ca": "letsencrypt.org"}],
        )
    )
    body = r.json()
    assert body["kept"] == [0]
    assert body["removed"] == [1]


def test_earlier_mismatch_picks_first_valid_winner():
    # [0] is unrelated (verdict would lose the effective owner); [1] and
    # [2] both reproduce the baseline, so the lexicographically smaller
    # kept list [1] wins.
    r = minimize(
        req(
            [
                caa("other.net", "issue", "ca.net"),
                caa("example.com", "issue", "letsencrypt.org"),
                caa("example.com", "issue", "letsencrypt.org"),
            ],
            [{"id": "q", "domain": "example.com", "ca": "letsencrypt.org"}],
        )
    )
    body = r.json()
    assert body["kept"] == [1]
    assert body["removed"] == [0, 2]


def test_shortest_beats_longer_regardless_of_indices():
    # [2] alone suffices; [0, 2] and [1, 2] would also work but are longer.
    r = minimize(
        req(
            [
                caa("a.test", "issue", ""),
                caa("b.test", "issue", ""),
                caa("example.com", "issue", "letsencrypt.org"),
            ],
            [{"id": "q", "domain": "example.com", "ca": "letsencrypt.org"}],
        )
    )
    body = r.json()
    assert body["kept"] == [2]
    assert body["removed"] == [0, 1]


# ---------- erroring candidates are skipped ----------

def test_self_loop_candidate_is_skipped():
    # Candidate [0] sends the query into the self-referencing CNAME at
    # "test" and is skipped; [1] alone reproduces the baseline.
    r = minimize(
        req(
            [
                cname("test", "test"),
                caa("a.test", "issue", "ca.net"),
            ],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 200
    body = r.json()
    assert body["kept"] == [1]
    assert body["removed"] == [0]


def test_looping_chain_candidate_is_skipped():
    # The baseline query stops at the CAA on a.test and never sees the
    # x.test <-> y.test loop. The empty candidate walks the parent "test"
    # into that loop and is skipped; [0] is the answer.
    r = minimize(
        req(
            [
                caa("a.test", "issue", "ca.net"),
                cname("test", "x.test"),
                cname("x.test", "y.test"),
                cname("y.test", "x.test"),
            ],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 200
    body = r.json()
    assert body["kept"] == [0]
    assert body["removed"] == [1, 2, 3]


# ---------- multiple queries ----------

def test_all_queries_must_be_preserved():
    # [0] alone would flip the wildcard query (issuewild falls back to the
    # non-matching issue value); [1] alone keeps both verdicts.
    r = minimize(
        req(
            [
                caa("example.com", "issue", "letsencrypt.org"),
                caa("example.com", "issuewild", "pki.goog"),
            ],
            [
                {"id": "plain", "domain": "www.example.com", "ca": "letsencrypt.org"},
                {
                    "id": "wild",
                    "domain": "example.com",
                    "wildcard": True,
                    "ca": "pki.goog",
                },
            ],
        )
    )
    body = r.json()
    assert body["kept"] == [1]
    assert body["removed"] == [0]
    assert body["queries"] == [
        {"id": "plain", "authorized": True, "effective_owner": "example.com"},
        {"id": "wild", "authorized": True, "effective_owner": "example.com"},
    ]


def test_non_contiguous_kept_records_keep_original_order():
    # Record 0 (explicit deny) is required for the plain query's denial,
    # record 2 for the wildcard query's allowance; record 1 is unrelated.
    records = [
        caa("example.com", "issue", ""),
        caa("other.net", "issue", "ca.net"),
        caa("example.com", "issuewild", "pki.goog"),
    ]
    r = minimize(
        req(
            records,
            [
                {"id": "deny", "domain": "example.com", "ca": "letsencrypt.org"},
                {
                    "id": "wild",
                    "domain": "example.com",
                    "wildcard": True,
                    "ca": "pki.goog",
                },
            ],
        )
    )
    body = r.json()
    assert body["kept"] == [0, 2]
    assert body["removed"] == [1]
    assert body["records"] == [records[0], records[2]]
    assert body["queries"] == [
        {"id": "deny", "authorized": False, "effective_owner": "example.com"},
        {"id": "wild", "authorized": True, "effective_owner": "example.com"},
    ]


def test_unknown_critical_tag_verdict_preserved():
    # Baseline denies because of the unknown critical tag; [1] alone keeps
    # that denial (same owner), so the authorizing issue record is dropped.
    r = minimize(
        req(
            [
                caa("example.com", "issue", "letsencrypt.org"),
                caa("example.com", "oddtag", "some-value", flag=128),
            ],
            [{"id": "q", "domain": "example.com", "ca": "letsencrypt.org"}],
        )
    )
    body = r.json()
    assert body["kept"] == [1]
    assert body["removed"] == [0]
    assert body["queries"] == [
        {"id": "q", "authorized": False, "effective_owner": "example.com"}
    ]


# ---------- larger searches ----------

def test_full_cname_chain_all_records_needed():
    # An 8-hop CNAME chain ending in the authorizing CAA: every record is
    # essential, so the search walks all sizes up to the full set.
    records = [cname("www.test", "n1.test")]
    records += [cname(f"n{i}.test", f"n{i + 1}.test") for i in range(1, 8)]
    records += [caa("n8.test", "issue", "ca.net")]
    r = minimize(req(records, [{"id": "q", "domain": "www.test", "ca": "ca.net"}]))
    body = r.json()
    assert body["kept"] == list(range(9))
    assert body["removed"] == []
    assert body["queries"] == [
        {"id": "q", "authorized": True, "effective_owner": "n8.test"}
    ]


def test_twelve_records_and_queries_boundary():
    records = [caa(f"h{i}.test", "issue", "ca.net") for i in range(12)]
    queries = [
        {"id": f"q{i}", "domain": f"h{i}.other.net", "ca": "ca.net"}
        for i in range(12)
    ]
    r = minimize(req(records, queries))
    assert r.status_code == 200
    body = r.json()
    # No query ever reaches a record, so everything is removable.
    assert body["kept"] == []
    assert body["removed"] == list(range(12))
    assert body["records"] == []
    assert [q["id"] for q in body["queries"]] == [f"q{i}" for i in range(12)]


def test_all_twelve_records_needed():
    # Each query is denied by its own record; dropping any record flips
    # that query to allowed, so the full set is the only answer.
    records = [caa(f"h{i}.test", "issue", "ca.net") for i in range(12)]
    queries = [
        {"id": f"q{i}", "domain": f"h{i}.test", "ca": "other.net"}
        for i in range(12)
    ]
    r = minimize(req(records, queries))
    assert r.status_code == 200
    body = r.json()
    assert body["kept"] == list(range(12))
    assert body["removed"] == []
    assert body["records"] == records
    assert body["queries"] == [
        {"id": f"q{i}", "authorized": False, "effective_owner": f"h{i}.test"}
        for i in range(12)
    ]


# ---------- response shape ----------

def test_baseline_results_in_query_order():
    r = minimize(
        req(
            [
                caa("example.com", "issue", "letsencrypt.org"),
                caa("other.net", "issue", "ca.net"),
            ],
            [
                {"id": "a", "domain": "www.example.com", "ca": "letsencrypt.org"},
                {
                    "id": "b",
                    "domain": "example.com",
                    "wildcard": True,
                    "ca": "pki.goog",
                },
                {"id": "c", "domain": "unrelated.org", "ca": "ca.net"},
            ],
        )
    )
    assert r.status_code == 200
    body = r.json()
    assert body["kept"] == [0]
    assert body["queries"] == [
        {"id": "a", "authorized": True, "effective_owner": "example.com"},
        {"id": "b", "authorized": False, "effective_owner": "example.com"},
        {"id": "c", "authorized": True, "effective_owner": None},
    ]


def test_names_are_normalized_in_response():
    r = minimize(
        req(
            [
                {
                    "type": "CAA",
                    "owner": "Example.COM.",
                    "flag": 0,
                    "tag": "ISSUE",
                    "value": "LetsEncrypt.ORG.",
                },
                caa("other.net", "issue", "ca.net"),
            ],
            [{"id": "q", "domain": "WWW.Example.Com.", "ca": "LETSENCRYPT.ORG"}],
        )
    )
    assert r.status_code == 200
    body = r.json()
    assert body["kept"] == [0]
    assert body["records"] == [
        {
            "type": "CAA",
            "owner": "example.com",
            "flag": 0,
            "tag": "issue",
            "value": "letsencrypt.org",
        }
    ]
    assert body["queries"] == [
        {"id": "q", "authorized": True, "effective_owner": "example.com"}
    ]


# ---------- 422 validation ----------

def test_records_count_limits_422():
    query = [{"id": "q", "domain": "a.test", "ca": "ca.net"}]
    assert minimize(req([], query)).status_code == 422
    thirteen = [caa(f"h{i}.test", "issue", "ca.net") for i in range(13)]
    assert minimize(req(thirteen, query)).status_code == 422


def test_queries_count_limits_422():
    record = [caa("a.test", "issue", "ca.net")]
    assert minimize(req(record, [])).status_code == 422
    thirteen = [
        {"id": f"q{i}", "domain": f"h{i}.test", "ca": "ca.net"} for i in range(13)
    ]
    assert minimize(req(record, thirteen)).status_code == 422


def test_duplicate_query_ids_422():
    r = minimize(
        req(
            [caa("a.test", "issue", "ca.net")],
            [
                {"id": "q", "domain": "a.test", "ca": "ca.net"},
                {"id": "q", "domain": "b.test", "ca": "ca.net"},
            ],
        )
    )
    assert r.status_code == 422


def test_blank_query_id_is_422():
    r = minimize(
        req(
            [caa("a.test", "issue", "ca.net")],
            [{"id": "  ", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422


def test_baseline_alias_loop_is_422():
    r = minimize(
        req(
            [cname("a.test", "b.test"), cname("b.test", "a.test")],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_baseline_mixed_owner_is_422():
    r = minimize(
        req(
            [cname("a.test", "b.test"), caa("a.test", "issue", "ca.net")],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "MixedRecordsError"


def test_baseline_multiple_cname_is_422():
    r = minimize(
        req(
            [cname("a.test", "b.test"), cname("a.test", "c.test")],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "MultipleCNAMEError"


def test_invalid_record_flag_is_422():
    r = minimize(
        req(
            [caa("a.test", "issue", "ca.net", flag=1)],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422


def test_invalid_query_name_is_422():
    r = minimize(
        req(
            [caa("a.test", "issue", "ca.net")],
            [{"id": "q", "domain": "bad..name", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422
