"""End-to-end tests for POST /v1/authorize/rollout-window."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def caa(owner, tag, value="", flag=0):
    return {"type": "CAA", "owner": owner, "flag": flag, "tag": tag, "value": value}


def cname(owner, target):
    return {"type": "CNAME", "owner": owner, "target": target}


def rollout(body):
    return client.post("/v1/authorize/rollout-window", json=body)


def req(before, after, queries, stale_seconds=None):
    return {
        "before": before,
        "after": after,
        "queries": queries,
        "stale_seconds": stale_seconds or {},
    }


def query(qid, domain, ca="ca.net", wildcard=False):
    return {"id": qid, "domain": domain, "wildcard": wildcard, "ca": ca}


# ---------- no change / unchanged multisets ----------

def test_no_changes_returns_zero():
    recs = [caa("example.com", "issue", "letsencrypt.org")]
    r = rollout(req(recs, recs, [query("q", "www.example.com", "letsencrypt.org")]))
    assert r.status_code == 200
    assert r.json() == {
        "changed_owners": [],
        "safe_from": 0,
        "first_unsafe": None,
    }


def test_empty_snapshots_return_zero():
    r = rollout(req([], [], [query("q", "a.test")]))
    assert r.status_code == 200
    assert r.json() == {"changed_owners": [], "safe_from": 0, "first_unsafe": None}


def test_record_order_does_not_matter():
    before = [
        caa("example.com", "issue", "letsencrypt.org"),
        caa("example.com", "issue", "pki.goog"),
    ]
    after = [
        caa("example.com", "issue", "pki.goog"),
        caa("example.com", "issue", "letsencrypt.org"),
    ]
    r = rollout(req(before, after, [query("q", "example.com", "pki.goog")]))
    assert r.status_code == 200
    assert r.json() == {"changed_owners": [], "safe_from": 0, "first_unsafe": None}


def test_duplicate_records_change_multiset():
    # Two identical records vs one: the per-owner multiset changed even
    # though every query's verdict is unaffected.
    before = [caa("example.com", "issue", "ca.net")] * 2
    after = [caa("example.com", "issue", "ca.net")]
    r = rollout(
        req(before, after, [query("q", "example.com")], {"example.com": 3})
    )
    assert r.status_code == 200
    assert r.json() == {
        "changed_owners": ["example.com"],
        "safe_from": 0,
        "first_unsafe": None,
    }


# ---------- safe window computation ----------

def test_value_change_safe_after_expiry():
    r = rollout(
        req(
            [caa("example.com", "issue", "pki.goog")],
            [caa("example.com", "issue", "letsencrypt.org")],
            [
                query("q-le", "www.example.com", "letsencrypt.org"),
                query("q-goog", "www.example.com", "pki.goog"),
            ],
            {"example.com": 30},
        )
    )
    assert r.status_code == 200
    assert r.json() == {
        "changed_owners": ["example.com"],
        "safe_from": 30,
        "first_unsafe": {
            "old_owners": ["example.com"],
            "query_id": "q-le",
            "error": None,
        },
    }


def test_change_unseen_by_queries_safe_at_zero():
    r = rollout(
        req(
            [caa("example.com", "issue", "pki.goog")],
            [caa("example.com", "issue", "letsencrypt.org")],
            [query("q", "unrelated.net")],
            {"example.com": 10},
        )
    )
    assert r.status_code == 200
    assert r.json() == {
        "changed_owners": ["example.com"],
        "safe_from": 0,
        "first_unsafe": None,
    }


def test_added_owner_counts_with_empty_old_group():
    # The added www owner shadows the parent; its old group is the empty
    # set, so a stale mix resolves www.example.com at the parent and the
    # effective_owner differs even though authorized stays true.
    r = rollout(
        req(
            [caa("example.com", "issue", "letsencrypt.org")],
            [
                caa("example.com", "issue", "letsencrypt.org"),
                caa("www.example.com", "issue", "letsencrypt.org"),
            ],
            [query("q", "www.example.com", "letsencrypt.org")],
            {"www.example.com": 5},
        )
    )
    assert r.status_code == 200
    assert r.json() == {
        "changed_owners": ["www.example.com"],
        "safe_from": 5,
        "first_unsafe": {
            "old_owners": ["www.example.com"],
            "query_id": "q",
            "error": None,
        },
    }


def test_removed_owner_counts_as_changed():
    r = rollout(
        req(
            [caa("old.example.com", "issue", "")],
            [],
            [query("q", "old.example.com")],
            {"old.example.com": 7},
        )
    )
    assert r.status_code == 200
    assert r.json() == {
        "changed_owners": ["old.example.com"],
        "safe_from": 7,
        "first_unsafe": {
            "old_owners": ["old.example.com"],
            "query_id": "q",
            "error": None,
        },
    }


def test_multiple_owners_max_of_min_horizon():
    # {a} unsafe until 10, {b} unsafe until 60, {a,b} until min(10, 60);
    # the window closes at the maximum horizon, 60.
    r = rollout(
        req(
            [caa("a.test", "issue", ""), caa("b.test", "issue", "")],
            [caa("a.test", "issue", "ca.net"), caa("b.test", "issue", "ca.net")],
            [query("qa", "a.test"), query("qb", "b.test")],
            {"a.test": 10, "b.test": 60},
        )
    )
    assert r.status_code == 200
    body = r.json()
    assert body["changed_owners"] == ["a.test", "b.test"]
    assert body["safe_from"] == 60
    # mask order: {a} is the first unsafe combination
    assert body["first_unsafe"] == {
        "old_owners": ["a.test"],
        "query_id": "qa",
        "error": None,
    }


def test_joint_old_state_horizon_is_min():
    # Only the combination with *both* owners stale is unsafe: the old
    # CNAME chain a.test -> b.test reaches the authorizing set, while any
    # single-owner-old mix falls through to the denying parent. The
    # horizon is min(10, 50) = 10, not the largest lifetime.
    r = rollout(
        req(
            [
                cname("a.test", "b.test"),
                caa("b.test", "issue", "ca.net"),
                caa("test", "issue", ""),
            ],
            [caa("test", "issue", "")],
            [query("q", "a.test")],
            {"a.test": 10, "b.test": 50},
        )
    )
    assert r.status_code == 200
    assert r.json() == {
        "changed_owners": ["a.test", "b.test"],
        "safe_from": 10,
        "first_unsafe": {
            "old_owners": ["a.test", "b.test"],
            "query_id": "q",
            "error": None,
        },
    }


def test_alias_error_in_mixed_snapshot():
    # Old a->b plus new b->a forms a loop that neither snapshot has alone.
    r = rollout(
        req(
            [cname("a.test", "b.test")],
            [cname("b.test", "a.test")],
            [query("q", "a.test")],
            {"a.test": 20, "b.test": 40},
        )
    )
    assert r.status_code == 200
    assert r.json() == {
        "changed_owners": ["a.test", "b.test"],
        "safe_from": 20,
        "first_unsafe": {
            "old_owners": ["a.test"],
            "query_id": None,
            "error": "CNAMELoopError",
        },
    }


def test_wildcard_query_uses_issuewild():
    r = rollout(
        req(
            [caa("example.com", "issuewild", "pki.goog")],
            [caa("example.com", "issuewild", "letsencrypt.org")],
            [query("w", "example.com", "letsencrypt.org", wildcard=True)],
            {"example.com": 12},
        )
    )
    assert r.status_code == 200
    body = r.json()
    assert body["safe_from"] == 12
    assert body["first_unsafe"]["query_id"] == "w"


def test_boundary_lifetimes():
    before = [caa("a.test", "issue", "")]
    after = [caa("a.test", "issue", "ca.net")]
    queries = [query("q", "a.test")]
    r = rollout(req(before, after, queries, {"a.test": 1}))
    assert r.status_code == 200
    assert r.json()["safe_from"] == 1
    r = rollout(req(before, after, queries, {"a.test": 86400}))
    assert r.status_code == 200
    assert r.json()["safe_from"] == 86400


# ---------- stale_seconds mapping ----------

def test_stale_owner_names_normalized():
    r = rollout(
        req(
            [],
            [caa("www.example.com", "issue", "ca.net")],
            [query("q", "www.example.com")],
            {"WWW.EXAMPLE.COM.": 5},
        )
    )
    assert r.status_code == 200
    assert r.json()["changed_owners"] == ["www.example.com"]
    assert r.json()["safe_from"] == 5


def test_stale_mapping_missing_owner_422():
    r = rollout(
        req(
            [],
            [caa("a.test", "issue", "ca.net")],
            [query("q", "a.test")],
            {},
        )
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "CAAError"


def test_stale_mapping_extra_owner_422():
    # No changes at all, so the mapping must be empty.
    recs = [caa("a.test", "issue", "ca.net")]
    r = rollout(req(recs, recs, [query("q", "a.test")], {"a.test": 5}))
    assert r.status_code == 422
    assert r.json()["error_type"] == "CAAError"


def test_stale_mapping_wrong_owner_422():
    r = rollout(
        req(
            [],
            [caa("a.test", "issue", "ca.net")],
            [query("q", "a.test")],
            {"b.test": 5},
        )
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "CAAError"


def test_stale_owner_invalid_name_422():
    r = rollout(
        req(
            [],
            [caa("a.test", "issue", "ca.net")],
            [query("q", "a.test")],
            {"bad..name": 5},
        )
    )
    assert r.status_code == 422


def test_stale_owner_duplicate_after_normalization_422():
    r = rollout(
        req(
            [],
            [caa("a.test", "issue", "ca.net")],
            [query("q", "a.test")],
            {"a.test": 5, "A.TEST.": 6},
        )
    )
    assert r.status_code == 422


def test_stale_seconds_value_bounds_422():
    before = []
    after = [caa("a.test", "issue", "ca.net")]
    queries = [query("q", "a.test")]
    assert rollout(req(before, after, queries, {"a.test": 0})).status_code == 422
    assert (
        rollout(req(before, after, queries, {"a.test": 86401})).status_code == 422
    )


# ---------- count limits ----------

def test_too_many_changed_owners_422():
    after = [caa(f"h{i}.test", "issue", "ca.net") for i in range(9)]
    stale = {f"h{i}.test": 5 for i in range(9)}
    r = rollout(req([], after, [query("q", "h0.test")], stale))
    assert r.status_code == 422
    assert r.json()["error_type"] == "CAAError"


def test_queries_count_limits_422():
    after = [caa("a.test", "issue", "ca.net")]
    stale = {"a.test": 5}
    assert rollout(req([], after, [], stale)).status_code == 422
    thirteen = [query(f"q{i}", f"h{i}.test") for i in range(13)]
    assert rollout(req([], after, thirteen, stale)).status_code == 422


def test_duplicate_query_ids_422():
    r = rollout(
        req(
            [],
            [caa("a.test", "issue", "ca.net")],
            [query("q", "a.test"), query("q", "b.test")],
            {"a.test": 5},
        )
    )
    assert r.status_code == 422


def test_records_count_limits_422():
    recs = [caa(f"h{i:03d}.test", "issue", "ca.net") for i in range(101)]
    queries = [query("q", "h000.test")]
    assert rollout(req(recs, [], queries)).status_code == 422
    assert rollout(req([], recs, queries)).status_code == 422


# ---------- snapshot evaluation errors ----------

def test_all_old_alias_error_422():
    r = rollout(
        req(
            [cname("a.test", "b.test"), cname("b.test", "a.test")],
            [],
            [query("q", "a.test")],
        )
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_all_new_record_error_422():
    r = rollout(
        req(
            [],
            [cname("a.test", "b.test"), caa("a.test", "issue", "ca.net")],
            [query("q", "z.test")],
        )
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "MixedRecordsError"
