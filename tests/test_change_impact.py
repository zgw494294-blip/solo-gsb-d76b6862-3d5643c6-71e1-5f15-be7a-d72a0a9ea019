"""End-to-end tests for POST /v1/authorize/change-impact."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def caa(owner, tag, value="", flag=0):
    return {"type": "CAA", "owner": owner, "flag": flag, "tag": tag, "value": value}


def cname(owner, target):
    return {"type": "CNAME", "owner": owner, "target": target}


def impact(body):
    return client.post("/v1/authorize/change-impact", json=body)


def req(records, edits, queries):
    return {"records": records, "edits": edits, "queries": queries}


# ---------- basic flip reporting ----------

def test_add_flips_and_omits_unchanged_query():
    r = impact(
        req(
            [caa("example.com", "issue", "pki.goog")],
            [{"add": caa("www.example.com", "issue", "letsencrypt.org")}],
            [
                {"id": "flip", "domain": "www.example.com", "ca": "letsencrypt.org"},
                {"id": "same", "domain": "api.example.com", "ca": "pki.goog"},
            ],
        )
    )
    assert r.status_code == 200
    body = r.json()
    assert [f["id"] for f in body["flips"]] == ["flip"]
    flip = body["flips"][0]
    assert flip["before_authorized"] is False
    assert flip["after_authorized"] is True
    assert flip["before_effective_owner"] == "example.com"
    assert flip["after_effective_owner"] == "www.example.com"
    assert flip["minimal_edits"] == [0]


def test_remove_flips_to_allowed_no_effective_owner():
    r = impact(
        req(
            [caa("example.com", "issue", "")],
            [{"remove": 0}],
            [{"id": "q", "domain": "example.com", "ca": "letsencrypt.org"}],
        )
    )
    assert r.status_code == 200
    flip = r.json()["flips"][0]
    assert flip["before_authorized"] is False
    assert flip["after_authorized"] is True
    assert flip["before_effective_owner"] == "example.com"
    assert flip["after_effective_owner"] is None
    assert flip["minimal_edits"] == [0]


def test_allow_to_deny_flip():
    # The added closer-owner set shadows the authorizing parent and denies pki.
    r = impact(
        req(
            [caa("example.com", "issue", "letsencrypt.org")],
            [{"add": caa("www.example.com", "issue", "pki.goog")}],
            [{"id": "q", "domain": "www.example.com", "ca": "letsencrypt.org"}],
        )
    )
    flip = r.json()["flips"][0]
    assert flip["before_authorized"] is True
    assert flip["after_authorized"] is False
    assert flip["before_effective_owner"] == "example.com"
    assert flip["after_effective_owner"] == "www.example.com"
    assert flip["minimal_edits"] == [0]


def test_no_flips_returns_empty_list():
    r = impact(
        req(
            [caa("example.com", "issue", "letsencrypt.org")],
            [{"add": caa("www.example.com", "iodef", "http://rpt.example")}],
            [
                {"id": "a", "domain": "a.example.com", "ca": "letsencrypt.org"},
                {"id": "b", "domain": "www.example.com", "ca": "letsencrypt.org"},
            ],
        )
    )
    assert r.status_code == 200
    assert r.json() == {"flips": []}


def test_flips_keep_query_order():
    r = impact(
        req(
            [caa("example.com", "issue", "pki.goog")],
            [{"add": caa("www.example.com", "issue", "letsencrypt.org")}],
            [
                {"id": "q1", "domain": "a.example.com", "ca": "letsencrypt.org"},
                {"id": "q2", "domain": "www.example.com", "ca": "letsencrypt.org"},
                {"id": "q3", "domain": "www.example.com", "ca": "pki.goog"},
            ],
        )
    )
    # q1 denied before and after; q2 deny->allow; q3 allow->deny
    assert [f["id"] for f in r.json()["flips"]] == ["q2", "q3"]
    q3 = r.json()["flips"][1]
    assert q3["before_authorized"] is True
    assert q3["after_authorized"] is False


def test_wildcard_query_flip():
    r = impact(
        req(
            [caa("example.com", "issuewild", "pki.goog")],
            [{"add": caa("example.com", "issuewild", "letsencrypt.org")}],
            [
                {
                    "id": "w",
                    "domain": "example.com",
                    "wildcard": True,
                    "ca": "letsencrypt.org",
                }
            ],
        )
    )
    flip = r.json()["flips"][0]
    assert flip["before_authorized"] is False
    assert flip["after_authorized"] is True
    assert flip["minimal_edits"] == [0]


# ---------- edits applied together ----------

def test_removals_use_original_indices():
    r = impact(
        req(
            [
                caa("a.test", "issue", ""),
                caa("b.test", "issue", ""),
                caa("c.test", "issue", ""),
            ],
            [{"remove": 0}, {"remove": 2}],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    # new record set only keeps b.test; a.test finds no CAA anywhere -> allowed
    flip = r.json()["flips"][0]
    assert flip["after_authorized"] is True
    assert flip["after_effective_owner"] is None
    # removing index 0 alone already reproduces the new verdict
    assert flip["minimal_edits"] == [0]


def test_adds_appended_in_edit_order():
    # Two adds at the same owner both survive; the authorizing value is the
    # second added record.
    r = impact(
        req(
            [caa("example.com", "issue", "pki.goog")],
            [
                {"add": caa("www.example.com", "issue", "pki.goog")},
                {"add": caa("www.example.com", "issue", "letsencrypt.org")},
            ],
            [{"id": "q", "domain": "www.example.com", "ca": "letsencrypt.org"}],
        )
    )
    flip = r.json()["flips"][0]
    assert flip["after_authorized"] is True
    assert flip["after_effective_owner"] == "www.example.com"
    # only edit 1 names letsencrypt.org, so it alone reproduces the verdict
    assert flip["minimal_edits"] == [1]


def test_cname_replacement_full_chain():
    # Baseline aliases www to a denying target; the parent also denies, so
    # dropping the alias alone cannot authorize. The new alias chain must be
    # built end to end (only [0,1] is reached: that subset allows by CAA
    # absence, which already reproduces the new verdict).
    r = impact(
        req(
            [
                cname("www.test", "deny.net"),
                caa("deny.net", "issue", ""),
                caa("test", "issue", ""),
            ],
            [
                {"remove": 0},
                {"add": cname("www.test", "allow.net")},
                {"add": caa("allow.net", "issue", "letsencrypt.org")},
            ],
            [{"id": "q", "domain": "www.test", "ca": "letsencrypt.org"}],
        )
    )
    flip = r.json()["flips"][0]
    assert flip["before_authorized"] is False
    assert flip["after_authorized"] is True
    assert flip["before_effective_owner"] == "deny.net"
    assert flip["after_effective_owner"] == "allow.net"
    assert flip["minimal_edits"] == [0, 1]


# ---------- minimal subset selection ----------

def test_tie_chooses_lexicographically_smallest():
    # Two individually sufficient, identical adds; edit 0 wins.
    r = impact(
        req(
            [caa("example.com", "issue", "pki.goog")],
            [
                {"add": caa("www.example.com", "issue", "letsencrypt.org")},
                {"add": caa("www.example.com", "issue", "letsencrypt.org")},
            ],
            [{"id": "q", "domain": "www.example.com", "ca": "letsencrypt.org"}],
        )
    )
    assert r.json()["flips"][0]["minimal_edits"] == [0]


def test_single_edit_beats_pair_regardless_of_indices():
    # Edit 1 flips by itself; [0, 2] also flips but is larger.
    r = impact(
        req(
            [caa("www.example.com", "issue", "pki.goog")],
            [
                {"add": caa("www.example.com", "iodef", "http://rpt.example")},
                {"add": caa("www.example.com", "issue", "letsencrypt.org")},
            ],
            [{"id": "q", "domain": "www.example.com", "ca": "letsencrypt.org"}],
        )
    )
    assert r.json()["flips"][0]["minimal_edits"] == [1]


def test_invalid_mixed_subset_is_skipped():
    # [1] alone mixes CAA and CNAME at a.test -> invalid, skipped;
    # [0] alone still loses to the denying parent test; the pair flips.
    r = impact(
        req(
            [
                cname("a.test", "b.test"),
                caa("test", "issue", ""),
            ],
            [
                {"remove": 0},
                {"add": caa("a.test", "issue", "letsencrypt.org")},
            ],
            [{"id": "q", "domain": "a.test", "ca": "letsencrypt.org"}],
        )
    )
    flip = r.json()["flips"][0]
    assert flip["before_authorized"] is False
    assert flip["after_authorized"] is True
    assert flip["minimal_edits"] == [0, 1]


def test_looped_and_oversized_subsets_skipped():
    # [0,1] forms a CNAME loop for the query -> skipped; [1] alone adds a
    # second CNAME at c.test -> multiple CNAMEs -> skipped; [0,3] valid and
    # flips, but [0] alone still hits the denying parent, so [0,3] is minimal.
    r = impact(
        req(
            [
                cname("a.test", "b.test"),
                caa("b.test", "issue", "pki.goog"),
                caa("test", "issue", "pki.goog"),
            ],
            [
                {"remove": 0},
                {"add": cname("c.test", "d.test")},
                {"add": cname("d.test", "c.test")},
                {"add": caa("a.test", "issue", "letsencrypt.org")},
            ],
            [{"id": "q", "domain": "a.test", "ca": "letsencrypt.org"}],
        )
    )
    flip = r.json()["flips"][0]
    assert flip["before_authorized"] is False
    assert flip["after_authorized"] is True
    assert flip["minimal_edits"] == [0, 3]


def test_oversized_subset_skipped_pair_required():
    # 100 baseline records. Subset [1] alone would be 101 records -> skipped;
    # [0] alone removes h00's set, so h00.test climbs to test, which has no
    # CAA -> pki authorized (does not reproduce the new denial); the pair
    # keeps the count at 100 and replaces h00's set with an other.net one.
    recs = [caa(f"h{i:02d}.test", "issue", "pki.goog") for i in range(100)]
    r = impact(
        req(
            recs,
            [
                {"remove": 0},
                {"add": caa("h00.test", "issue", "other.net")},
            ],
            [{"id": "q", "domain": "h00.test", "ca": "pki.goog"}],
        )
    )
    flip = r.json()["flips"][0]
    assert flip["before_authorized"] is True
    assert flip["after_authorized"] is False
    assert flip["minimal_edits"] == [0, 1]


# ---------- 422 validation ----------

def test_duplicate_remove_indices_422():
    r = impact(
        req(
            [caa("a.test", "issue", ""), caa("b.test", "issue", "")],
            [{"remove": 0}, {"remove": 0}],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422


def test_remove_out_of_range_422():
    r = impact(
        req(
            [caa("a.test", "issue", "")],
            [{"remove": 1}],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422


def test_edit_without_action_422():
    r = impact(
        req(
            [],
            [{}],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422


def test_edit_with_both_actions_422():
    r = impact(
        req(
            [],
            [
                {
                    "remove": 0,
                    "add": caa("a.test", "issue", "ca.net"),
                }
            ],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422


def test_duplicate_query_ids_422():
    r = impact(
        req(
            [],
            [{"add": caa("a.test", "issue", "")}],
            [
                {"id": "q", "domain": "a.test", "ca": "ca.net"},
                {"id": "q", "domain": "b.test", "ca": "ca.net"},
            ],
        )
    )
    assert r.status_code == 422


def test_edits_count_limits_422():
    query = [{"id": "q", "domain": "a.test", "ca": "ca.net"}]
    assert impact(req([], [], query)).status_code == 422
    nine = [{"add": caa(f"h{i}.test", "issue", "ca.net")} for i in range(9)]
    assert impact(req([], nine, query)).status_code == 422


def test_queries_count_limits_422():
    edit = [{"add": caa("a.test", "issue", "")}]
    assert impact(req([], edit, [])).status_code == 422
    twenty_one = [
        {"id": f"q{i}", "domain": f"h{i}.test", "ca": "ca.net"} for i in range(21)
    ]
    assert impact(req([], edit, twenty_one)).status_code == 422


def test_more_than_100_baseline_records_422():
    recs = [caa(f"h{i:03d}.test", "issue", "ca.net") for i in range(101)]
    r = impact(
        req(
            recs,
            [{"add": caa("z.test", "issue", "ca.net")}],
            [{"id": "q", "domain": "z.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422


def test_more_than_100_records_after_edits_422():
    recs = [caa(f"h{i:03d}.test", "issue", "ca.net") for i in range(100)]
    r = impact(
        req(
            recs,
            [{"add": caa("z.test", "issue", "ca.net")}],
            [{"id": "q", "domain": "z.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "CAAError"


def test_baseline_alias_loop_is_422():
    r = impact(
        req(
            [cname("a.test", "b.test"), cname("b.test", "a.test")],
            [{"add": caa("z.test", "issue", "ca.net")}],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_new_version_alias_loop_is_422():
    r = impact(
        req(
            [cname("a.test", "b.test")],
            [{"add": cname("b.test", "a.test")}],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_new_version_mixed_owner_is_422():
    r = impact(
        req(
            [cname("a.test", "b.test")],
            [{"add": caa("a.test", "issue", "ca.net")}],
            [{"id": "q", "domain": "z.test", "ca": "ca.net"}],
        )
    )
    # Querying z.test still builds the whole index, so the mixed owner in
    # the new record set is rejected.
    assert r.status_code == 422
    assert r.json()["error_type"] == "MixedRecordsError"


def test_invalid_added_record_is_422():
    r = impact(
        req(
            [],
            [{"add": caa("a.test", "issue", "ca.net;account=uri")}],
            [{"id": "q", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422


def test_blank_query_id_is_422():
    r = impact(
        req(
            [],
            [{"add": caa("a.test", "issue", "ca.net")}],
            [{"id": "  ", "domain": "a.test", "ca": "ca.net"}],
        )
    )
    assert r.status_code == 422
