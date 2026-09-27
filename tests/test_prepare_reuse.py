"""Regression tests: batch searches must not re-prepare a record group.

Within one request, each baseline, new-version or candidate record group
may go through ``app.engine.prepare_records`` at most once; when the
search revisits a group it already prepared — the full edit subset in
change-impact, the full subsequence in minimize, the all-old / all-new
combinations in rollout-window, or a candidate shared by several search
rounds — the cached snapshot (or the cached preparation failure) is
reused. The responses themselves must stay exactly as before.
"""

import pytest
from fastapi.testclient import TestClient

import app.engine as engine
from app.main import app

client = TestClient(app)


def caa(owner, tag, value="", flag=0):
    return {"type": "CAA", "owner": owner, "flag": flag, "tag": tag, "value": value}


def cname(owner, target):
    return {"type": "CNAME", "owner": owner, "target": target}


def fingerprint(records):
    """Content key identifying a record group, mirroring the engine's."""
    return tuple(tuple(sorted(rec.items())) for rec in records)


@pytest.fixture
def prepare_calls(monkeypatch):
    """Spy on engine.prepare_records, recording each prepared group."""
    calls = []
    real_prepare = engine.prepare_records

    def spy(records):
        calls.append(fingerprint(records))
        return real_prepare(records)

    monkeypatch.setattr(engine, "prepare_records", spy)
    return calls


# ---------- /v1/authorize/change-impact ----------

def test_change_impact_full_edit_set_reuses_new_version_snapshot(prepare_calls):
    # Only the full edit set flips the query: [0] alone still denies via
    # the parent test, [1] alone stacks a second CNAME on www.test
    # (invalid, skipped), so the search enumerates the full set — which
    # is exactly the already-prepared new record set.
    records = [
        cname("www.test", "deny.test"),
        caa("deny.test", "issue", ""),
        caa("allow.test", "issue", "ca.net"),
        caa("test", "issue", ""),
    ]
    edits = [
        {"remove": 0},
        {"add": cname("www.test", "allow.test")},
    ]
    queries = [{"id": "q", "domain": "www.test", "ca": "ca.net"}]
    r = client.post(
        "/v1/authorize/change-impact",
        json={"records": records, "edits": edits, "queries": queries},
    )
    assert r.status_code == 200
    flip = r.json()["flips"][0]
    assert flip["before_authorized"] is False
    assert flip["after_authorized"] is True
    assert flip["minimal_edits"] == [0, 1]

    new_records = [
        caa("deny.test", "issue", ""),
        caa("allow.test", "issue", "ca.net"),
        caa("test", "issue", ""),
        cname("www.test", "allow.test"),
    ]
    # Baseline, new version, subset [0] and the invalid subset [1] are
    # prepared once each; the full subset [0, 1] reuses the new
    # version's snapshot instead of being prepared a second time.
    assert len(prepare_calls) == 4
    assert prepare_calls.count(fingerprint(records)) == 1
    assert prepare_calls.count(fingerprint(new_records)) == 1


def test_change_impact_candidate_group_shared_across_flips(prepare_calls):
    # Two queries flip; both minimal-subset searches enumerate the same
    # candidate subset [0], whose record group is prepared once and
    # reused for the second flip.
    records = [caa("example.com", "issue", "pki.goog")]
    edits = [
        {"add": caa("www.example.com", "issue", "letsencrypt.org")},
        {"add": caa("www.example.com", "iodef", "http://rpt.example")},
    ]
    queries = [
        {"id": "allow", "domain": "www.example.com", "ca": "letsencrypt.org"},
        {"id": "deny", "domain": "www.example.com", "ca": "pki.goog"},
    ]
    r = client.post(
        "/v1/authorize/change-impact",
        json={"records": records, "edits": edits, "queries": queries},
    )
    assert r.status_code == 200
    flips = r.json()["flips"]
    assert [f["id"] for f in flips] == ["allow", "deny"]
    assert all(f["minimal_edits"] == [0] for f in flips)

    subset_zero = records + [caa("www.example.com", "issue", "letsencrypt.org")]
    # Baseline + new version + the shared subset-[0] candidate.
    assert len(prepare_calls) == 3
    assert prepare_calls.count(fingerprint(subset_zero)) == 1


def test_change_impact_invalid_candidate_prepared_once(prepare_calls):
    # Subset [1] mixes CAA and CNAME at a.test and is skipped for both
    # flipped queries; its preparation failure is reused, not retried.
    records = [
        cname("a.test", "b.test"),
        caa("test", "issue", ""),
    ]
    edits = [
        {"remove": 0},
        {"add": caa("a.test", "issue", "ca.net")},
    ]
    queries = [
        {"id": "apex", "domain": "a.test", "ca": "ca.net"},
        {"id": "www", "domain": "www.a.test", "ca": "ca.net"},
    ]
    r = client.post(
        "/v1/authorize/change-impact",
        json={"records": records, "edits": edits, "queries": queries},
    )
    assert r.status_code == 200
    flips = r.json()["flips"]
    assert [f["id"] for f in flips] == ["apex", "www"]
    assert all(f["minimal_edits"] == [0, 1] for f in flips)

    invalid_subset = records + [caa("a.test", "issue", "ca.net")]
    # Baseline + new version + subset [0] + the failing subset [1];
    # the full subset [0, 1] reuses the new version's snapshot.
    assert len(prepare_calls) == 4
    assert prepare_calls.count(fingerprint(invalid_subset)) == 1


# ---------- /v1/records/minimize ----------

def test_minimize_full_subsequence_reuses_baseline_snapshot(prepare_calls):
    # Every record is essential, so the search walks all sizes up to the
    # full subsequence — which is the already-prepared baseline set.
    records = [
        cname("www.test", "edge.test"),
        caa("edge.test", "issue", "ca.net"),
    ]
    r = client.post(
        "/v1/records/minimize",
        json={
            "records": records,
            "queries": [{"id": "q", "domain": "www.test", "ca": "ca.net"}],
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["kept"] == [0, 1]
    assert body["queries"] == [
        {"id": "q", "authorized": True, "effective_owner": "edge.test"}
    ]

    # Baseline + empty subsequence + [0] + [1]; the full subsequence
    # [0, 1] reuses the baseline snapshot.
    assert len(prepare_calls) == 4
    assert prepare_calls.count(fingerprint(records)) == 1


# ---------- /v1/authorize/rollout-window ----------

def test_rollout_window_all_old_and_all_new_reuse_snapshots(prepare_calls):
    # One changed owner: mask 0 is the all-new snapshot and mask 1 the
    # all-old one; both reuse the snapshots prepared up front.
    r = client.post(
        "/v1/authorize/rollout-window",
        json={
            "before": [caa("example.com", "issue", "pki.goog")],
            "after": [caa("example.com", "issue", "letsencrypt.org")],
            "queries": [
                {"id": "q-le", "domain": "www.example.com", "ca": "letsencrypt.org"},
                {"id": "q-goog", "domain": "www.example.com", "ca": "pki.goog"},
            ],
            "stale_seconds": {"example.com": 30},
        },
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
    # Only the two endpoint snapshots are prepared, once each.
    assert len(prepare_calls) == 2
    assert prepare_calls.count(fingerprint([caa("example.com", "issue", "pki.goog")])) == 1
    assert prepare_calls.count(fingerprint([caa("example.com", "issue", "letsencrypt.org")])) == 1


def test_rollout_window_interior_mixes_prepared_once(prepare_calls):
    # Two changed owners: the interior mixes {a} and {b} are prepared
    # once each, while the all-new (mask 0) and all-old (mask 3)
    # combinations reuse the endpoint snapshots.
    r = client.post(
        "/v1/authorize/rollout-window",
        json={
            "before": [caa("a.test", "issue", ""), caa("b.test", "issue", "")],
            "after": [
                caa("a.test", "issue", "ca.net"),
                caa("b.test", "issue", "ca.net"),
            ],
            "queries": [
                {"id": "qa", "domain": "a.test", "ca": "ca.net"},
                {"id": "qb", "domain": "b.test", "ca": "ca.net"},
            ],
            "stale_seconds": {"a.test": 10, "b.test": 60},
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["changed_owners"] == ["a.test", "b.test"]
    assert body["safe_from"] == 60
    assert body["first_unsafe"] == {
        "old_owners": ["a.test"],
        "query_id": "qa",
        "error": None,
    }

    # before + after + the {a} mix + the {b} mix.
    assert len(prepare_calls) == 4
    assert prepare_calls.count(
        fingerprint([caa("a.test", "issue", ""), caa("b.test", "issue", "ca.net")])
    ) == 1
    assert prepare_calls.count(
        fingerprint([caa("b.test", "issue", ""), caa("a.test", "issue", "ca.net")])
    ) == 1
