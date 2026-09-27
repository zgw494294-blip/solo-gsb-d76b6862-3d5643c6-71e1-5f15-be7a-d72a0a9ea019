"""End-to-end tests for the offline CAA authorization API."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def caa(owner, tag, value="", flag=0):
    return {"type": "CAA", "owner": owner, "flag": flag, "tag": tag, "value": value}


def cname(owner, target):
    return {"type": "CNAME", "owner": owner, "target": target}


def post(body):
    return client.post("/v1/authorize", json=body)


BASE = {"domain": "www.example.com", "wildcard": False, "ca": "letsencrypt.org"}


# ---------- happy paths ----------

def test_match_at_parent():
    r = post({**BASE, "records": [caa("example.com", "issue", "letsencrypt.org")]})
    assert r.status_code == 200
    body = r.json()
    assert body["authorized"] is True
    assert body["effective_owner"] == "example.com"
    assert body["matched_tag"] == "issue"
    assert body["matched_value"] == "letsencrypt.org"
    # trace walked www.example.com (miss) then example.com (hit)
    queries = [s["query"] for s in body["trace"]]
    assert queries == ["www.example.com", "example.com"]


def test_case_and_trailing_dot_normalized():
    r = post(
        {
            "domain": "WWW.Example.Com.",
            "wildcard": False,
            "ca": "LetsEncrypt.ORG.",
            "records": [caa("EXAMPLE.com.", "issue", "LETSENCRYPT.org.")],
        }
    )
    assert r.status_code == 200
    assert r.json()["authorized"] is True


def test_no_caa_anywhere_allows():
    r = post({**BASE, "records": []})
    assert r.status_code == 200
    body = r.json()
    assert body["authorized"] is True
    assert body["effective_owner"] is None


def test_different_ca_denied():
    r = post({**BASE, "records": [caa("example.com", "issue", "pki.goog")]})
    assert r.status_code == 200
    assert r.json()["authorized"] is False


def test_empty_value_denies_everyone():
    r = post({**BASE, "records": [caa("example.com", "issue", "")]})
    assert r.status_code == 200
    assert r.json()["authorized"] is False


def test_any_of_multiple_issue_matches():
    r = post(
        {
            **BASE,
            "records": [
                caa("example.com", "issue", "pki.goog"),
                caa("example.com", "issue", ""),
                caa("example.com", "issue", "letsencrypt.org"),
            ],
        }
    )
    assert r.json()["authorized"] is True
    assert r.json()["matched_value"] == "letsencrypt.org"


def test_first_caa_set_wins():
    # www.example.com has a CAA set denying everything; parent must be ignored.
    r = post(
        {
            **BASE,
            "records": [
                caa("www.example.com", "issue", "pki.goog"),
                caa("example.com", "issue", "letsencrypt.org"),
            ],
        }
    )
    body = r.json()
    assert body["authorized"] is False
    assert body["effective_owner"] == "www.example.com"


# ---------- wildcard semantics ----------

def test_wildcard_uses_issuewild_when_present():
    r = post(
        {
            **BASE,
            "wildcard": True,
            "records": [
                caa("example.com", "issue", "letsencrypt.org"),
                caa("example.com", "issuewild", "pki.goog"),
            ],
        }
    )
    body = r.json()
    assert body["authorized"] is False
    assert body["matched_tag"] == "issuewild"


def test_wildcard_falls_back_to_issue():
    r = post(
        {
            **BASE,
            "wildcard": True,
            "records": [
                caa("example.com", "issue", "letsencrypt.org"),
                caa("example.com", "iodef", "mailto:ops@example.com"),
            ],
        }
    )
    body = r.json()
    assert body["authorized"] is True
    assert body["matched_tag"] == "issue"


def test_issuewild_ignored_for_non_wildcard():
    r = post({**BASE, "records": [caa("example.com", "issuewild", "pki.goog")]})
    # issue is absent -> allowed even though issuewild forbids wildcard issuance
    assert r.json()["authorized"] is True
    assert r.json()["matched_tag"] is None


def test_empty_issuewild_denies_wildcard():
    r = post(
        {
            **BASE,
            "wildcard": True,
            "records": [
                caa("example.com", "issue", "letsencrypt.org"),
                caa("example.com", "issuewild", ""),
            ],
        }
    )
    assert r.json()["authorized"] is False
    assert r.json()["matched_tag"] == "issuewild"


# ---------- unknown critical tag ----------

def test_unknown_critical_tag_denies():
    r = post(
        {
            **BASE,
            "records": [
                caa("example.com", "issue", "letsencrypt.org"),
                caa("example.com", "futuretag", "x", flag=128),
            ],
        }
    )
    body = r.json()
    assert body["authorized"] is False
    assert "futuretag" in body["reason"]


def test_unknown_noncritical_tag_allowed():
    r = post(
        {
            **BASE,
            "records": [
                caa("example.com", "futuretag", "x", flag=0),
                caa("example.com", "issue", "letsencrypt.org"),
            ],
        }
    )
    assert r.json()["authorized"] is True


def test_known_critical_tag_ok():
    r = post(
        {**BASE, "records": [caa("example.com", "issue", "letsencrypt.org", flag=128)]}
    )
    assert r.json()["authorized"] is True


# ---------- CNAME behaviour ----------

def test_cname_redirect_and_recheck():
    r = post(
        {
            **BASE,
            "records": [
                cname("www.example.com", "cdn.provider.net"),
                caa("cdn.provider.net", "issue", "letsencrypt.org"),
            ],
        }
    )
    body = r.json()
    assert body["authorized"] is True
    assert body["effective_owner"] == "cdn.provider.net"
    kinds = [(s["query"], s["kind"], s["cname_target"]) for s in body["trace"]]
    assert kinds[0] == ("www.example.com", "cname", "cdn.provider.net")


def test_cname_chain_within_limit():
    recs = [
        cname("a.test", "b.test"),
        cname("b.test", "c.test"),
        caa("c.test", "issue", "letsencrypt.org"),
    ]
    r = post({**BASE, "domain": "a.test", "records": recs})
    assert r.status_code == 200
    body = r.json()
    assert body["effective_owner"] == "c.test"
    assert max(s["cname_hops"] for s in body["trace"]) == 2


def test_cname_loop_is_422():
    r = post(
        {
            **BASE,
            "domain": "www.example.com",
            "records": [
                cname("www.example.com", "alias.loop.net"),
                cname("alias.loop.net", "www.example.com"),
            ],
        }
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_self_cname_is_422():
    r = post(
        {
            **BASE,
            "domain": "www.example.com",
            "records": [cname("www.example.com", "www.example.com")],
        }
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_nine_hops_is_422():
    recs = [cname(f"n{i}.test", f"n{i+1}.test") for i in range(9)]
    r = post({**BASE, "domain": "n0.test", "records": recs})
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELimitError"


def test_eight_hops_ok():
    # 8 CNAMEs (hops 1..8) ending in a CAA set is still accepted.
    recs = [cname(f"n{i}.test", f"n{i+1}.test") for i in range(8)]
    recs.append(caa("n8.test", "issue", "letsencrypt.org"))
    r = post({**BASE, "domain": "n0.test", "records": recs})
    assert r.status_code == 200
    assert r.json()["effective_owner"] == "n8.test"


def test_cname_search_climbs_from_target_not_original_parent():
    # www.example.com aliases to node.cdn.net. The target has no CAA, so the
    # search climbs the *target's* ancestry and finds cdn.net's set, which
    # only allows pki.goog. The original domain's parent (example.com, which
    # would allow letsencrypt.org) must never be consulted.
    r = post(
        {
            **BASE,
            "records": [
                cname("www.example.com", "node.cdn.net"),
                caa("cdn.net", "issue", "pki.goog"),
                caa("example.com", "issue", "letsencrypt.org"),
            ],
        }
    )
    body = r.json()
    assert body["authorized"] is False
    assert body["effective_owner"] == "cdn.net"
    assert body["matched_tag"] == "issue"
    # trace records the alias, then the target, then cdn.net — in that order
    kinds = [(s["query"], s["kind"], s["cname_target"]) for s in body["trace"]]
    assert kinds == [
        ("www.example.com", "cname", "node.cdn.net"),
        ("node.cdn.net", "caa", None),
        ("cdn.net", "caa", None),
    ]
    assert body["trace"][2]["caa"] == [{"flag": 0, "tag": "issue", "value": "pki.goog"}]


def test_cname_target_without_caa_never_falls_back_to_original_parents():
    # The alias target's whole ancestry has no CAA; the original domain's
    # parent set (which would deny) is not consulted, so issuance is allowed.
    r = post(
        {
            **BASE,
            "records": [
                cname("www.example.com", "node.cdn.net"),
                caa("example.com", "issue", "pki.goog"),
            ],
        }
    )
    body = r.json()
    assert body["authorized"] is True
    assert body["effective_owner"] is None


def test_cname_hops_accumulate_across_parent_levels():
    # The alias target's parent itself carries a CNAME; the hop counter must
    # not reset when the search climbs a level and follows another alias.
    recs = [
        cname("www.a.test", "x.y.z.test"),  # hop 1
        cname("z.test", "p.q.test"),  # hop 2, found while climbing from the target
        caa("p.q.test", "issue", "letsencrypt.org"),
    ]
    r = post({**BASE, "domain": "www.a.test", "records": recs})
    assert r.status_code == 200
    body = r.json()
    assert body["authorized"] is True
    assert body["effective_owner"] == "p.q.test"
    assert [s["cname_hops"] for s in body["trace"] if s["kind"] == "cname"] == [1, 2]


def test_cname_loop_across_parent_levels_is_422():
    # The alias target's parent aliases back to an already-visited name.
    recs = [
        cname("www.a.test", "x.y.test"),
        cname("test", "www.a.test"),
    ]
    r = post({**BASE, "domain": "www.a.test", "records": recs})
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_cname_hop_limit_spans_parent_levels():
    # Nine aliases chained across parent levels (each target's parent holds
    # the next CNAME) exceed the 8-hop budget even though no name repeats.
    recs = [cname("a.t0", "h1.x.t1")]
    recs += [cname(f"t{i}", f"h{i+1}.x.t{i+1}") for i in range(1, 9)]
    r = post({**BASE, "domain": "a.t0", "records": recs})
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELimitError"


# ---------- 422 validation ----------

def test_bad_domain_label():
    for bad in ["-bad.com", "bad-.com", "ex_ample.com", "bad..com", ".", ""]:
        r = post({**BASE, "domain": bad})
        assert r.status_code == 422, bad


def test_bad_flag():
    r = post(
        {**BASE, "records": [caa("example.com", "issue", "letsencrypt.org", flag=1)]}
    )
    assert r.status_code == 422


def test_bad_issue_value_with_params():
    r = post(
        {
            **BASE,
            "records": [
                caa("example.com", "issue", "letsencrypt.org; account=uri")
            ],
        }
    )
    assert r.status_code == 422


def test_mixed_caa_and_cname_same_owner():
    r = post(
        {
            **BASE,
            "records": [
                cname("www.example.com", "elsewhere.net"),
                caa("www.example.com", "issue", "letsencrypt.org"),
            ],
        }
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "MixedRecordsError"


def test_multiple_cnames_same_owner():
    r = post(
        {
            **BASE,
            "records": [
                cname("www.example.com", "a.net"),
                cname("www.example.com", "b.net"),
            ],
        }
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "MultipleCNAMEError"


def test_more_than_100_records():
    recs = [
        caa(f"h{i:03d}.example.com", "issue", "letsencrypt.org") for i in range(101)
    ]
    r = post({**BASE, "records": recs})
    assert r.status_code == 422


def test_invalid_record_type():
    r = post({**BASE, "records": [{"type": "A", "owner": "x", "value": "1.2.3.4"}]})
    assert r.status_code == 422


def test_wildcard_field_is_boolean():
    r = post({**BASE, "wildcard": "yes"})
    assert r.status_code == 422


# ---------- patch-plan ----------

def plan(body):
    return client.post("/v1/authorize/patch-plan", json=body)


def test_patch_plan_basic_first_visited_owner():
    r = plan({**BASE, "records": [caa("example.com", "issue", "pki.goog")]})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "patched"
    # the queried name is the first non-CNAME name on the lookup path
    assert body["added_record"] == {
        "type": "CAA",
        "owner": "www.example.com",
        "flag": 0,
        "tag": "issue",
        "value": "letsencrypt.org",
    }
    assert body["before_effective_owner"] == "example.com"
    assert body["after_effective_owner"] == "www.example.com"


def test_patch_plan_already_authorized():
    r = plan({**BASE, "records": [caa("example.com", "issue", "letsencrypt.org")]})
    body = r.json()
    assert body["status"] == "already_authorized"
    assert body["added_record"] is None
    assert body["before_effective_owner"] == "example.com"
    assert body["after_effective_owner"] is None


def test_patch_plan_already_authorized_no_caa_anywhere():
    r = plan({**BASE, "records": []})
    body = r.json()
    assert body["status"] == "already_authorized"
    assert body["before_effective_owner"] is None


def test_patch_plan_no_solution_unknown_critical_tag():
    # The only name on the path already carries an unknown critical tag, so
    # merging an issue record there still refuses issuance.
    r = plan(
        {
            "domain": "example.com",
            "ca": "letsencrypt.org",
            "records": [caa("example.com", "futuretag", "x", flag=128)],
        }
    )
    body = r.json()
    assert body["status"] == "no_solution"
    assert body["added_record"] is None
    assert body["before_effective_owner"] == "example.com"
    assert body["after_effective_owner"] is None


def test_patch_plan_no_solution_when_protected_is_the_target():
    # Any patch that authorizes the target also flips the identical
    # protected query, so no candidate qualifies.
    r = plan(
        {
            **BASE,
            "records": [caa("example.com", "issue", "pki.goog")],
            "protected": [{"domain": "www.example.com", "ca": "letsencrypt.org"}],
        }
    )
    assert r.json()["status"] == "no_solution"


def test_patch_plan_skips_owner_that_breaks_protected():
    # Patching www.example.com would flip the protected verdict for
    # www.example.com/pki.goog; the next name on the path (example.com,
    # which already holds the effective set) qualifies instead.
    r = plan(
        {
            **BASE,
            "records": [caa("example.com", "issue", "pki.goog")],
            "protected": [{"domain": "www.example.com", "ca": "pki.goog"}],
        }
    )
    body = r.json()
    assert body["status"] == "patched"
    assert body["added_record"]["owner"] == "example.com"
    assert body["before_effective_owner"] == "example.com"
    assert body["after_effective_owner"] == "example.com"


def test_patch_plan_protected_unaffected():
    r = plan(
        {
            **BASE,
            "records": [caa("example.com", "issue", "pki.goog")],
            "protected": [{"domain": "api.other.net", "ca": "letsencrypt.org"}],
        }
    )
    body = r.json()
    assert body["status"] == "patched"
    assert body["added_record"]["owner"] == "www.example.com"


def test_patch_plan_wildcard_uses_issuewild():
    r = plan(
        {
            **BASE,
            "wildcard": True,
            "records": [caa("example.com", "issuewild", "pki.goog")],
        }
    )
    body = r.json()
    assert body["status"] == "patched"
    assert body["added_record"]["tag"] == "issuewild"
    assert body["added_record"]["owner"] == "www.example.com"


def test_patch_plan_skips_cname_owners():
    # www.example.com is a CNAME and cannot own the new record; the patch
    # lands on the first non-CNAME name on the path.
    r = plan(
        {
            **BASE,
            "records": [
                cname("www.example.com", "node.cdn.net"),
                caa("cdn.net", "issue", "pki.goog"),
            ],
        }
    )
    body = r.json()
    assert body["status"] == "patched"
    assert body["added_record"]["owner"] == "node.cdn.net"
    assert body["before_effective_owner"] == "cdn.net"
    assert body["after_effective_owner"] == "node.cdn.net"


def test_patch_plan_99_records_ok():
    recs = [caa(f"h{i:03d}.example.com", "issue", "pki.goog") for i in range(99)]
    r = plan({**BASE, "records": recs})
    assert r.status_code == 200


def test_patch_plan_record_and_protected_limits():
    recs = [caa(f"h{i:03d}.example.com", "issue", "pki.goog") for i in range(100)]
    assert plan({**BASE, "records": recs}).status_code == 422
    prot = [{"domain": f"h{i}.example.com", "ca": "letsencrypt.org"} for i in range(21)]
    assert plan({**BASE, "protected": prot}).status_code == 422


def test_patch_plan_bad_protected_domain():
    r = plan({**BASE, "protected": [{"domain": "bad..com", "ca": "letsencrypt.org"}]})
    assert r.status_code == 422


def test_patch_plan_protected_alias_error_is_422():
    # The protected query hits a CNAME loop even though the target is fine.
    r = plan(
        {
            **BASE,
            "records": [
                cname("a.loop.net", "b.loop.net"),
                cname("b.loop.net", "a.loop.net"),
            ],
            "protected": [{"domain": "a.loop.net", "ca": "letsencrypt.org"}],
        }
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_patch_plan_mixed_records_is_422():
    r = plan(
        {
            **BASE,
            "records": [
                cname("www.example.com", "elsewhere.net"),
                caa("www.example.com", "issue", "letsencrypt.org"),
            ],
        }
    )
    assert r.status_code == 422
    assert r.json()["error_type"] == "MixedRecordsError"


def test_health():
    assert client.get("/health").json() == {"status": "ok"}
