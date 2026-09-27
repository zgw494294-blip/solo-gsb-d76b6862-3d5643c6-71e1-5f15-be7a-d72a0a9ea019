"""Offline CAA (Certificate Authority Authorization) resolution engine.

Implements the lookup semantics of RFC 8659 against a caller-supplied set
of DNS records, so no network access is required:

* the owner name is walked from the queried name up to the root;
* a CNAME redirects the search to the alias target, and the upward walk
  continues from the *target* (the original name's parents are abandoned);
* CNAME hops are counted and loops detected across the whole resolution,
  spanning parent levels (max 8 hops, loops rejected);
* the *first* owner that has CAA records is the authoritative set.

Record handling is split into two phases so batch operations can share a
single validation pass per record set: :func:`prepare_records` normalizes
and validates the records once (names, mixed CAA/CNAME owners, multiple
CNAMEs) and freezes them into an immutable :class:`PreparedRecords` index
that no longer depends on the input; :func:`evaluate_prepared` then runs
any number of lookups against that index. CNAME loops and the cumulative
hop limit are properties of the path a lookup actually walks, so they are
still checked during the lookup itself. :func:`evaluate` remains as a
one-shot compatibility wrapper combining both phases.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from itertools import combinations
from types import MappingProxyType
from typing import Mapping, Optional

MAX_CNAME_HOPS = 8
MAX_RECORDS = 100
MAX_CHANGED_OWNERS = 8

# Tags understood by this implementation. RFC 8659 defines five; any other
# tag carrying the critical flag (128) must cause issuance to be refused.
KNOWN_TAGS = frozenset({"issue", "issuewild", "iodef", "contactemail", "contactphone"})


class CAAError(ValueError):
    """Base class for 422-grade validation/resolution failures."""


class InvalidNameError(CAAError):
    pass


class MixedRecordsError(CAAError):
    pass


class MultipleCNAMEError(CAAError):
    pass


class CNAMELoopError(CAAError):
    pass


class CNAMELimitError(CAAError):
    pass


@dataclass(frozen=True)
class CAAEntry:
    owner: str
    flag: int
    tag: str
    value: str


@dataclass(frozen=True)
class CNAMERecord:
    owner: str
    target: str


@dataclass(frozen=True)
class PreparedRecords:
    """Immutable index of a validated record set, detached from the input.

    Built once by :func:`prepare_records` and reusable for any number of
    :func:`evaluate_prepared` lookups: ``caa_map`` maps each owner name to
    its CAA entries in input order, ``cname_map`` maps each owner name to
    its normalized CNAME target. The mappings and their contents share no
    mutable state with the original record dicts, so later mutations of
    the input — or of any trace returned by a lookup — cannot affect the
    snapshot or subsequent verdicts.
    """

    caa_map: Mapping[str, tuple[CAAEntry, ...]]
    cname_map: Mapping[str, str]


@dataclass
class TraceStep:
    """One node visited during the CAA search."""

    query: str
    kind: str  # "caa" | "cname"
    cname_target: Optional[str] = None
    cname_hops: int = 0
    caa: Optional[list[dict]] = None

    def as_dict(self) -> dict:
        return {
            "query": self.query,
            "kind": self.kind,
            "cname_target": self.cname_target,
            "cname_hops": self.cname_hops,
            "caa": self.caa,
        }


def normalize_name(
    raw: str, *, field: str = "name", allow_underscore: bool = False
) -> str:
    """Lower-case a DNS name, strip a single trailing dot and validate it.

    Empty labels, labels longer than 63 octets, invalid characters and
    overall length above 253 octets are rejected. Wildcards ("*") are not
    accepted here. Underscores are rejected like every other non-LDH
    character by default; ``allow_underscore`` admits them (DNS-01 owners
    such as ``_acme-challenge.example.com`` and alias targets legitimately
    carry underscore labels).
    """
    if not isinstance(raw, str):
        raise InvalidNameError(f"{field} must be a string")
    name = raw.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    if not name:
        raise InvalidNameError(f"{field} must not be empty or root")
    labels = name.split(".")
    for label in labels:
        if not label:
            raise InvalidNameError(f"invalid {field} {raw!r}: empty label")
        if label.startswith("*"):
            raise InvalidNameError(f"invalid {field} {raw!r}: wildcard not allowed")
        if len(label) > 63:
            raise InvalidNameError(
                f"invalid {field} {raw!r}: label longer than 63 characters"
            )
        if label.startswith("-") or label.endswith("-"):
            raise InvalidNameError(
                f"invalid {field} {raw!r}: label must not start/end with '-'"
            )
        if not all(
            c.isascii() and (c.isalnum() or c == "-" or (allow_underscore and c == "_"))
            for c in label
        ):
            raise InvalidNameError(
                f"invalid {field} {raw!r}: illegal character in label"
            )
    if len(name) > 253:
        raise InvalidNameError(f"invalid {field} {raw!r}: name too long")
    return name


def parent_of(name: str) -> Optional[str]:
    """Return the parent zone, or None at the root / TLD boundary."""
    if "." not in name:
        return None
    return name.split(".", 1)[1]


def prepare_records(records: list[dict]) -> PreparedRecords:
    """Validate raw record dicts and freeze them into an immutable index.

    Performs every record-set-level check in one pass: owner/target name
    normalization, rejection of owners mixing CAA and CNAME records and of
    owners with multiple CNAME records. The returned snapshot holds only
    normalized, immutable values, so it is unaffected by later changes to
    ``records``. CNAME loops and hop limits are *not* checked here — they
    depend on the path a lookup actually walks and are enforced by
    :func:`evaluate_prepared`.
    """
    caa_map: dict[str, list[CAAEntry]] = {}
    cname_map: dict[str, str] = {}

    for rec in records:
        kind = rec.get("type")
        owner = normalize_name(rec.get("owner", ""), field="owner")
        if kind == "CAA":
            if owner in cname_map:
                raise MixedRecordsError(
                    f"owner {owner!r} mixes CNAME and CAA records"
                )
            caa_map.setdefault(owner, []).append(
                CAAEntry(
                    owner=owner,
                    flag=int(rec["flag"]),
                    tag=str(rec["tag"]).strip().lower(),
                    value=rec["value"],
                )
            )
        elif kind == "CNAME":
            if owner in caa_map:
                raise MixedRecordsError(
                    f"owner {owner!r} mixes CNAME and CAA records"
                )
            if owner in cname_map:
                raise MultipleCNAMEError(
                    f"owner {owner!r} has multiple CNAME records"
                )
            cname_map[owner] = normalize_name(rec.get("target", ""), field="target")
        else:  # pragma: no cover - rejected by the schema layer
            raise CAAError(f"unknown record type {kind!r}")

    return PreparedRecords(
        caa_map=MappingProxyType(
            {owner: tuple(entries) for owner, entries in caa_map.items()}
        ),
        cname_map=MappingProxyType(cname_map),
    )


def evaluate_prepared(
    domain: str,
    wildcard: bool,
    ca: str,
    snapshot: PreparedRecords,
) -> dict:
    """Run the full CAA lookup and authorization decision on a prepared
    snapshot.

    Same verdict, trace and error semantics as :func:`evaluate`, but
    reuses the immutable index built by :func:`prepare_records` instead of
    re-validating a record set. CNAME loops and the cumulative hop limit
    are still enforced here, while the lookup walks the alias chain.

    Returns a dict with ``authorized``, ``effective_owner``,
    ``matched_tag``, ``matched_value``, ``reason`` and ``trace``.
    """
    qname = normalize_name(domain, field="domain")
    ca_name = normalize_name(ca, field="ca")
    return _decide(qname, wildcard, ca_name, snapshot)


def evaluate(
    domain: str,
    wildcard: bool,
    ca: str,
    records: list[dict],
) -> dict:
    """Run the full CAA lookup and authorization decision.

    Compatibility wrapper around :func:`prepare_records` +
    :func:`evaluate_prepared` for one-shot callers; batch operations
    should prepare the record set once and reuse the snapshot instead.

    Returns a dict with ``authorized``, ``effective_owner``,
    ``matched_tag``, ``matched_value``, ``reason`` and ``trace``.
    """
    qname = normalize_name(domain, field="domain")
    ca_name = normalize_name(ca, field="ca")
    return _decide(qname, wildcard, ca_name, prepare_records(records))


def _decide(
    qname: str,
    wildcard: bool,
    ca_name: str,
    snapshot: PreparedRecords,
) -> dict:
    """Walk the prepared index for an already-normalized domain/CA pair."""
    caa_map = snapshot.caa_map
    cname_map = snapshot.cname_map

    trace: list[TraceStep] = []
    effective: Optional[tuple[CAAEntry, ...]] = None
    effective_owner: Optional[str] = None

    # Walk from the queried name upward. A CNAME redirects the search to the
    # alias target and the climb continues from there — the search never
    # falls back to the original name's parents once an alias was followed.
    # The hop counter and the visited set span the whole resolution (across
    # parent levels), so a chain split over several levels still trips the
    # 8-hop limit and any revisited name — however reached — is a loop.
    current: Optional[str] = qname
    hops = 0
    seen: set[str] = set()
    path: list[str] = []
    while current is not None:
        if current in seen:
            raise CNAMELoopError(
                f"CNAME loop detected at {current!r} "
                f"(path: {' -> '.join(path + [current])})"
            )
        seen.add(current)
        path.append(current)

        if current in cname_map:
            if hops >= MAX_CNAME_HOPS:
                raise CNAMELimitError(
                    f"CNAME chain exceeds {MAX_CNAME_HOPS} hops from {qname!r}"
                )
            target = cname_map[current]
            hops += 1
            trace.append(
                TraceStep(
                    query=current,
                    kind="cname",
                    cname_target=target,
                    cname_hops=hops,
                )
            )
            current = target
            continue

        # No alias at this name: the CAA lookup happens here.
        if current in caa_map:
            caa_at = caa_map[current]
            trace.append(
                TraceStep(
                    query=current,
                    kind="caa",
                    cname_hops=hops,
                    caa=[
                        {"flag": e.flag, "tag": e.tag, "value": e.value}
                        for e in caa_at
                    ],
                )
            )
            effective = caa_at
            effective_owner = current
            break

        # Record the empty lookup so the trace shows every inspected name,
        # then continue at the parent of the *current* name (which is the
        # alias target's parent when a CNAME was followed).
        trace.append(TraceStep(query=current, kind="caa", cname_hops=hops, caa=None))
        current = parent_of(current)

    if effective is None:
        return {
            "authorized": True,
            "effective_owner": None,
            "matched_tag": None,
            "matched_value": None,
            "reason": "no CAA records found at any parent; issuance allowed",
            "trace": [s.as_dict() for s in trace],
        }

    # Rule 1: an unknown tag with the critical bit set forbids issuance.
    for entry in effective:
        if entry.flag == 128 and entry.tag not in KNOWN_TAGS:
            return {
                "authorized": False,
                "effective_owner": effective_owner,
                "matched_tag": None,
                "matched_value": None,
                "reason": (
                    f"unknown critical tag {entry.tag!r} (flag=128) at "
                    f"{effective_owner}; issuance refused"
                ),
                "trace": [s.as_dict() for s in trace],
            }

    # Rule 2: choose issuewild for wildcard names when present, else issue.
    chosen = "issuewild" if wildcard else "issue"
    if wildcard:
        tags = [e for e in effective if e.tag == "issuewild"]
        if not tags:
            chosen = "issue"
            tags = [e for e in effective if e.tag == "issue"]
    else:
        tags = [e for e in effective if e.tag == "issue"]

    if not tags:
        # Applicable property absent at the authoritative set -> allowed.
        return {
            "authorized": True,
            "effective_owner": effective_owner,
            "matched_tag": None,
            "matched_value": None,
            "reason": (
                f"effective CAA set at {effective_owner} contains no {chosen} "
                f"property; issuance allowed"
            ),
            "trace": [s.as_dict() for s in trace],
        }

    # Rule 3: property present -> at least one non-empty value must name the CA.
    # Empty value is an explicit "deny everyone"; it never matches.
    match: Optional[CAAEntry] = next(
        (e for e in tags if e.value and e.value == ca_name), None
    )
    if match is not None:
        return {
            "authorized": True,
            "effective_owner": effective_owner,
            "matched_tag": chosen,
            "matched_value": match.value,
            "reason": (
                f"{chosen} property at {effective_owner} authorizes CA {ca_name}"
            ),
            "trace": [s.as_dict() for s in trace],
        }

    values = [e.value for e in tags]
    return {
        "authorized": False,
        "effective_owner": effective_owner,
        "matched_tag": chosen,
        "matched_value": None,
        "reason": (
            f"{chosen} property at {effective_owner} does not authorize CA "
            f"{ca_name}; present values: {values}"
        ),
        "trace": [s.as_dict() for s in trace],
    }


def _records_key(records: list[dict]) -> tuple:
    """Hashable fingerprint of a raw record group, order included.

    Used as the snapshot-cache key inside one batch operation: two
    groups with the same fingerprint normalize to the same
    :class:`PreparedRecords`, so the snapshot (or the preparation
    failure) of the first is reused for the second. Record dicts only
    carry strings and ints, so the sorted-items tuple is hashable.
    """
    return tuple(tuple(sorted(rec.items())) for rec in records)


def _evaluator_for(
    records: list[dict],
    cache: Optional[dict[tuple, object]] = None,
):
    """Return an evaluate-like callable sharing one prepared snapshot.

    The first call normalizes the query names and then prepares the
    record set — the same validation order as :func:`evaluate` — and
    caches the immutable :class:`PreparedRecords` index; later calls
    reuse it. When ``cache`` (a dict local to one batch operation) is
    given, the outcome is additionally keyed by the record group's
    content: a group already prepared anywhere in the operation —
    baseline, new version or an earlier candidate — is not normalized
    and validated again, and a group whose preparation already failed
    raises the same :class:`CAAError` again without re-running
    :func:`prepare_records`. Batch operations build one such evaluator
    per record group, so each distinct group is prepared at most once
    per operation no matter how many queries or search rounds run
    against it.
    """
    snapshot: list[PreparedRecords] = []

    def run(domain: str, wildcard: bool, ca: str) -> dict:
        qname = normalize_name(domain, field="domain")
        ca_name = normalize_name(ca, field="ca")
        if not snapshot:
            if cache is None:
                snapshot.append(prepare_records(records))
            else:
                key = _records_key(records)
                if key not in cache:
                    try:
                        cache[key] = prepare_records(records)
                    except CAAError as exc:
                        # A group that fails to prepare fails for every
                        # later visit too; reuse the failure.
                        cache[key] = exc
                        raise
                prepared = cache[key]
                if isinstance(prepared, CAAError):
                    raise prepared
                snapshot.append(prepared)
        return _decide(qname, wildcard, ca_name, snapshot[0])

    return run


def _maximum_matching(
    eligible: list[list[int]],
    capacities: dict[int, int],
    active: list[bool],
) -> int:
    """Maximum bipartite b-matching size between requests and CA slots.

    ``eligible[i]`` lists the CA indices authorized for request ``i``;
    CA ``c`` offers ``capacities[c]`` identical slots. Only requests with
    ``active[i]`` true participate. Kuhn's algorithm on the slot-expanded
    graph returns the maximum number of requests that can be assigned.
    """
    # owner[r] = CA index currently occupying slot r; slots are grouped by CA.
    owner: list[Optional[int]] = []
    slot_of: dict[int, range] = {}
    start = 0
    for c, cap in capacities.items():
        slot_of[c] = range(start, start + cap)
        owner.extend([None] * cap)
        start += cap

    def augment(req: int, seen: list[bool]) -> bool:
        for ca_idx in eligible[req]:
            for slot in slot_of[ca_idx]:
                if seen[slot]:
                    continue
                seen[slot] = True
                holder = owner[slot]
                if holder is None or augment(holder, seen):
                    owner[slot] = req
                    return True
        return False

    size = 0
    for i in range(len(active)):
        if active[i] and eligible[i]:
            if augment(i, [False] * len(owner)):
                size += 1
    return size


def route_issuance(
    cas: list[dict],
    requests: list[dict],
    records: list[dict],
) -> dict:
    """Assign at most one authorized, capacity-respecting CA to each request.

    Optimization order:

    1. maximize the number of assigned requests;
    2. among equally-sized solutions, minimize lexicographically the tuple
       of per-request outcomes in request input order, where each outcome is
       the index (0-based) of the chosen candidate in that request's
       candidate list, and an unassigned request sorts *after* every
       candidate index.

    Each request's candidates are evaluated against a single prepared
    snapshot of ``records`` (so every name/record/alias validation
    failure surfaces as a 422-grade :class:`CAAError`); only authorized
    candidates are usable. The greedy prefix construction keeps a
    maximum-cardinality completion feasible at every step, which yields
    the lexicographically smallest optimum.

    A request with no authorized candidate is reported as
    ``no_authorized_candidate``; a request that stays unassigned despite
    having authorized candidates is reported as ``insufficient_capacity``.
    """
    ca_names = [normalize_name(ca["ca"], field="ca") for ca in cas]
    capacities = {i: int(ca["capacity"]) for i, ca in enumerate(cas)}
    ca_index = {name: i for i, name in enumerate(ca_names)}

    # One record set for the whole operation: a single evaluator prepares
    # it on first use and reuses the snapshot for every authorization.
    authorize = _evaluator_for(records)

    eligible: list[list[int]] = []
    for req in requests:
        domain = normalize_name(req["domain"], field="domain")
        wildcard = bool(req.get("wildcard", False))
        usable: list[int] = []
        for cand in req["candidates"]:
            ca_name = normalize_name(cand, field="candidate")
            verdict = authorize(domain, wildcard, ca_name)
            if verdict["authorized"]:
                usable.append(ca_index[ca_name])
        eligible.append(usable)

    n = len(requests)
    active = [True] * n
    max_total = _maximum_matching(eligible, capacities, active)

    remaining = dict(capacities)
    assignments: list[Optional[int]] = [None] * n
    reasons: list[Optional[str]] = [None] * n

    for i in range(n):
        chosen: Optional[int] = None
        for ca_idx in eligible[i]:
            if remaining.get(ca_idx, 0) <= 0:
                continue
            # Tentatively assign this CA, freeze the prefix, and require the
            # suffix to complete the solution to maximum cardinality.
            remaining[ca_idx] -= 1
            trial = list(active)
            trial[i] = False
            suffix_cap = dict(remaining)
            fixed = max_total - sum(1 for a in assignments[:i] if a is not None) - 1
            if _maximum_matching(eligible, suffix_cap, trial) == fixed:
                chosen = ca_idx
                break
            remaining[ca_idx] += 1

        if chosen is None:
            assignments[i] = None
            reasons[i] = (
                "no authorized candidate"
                if not eligible[i]
                else "insufficient capacity for every authorized candidate"
            )
        else:
            assignments[i] = chosen
        active[i] = False

    results = [
        {
            "id": requests[i]["id"],
            "assigned_ca": ca_names[ca_idx] if ca_idx is not None else None,
            "reason": reasons[i],
        }
        for i, ca_idx in enumerate(assignments)
    ]
    usage = [
        {
            "ca": ca_names[i],
            "capacity": capacities[i],
            "used": sum(1 for a in assignments if a == i),
        }
        for i in range(len(cas))
    ]
    return {"assigned": max_total, "results": results, "usage": usage}


def check_csr(
    names: list[dict],
    ca: str,
    records: list[dict],
) -> dict:
    """Authorize every SAN identifier of a CSR against one record snapshot.

    ``names`` carries one ``{"name", "domain", "wildcard"}`` entry per
    SAN DNSName, in SAN order (``name`` keeps the ``*.`` wildcard marker,
    ``domain`` is the name the CAA lookup actually runs). The record set
    is prepared once and shared by every lookup, and each identifier is
    evaluated with the same rules as :func:`evaluate`; any name/record/
    alias failure surfaces as a 422-grade :class:`CAAError`. The whole
    CSR is acceptable only when *every* identifier is authorized.
    """
    ca_name = normalize_name(ca, field="ca")

    # One record set for the whole CSR: a single evaluator prepares it on
    # first use and every SAN identifier reuses the same snapshot.
    authorize = _evaluator_for(records)

    identifiers: list[dict] = []
    for entry in names:
        verdict = authorize(entry["domain"], entry["wildcard"], ca_name)
        identifiers.append(
            {
                "name": entry["name"],
                "wildcard": entry["wildcard"],
                "domain": entry["domain"],
                "authorized": verdict["authorized"],
                "effective_owner": verdict["effective_owner"],
                "reason": verdict["reason"],
                "trace": verdict["trace"],
            }
        )

    authorized = all(item["authorized"] for item in identifiers)
    if authorized:
        reason = (
            f"all {len(identifiers)} SAN identifier(s) authorized for CA "
            f"{ca_name}"
        )
    else:
        failed = [item["name"] for item in identifiers if not item["authorized"]]
        reason = (
            f"{len(failed)} of {len(identifiers)} SAN identifier(s) not "
            f"authorized for CA {ca_name}: {failed}; CSR not acceptable"
        )
    return {"authorized": authorized, "reason": reason, "identifiers": identifiers}


def plan_patch(
    domain: str,
    wildcard: bool,
    ca: str,
    records: list[dict],
    protected: list[dict],
) -> dict:
    """Search for a one-record CAA patch that flips the target to authorized.

    The target query and every protected query are evaluated against a
    prepared snapshot of the supplied records first (any validation/alias
    error propagates as a 422-grade :class:`CAAError`). When the target is
    already authorized no patch is attempted. Otherwise every name the
    target lookup actually visited *without* following a CNAME — i.e.
    every point where an added CAA record would be consulted — is tried,
    in visitation order, as the owner of a single ``flag=0`` record whose
    tag is ``issuewild`` for wildcard requests and ``issue`` otherwise,
    and whose value is the target CA. A candidate wins when the patched
    record set authorizes the target *and* leaves every protected query's
    ``authorized`` verdict unchanged; the first (earliest-visited) winning
    owner is returned.
    """
    # The baseline record set backs the target and every protected query
    # through one shared evaluator (prepared once, on first use).
    baseline_eval = _evaluator_for(records)
    target = baseline_eval(domain, wildcard, ca)
    baselines = [
        baseline_eval(p["domain"], p.get("wildcard", False), p["ca"])[
            "authorized"
        ]
        for p in protected
    ]

    if target["authorized"]:
        return {
            "status": "already_authorized",
            "added_record": None,
            "before_effective_owner": target["effective_owner"],
            "after_effective_owner": None,
            "reason": "target is already authorized; no patch needed",
        }

    tag = "issuewild" if wildcard else "issue"
    ca_name = normalize_name(ca, field="ca")
    before_owner = target["effective_owner"]

    # Candidate owners: names the lookup visited where a CAA record would
    # be consulted (CNAME hops are not eligible owners). Trace order is
    # visitation order, so the earliest-visited qualifying name wins.
    candidates = [s["query"] for s in target["trace"] if s["kind"] == "caa"]

    for owner in candidates:
        patch = {
            "type": "CAA",
            "owner": owner,
            "flag": 0,
            "tag": tag,
            "value": ca_name,
        }
        # Each candidate record group gets its own evaluator, prepared
        # once and reused for the target and every protected query.
        patched_eval = _evaluator_for(records + [patch])
        new_target = patched_eval(domain, wildcard, ca)
        if not new_target["authorized"]:
            continue
        protected_ok = all(
            patched_eval(p["domain"], p.get("wildcard", False), p["ca"])[
                "authorized"
            ]
            == baseline
            for p, baseline in zip(protected, baselines)
        )
        if not protected_ok:
            continue
        after_owner = new_target["effective_owner"]
        if after_owner == before_owner:
            change = f"target effective owner stays {before_owner}"
        else:
            change = (
                f"target effective owner changes {before_owner} -> {after_owner}"
            )
        return {
            "status": "patched",
            "added_record": patch,
            "before_effective_owner": before_owner,
            "after_effective_owner": after_owner,
            "reason": f"add {tag} record for {ca_name} at {owner}; {change}",
        }

    return {
        "status": "no_solution",
        "added_record": None,
        "before_effective_owner": before_owner,
        "after_effective_owner": None,
        "reason": (
            "no single flag=0 CAA record on the target lookup path both "
            "authorizes the target and preserves every protected verdict"
        ),
    }


def apply_edits(
    records: list[dict],
    edits: list[dict],
    *,
    indices: Optional[frozenset[int]] = None,
) -> list[dict]:
    """Apply a subset of edits to a baseline record list.

    ``remove`` edits name a zero-based index into the original baseline
    (removed positions never shift, even when several removals are given);
    ``add`` edits are appended in edit order. ``indices`` restricts the
    applied edits to those edit positions; ``None`` applies every edit.
    """
    removed = {
        edits[i]["remove"]
        for i in (range(len(edits)) if indices is None else indices)
        if "remove" in edits[i]
    }
    result = [rec for idx, rec in enumerate(records) if idx not in removed]
    for i in range(len(edits)):
        if indices is not None and i not in indices:
            continue
        if "add" in edits[i]:
            result.append(edits[i]["add"])
    return result


def change_impact(
    records: list[dict],
    edits: list[dict],
    queries: list[dict],
) -> dict:
    """Report authorization verdicts that flip when a batch of edits lands.

    All edits are applied together (removals by original zero-based index,
    additions appended in edit order) to produce the new record set; both
    versions must pass the record/alias validation applied to every query,
    otherwise the request fails with a 422-grade :class:`CAAError`.

    For each query whose ``authorized`` verdict differs between versions,
    the smallest subset of edits which, applied alone to the baseline,
    reproduces the *new* verdict is returned; ties break on the
    lexicographically smallest list of (zero-based) edit indices.
    Subsets whose record set is itself invalid (>100 records, mixed
    CAA/CNAME owner, multiple CNAMEs) or whose evaluation hits an alias
    error (loop, >8 hops) are skipped rather than reported.
    """
    n_edits = len(edits)

    def verdict_for(run, q: dict) -> dict:
        return run(q["domain"], q.get("wildcard", False), q["ca"])

    # One snapshot cache shared by the baseline, the new version and
    # every candidate subset: each distinct record group is prepared at
    # most once per request, and a group the search revisits — such as
    # the full edit set, which is also enumerated as a candidate subset —
    # reuses the snapshot built on its first visit.
    cache: dict[tuple, object] = {}

    # Baseline: one evaluator prepares the existing record set on first
    # use and every query reuses the snapshot, so the set is fully
    # exercised by the same name/record/alias rules as /v1/authorize.
    before_eval = _evaluator_for(records, cache)
    before: list[dict] = [verdict_for(before_eval, q) for q in queries]

    new_records = apply_edits(records, edits)
    if len(new_records) > MAX_RECORDS:
        raise CAAError(
            f"record set after edits has {len(new_records)} records; "
            f"at most {MAX_RECORDS} allowed"
        )
    after_eval = _evaluator_for(new_records, cache)
    after: list[dict] = [verdict_for(after_eval, q) for q in queries]

    flips: list[dict] = []
    for qi, q in enumerate(queries):
        b, a = before[qi], after[qi]
        if b["authorized"] == a["authorized"]:
            continue

        # Try subsets by increasing size; tuples are naturally generated in
        # lexicographic order, so the first reproducing the new verdict is
        # the minimal, lexicographically smallest edit-index list.
        minimal: Optional[list[int]] = None
        for size in range(1, n_edits + 1):
            for subset in combinations(range(n_edits), size):
                sub_records = apply_edits(
                    records, edits, indices=frozenset(subset)
                )
                if len(sub_records) > MAX_RECORDS:
                    continue
                try:
                    # Each candidate record group is prepared once per
                    # request (the cache also covers the full edit set,
                    # already prepared as the new version); invalid
                    # candidates are skipped, not reported.
                    sub_verdict = verdict_for(
                        _evaluator_for(sub_records, cache), q
                    )
                except CAAError:
                    continue
                if sub_verdict["authorized"] == a["authorized"]:
                    minimal = list(subset)
                    break
            if minimal is not None:
                break
        # The full edit set reproduced the new verdict above, so a minimal
        # subset always exists.
        flips.append(
            {
                "id": q["id"],
                "before_authorized": b["authorized"],
                "after_authorized": a["authorized"],
                "before_effective_owner": b["effective_owner"],
                "after_effective_owner": a["effective_owner"],
                "minimal_edits": minimal,
            }
        )

    return {"flips": flips}


def minimize_records(
    records: list[dict],
    queries: list[dict],
) -> dict:
    """Find the shortest kept-record subsequence preserving every verdict.

    Each query is first evaluated against the full record set (any
    validation/alias failure propagates as a 422-grade :class:`CAAError`).
    Records may only be *deleted*: candidate subsequences of the original
    list are tried by increasing length, and a candidate wins when every
    query keeps its baseline ``authorized`` and ``effective_owner``.
    Candidates whose evaluation raises a record/alias error (mixed
    CAA/CNAME owner, multiple CNAMEs, CNAME loop, >8 hops) are skipped
    rather than reported. Ties on length break on the lexicographically
    smallest list of kept zero-based indices — ``combinations`` already
    enumerates index tuples in that order, so the first match wins. The
    full record set always reproduces the baseline, so a winner exists.
    """

    def pair_for(run, q: dict) -> tuple[bool, Optional[str]]:
        verdict = run(q["domain"], q.get("wildcard", False), q["ca"])
        return verdict["authorized"], verdict["effective_owner"]

    # One snapshot cache shared by the baseline and every candidate
    # subsequence: each distinct record group is prepared at most once
    # per request, and a group the search revisits — such as the full
    # subsequence, which equals the baseline — reuses the snapshot.
    cache: dict[tuple, object] = {}

    # Baseline: one evaluator prepares the full record set on first use
    # and every query reuses the snapshot, so the existing name/record/
    # alias rules surface exactly as in /v1/authorize.
    baseline_eval = _evaluator_for(records, cache)
    baselines = [pair_for(baseline_eval, q) for q in queries]

    n = len(records)
    kept: Optional[tuple[int, ...]] = None
    for size in range(n + 1):
        for subset in combinations(range(n), size):
            sub_records = [records[i] for i in subset]
            try:
                # Each candidate subsequence is prepared once per
                # request and reused for every query; invalid
                # candidates are skipped.
                sub_eval = _evaluator_for(sub_records, cache)
                if all(
                    pair_for(sub_eval, q) == baseline
                    for q, baseline in zip(queries, baselines)
                ):
                    kept = subset
                    break
            except CAAError:
                continue  # record/alias failure: skip this candidate
        if kept is not None:
            break

    # ``records`` itself reproduces the baseline, so kept is never None.
    kept_set = set(kept)
    return {
        "kept": list(kept),
        "removed": [i for i in range(n) if i not in kept_set],
        "records": [records[i] for i in kept],
        "queries": [
            {
                "id": q["id"],
                "authorized": authorized,
                "effective_owner": owner,
            }
            for q, (authorized, owner) in zip(queries, baselines)
        ],
    }


def rollout_window(
    before: list[dict],
    after: list[dict],
    queries: list[dict],
    stale_seconds: dict[str, int],
) -> dict:
    """Compute the first second when every old/new snapshot mix is safe.

    The two snapshots are compared owner by owner: an owner whose
    *normalized record multiset* differs between ``before`` and ``after``
    is a *changed owner*. An owner present on only one side counts too —
    the missing side is the empty multiset, so an added owner has an empty
    old group and a removed owner an empty new group. While
    ``t < stale_seconds[owner]`` a changed owner may independently serve
    its whole old or new record group; once ``t`` reaches the lifetime it
    serves only the new group, and unchanged owners are fixed.

    Every mixed snapshot reachable at ``t`` is evaluated with the same
    rules as :func:`evaluate`; a mix is *unsafe* when any query hits an
    alias error (CNAME loop / >8 hops) or its ``authorized`` /
    ``effective_owner`` pair differs from the all-new snapshot. A mix
    keeping the owner set ``O`` on old values is reachable exactly while
    ``t < min(stale_seconds[o] for o in O)``, so the earliest safe integer
    second is the maximum of that minimum over all unsafe mixes — 0 when
    no unsafe mix exists (in particular when nothing changed).

    Both snapshots are first evaluated in full, so any name/record/alias
    failure surfaces as a 422-grade :class:`CAAError`; more than
    ``MAX_CHANGED_OWNERS`` changed owners, or a ``stale_seconds`` map that
    does not name exactly the changed owners, also raise.

    Combinations are enumerated by increasing bitmask over the sorted
    changed owners (a set bit keeps that owner on its old group; mask 0 is
    the all-new snapshot itself and is therefore always safe). The first
    unsafe combination at ``t=0`` is reported with its sorted old-value
    owners and the first failing query in input order — a verdict
    mismatch yields ``query_id``, an alias error yields ``error``.
    """

    def pair_for(run, q: dict) -> tuple[bool, Optional[str]]:
        verdict = run(q["domain"], q.get("wildcard", False), q["ca"])
        return verdict["authorized"], verdict["effective_owner"]

    # Both snapshots must be fully valid for every query; any name, record
    # or alias failure surfaces exactly as in /v1/authorize. Each snapshot
    # gets one evaluator, prepared on first use and reused for its queries;
    # both share one snapshot cache with the mixed combinations below, so
    # a record group is prepared at most once per request.
    cache: dict[tuple, object] = {}
    before_eval = _evaluator_for(before, cache)
    for q in queries:
        pair_for(before_eval, q)
    after_eval = _evaluator_for(after, cache)
    baseline = [pair_for(after_eval, q) for q in queries]

    def owner_of(rec: dict) -> str:
        return normalize_name(rec.get("owner", ""), field="owner")

    def record_key(rec: dict) -> tuple:
        if rec.get("type") == "CAA":
            return (
                "CAA",
                int(rec["flag"]),
                str(rec["tag"]).strip().lower(),
                rec["value"],
            )
        return ("CNAME", normalize_name(rec.get("target", ""), field="target"))

    before_owners = [owner_of(rec) for rec in before]
    after_owners = [owner_of(rec) for rec in after]
    before_multi: dict[str, Counter] = {}
    for rec, owner in zip(before, before_owners):
        before_multi.setdefault(owner, Counter())[record_key(rec)] += 1
    after_multi: dict[str, Counter] = {}
    for rec, owner in zip(after, after_owners):
        after_multi.setdefault(owner, Counter())[record_key(rec)] += 1

    changed = sorted(
        owner
        for owner in set(before_multi) | set(after_multi)
        if before_multi.get(owner, Counter()) != after_multi.get(owner, Counter())
    )

    if len(changed) > MAX_CHANGED_OWNERS:
        raise CAAError(
            f"{len(changed)} changed owners; at most {MAX_CHANGED_OWNERS} allowed"
        )
    mapped = set(stale_seconds)
    if mapped != set(changed):
        parts = []
        missing = sorted(set(changed) - mapped)
        if missing:
            parts.append(f"missing lifetimes for {missing}")
        unexpected = sorted(mapped - set(changed))
        if unexpected:
            parts.append(f"unexpected owners {unexpected}")
        raise CAAError(
            "stale_seconds must name exactly the changed owners ("
            + "; ".join(parts)
            + ")"
        )

    changed_set = set(changed)

    def mixed_records(old_owners: set[str]) -> list[dict]:
        # Unchanged owners always serve their (identical) group; a changed
        # owner serves its old group when kept stale, else its new group.
        recs = [
            rec
            for rec, owner in zip(before, before_owners)
            if owner not in changed_set or owner in old_owners
        ]
        recs.extend(
            rec
            for rec, owner in zip(after, after_owners)
            if owner in changed_set and owner not in old_owners
        )
        return recs

    def mix_failure(run) -> Optional[dict]:
        # The mixed snapshot's evaluator prepares its record group once
        # (or reuses the shared cache) and serves every query. A
        # record/alias failure makes the mix unsafe without naming a
        # query; a verdict mismatch names the first failing query.
        try:
            for q, base in zip(queries, baseline):
                pair = pair_for(run, q)
                if pair != base:
                    return {"query_id": q["id"], "error": None}
        except CAAError as exc:
            return {"query_id": None, "error": exc.__class__.__name__}
        return None

    k = len(changed)
    safe_from = 0
    first_unsafe: Optional[dict] = None
    for mask in range(1 << k):
        old_owners = {changed[i] for i in range(k) if mask & (1 << i)}
        if not old_owners:
            # Mask 0 is the all-new snapshot: reuse its evaluator.
            failure = mix_failure(after_eval)
        elif old_owners == changed_set:
            # Every changed owner stale is the all-old snapshot: reuse
            # its evaluator instead of re-preparing the same records.
            failure = mix_failure(before_eval)
        else:
            failure = mix_failure(
                _evaluator_for(mixed_records(old_owners), cache)
            )
        if failure is None:
            continue
        # Mask 0 is the all-new snapshot and never fails, so old_owners is
        # non-empty here. The mix stays reachable while every owner it
        # keeps stale is unexpired: t < min lifetime over old_owners.
        horizon = min(stale_seconds[owner] for owner in old_owners)
        safe_from = max(safe_from, horizon)
        if first_unsafe is None:
            first_unsafe = {"old_owners": sorted(old_owners), **failure}

    return {
        "changed_owners": changed,
        "safe_from": safe_from,
        "first_unsafe": first_unsafe,
    }
