"""Offline ACME DNS-01 challenge verification for POST /v1/issuance/check-dns01.

Implements the DNS-01 validation semantics of RFC 8555 §8.4 against a
caller-supplied set of TXT/CNAME records, so no network access is
required:

* the challenge key authorization is ``token.thumbprint`` where
  ``thumbprint`` is the RFC 7638 JWK thumbprint of the caller's RSA JWK
  (canonical JSON of its base64url ``e``/``kty``/``n`` members hashed
  with SHA-256); the required TXT value is the unpadded base64url of
  ``SHA-256(token.thumbprint)``;
* every challenge — wildcard or not — is looked up at the exact owner
  ``_acme-challenge.<domain>``; the domain never carries a ``*``;
* a CNAME at that owner redirects the lookup to its target, and the
  chain is followed at the target only — the search never climbs to a
  parent name, and the chain must not loop or exceed 8 hops;
* TXT RRs are given as ordered ``chunks`` (the DNS wire string of one
  TXT RR is one character-string split over several 255-octet chunks);
  the chunks of one RR are concatenated in order and compared as a whole.

JWK/token parsing failures raise :class:`InvalidJWKError` /
:class:`InvalidTokenError`; record-set and alias failures reuse the
engine's 422-grade :class:`CAAError` hierarchy. A missing or mismatching
TXT RR is *not* a request error: the single challenge fails while the
rest of the batch is still evaluated.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Optional

from .engine import (
    CAAError,
    MAX_CNAME_HOPS,
    MAX_RECORDS,
    CNAMELimitError,
    CNAMELoopError,
    MixedRecordsError,
    MultipleCNAMEError,
    normalize_name,
)

ACME_CHALLENGE_LABEL = "_acme-challenge"
MAX_CHALLENGES = 20

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class InvalidJWKError(CAAError):
    """The RSA JWK (kty/n/e) is malformed; maps to HTTP 422."""


class InvalidTokenError(CAAError):
    """An ACME challenge token is not unpadded base64url; maps to 422."""


@dataclass(frozen=True)
class TXTRecord:
    owner: str
    chunks: tuple[str, ...]


@dataclass(frozen=True)
class PreparedDNSRecords:
    """Immutable index of a validated TXT/CNAME record set.

    ``txt_map`` maps each owner name to its TXT RRs in input order (each
    RR an ordered tuple of chunks); ``cname_map`` maps each owner name to
    its normalized CNAME target.
    """

    txt_map: Mapping[str, tuple[TXTRecord, ...]]
    cname_map: Mapping[str, str]


def _decode_base64url(raw: str, *, field: str) -> bytes:
    """Strictly decode an unpadded base64url string.

    Padding characters, characters outside the base64url alphabet and
    non-canonical encodings (length mod 4 equal to 1, or non-zero unused
    bits in the final quantum) are rejected; round-tripping the decoded
    bytes through the encoder enforces the canonical form.
    """
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{field} must be a non-empty base64url string")
    if "=" in raw or not _BASE64URL_RE.fullmatch(raw):
        raise ValueError(f"{field} must be unpadded base64url")
    try:
        data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception as exc:  # pragma: no cover - regex already tight
        raise ValueError(f"{field} is not valid base64url") from exc
    if base64.urlsafe_b64encode(data).rstrip(b"=") != raw.encode("ascii"):
        raise ValueError(f"{field} is not canonical base64url")
    return data


def validate_rsa_jwk(jwk: object) -> dict:
    """Validate an RSA public JWK and return its canonical members.

    Only ``kty``/``n``/``e`` are required (RFC 7517 permits and ignores
    additional members); ``kty`` must be the exact string ``RSA`` and
    both ``n`` and ``e`` must be non-empty unpadded base64url encodings
    of positive big-endian integers without a leading zero octet, as the
    JWK RSA representation mandates. The modulus and public exponent
    must additionally be odd integers (an RSA public key is a pair of
    odd numbers). Returns ``{"kty", "n", "e"}`` with the original
    base64url strings, suitable both for thumbprinting and the schema.
    """
    if not isinstance(jwk, dict):
        raise InvalidJWKError("jwk must be a JSON object")
    kty = jwk.get("kty")
    if kty != "RSA":
        raise InvalidJWKError("jwk.kty must be the string 'RSA'")

    def member(name: str) -> str:
        value = jwk.get(name)
        try:
            data = _decode_base64url(value, field=f"jwk.{name}")
        except ValueError as exc:
            raise InvalidJWKError(str(exc)) from exc
        if not data:
            raise InvalidJWKError(f"jwk.{name} must not be zero")
        if data[0] == 0:
            raise InvalidJWKError(
                f"jwk.{name} must not carry a leading zero octet"
            )
        number = int.from_bytes(data, "big")
        if number == 0:
            raise InvalidJWKError(f"jwk.{name} must be a positive integer")
        if number % 2 == 0:
            raise InvalidJWKError(f"jwk.{name} must be an odd integer")
        return value

    n = member("n")
    e = member("e")
    if int.from_bytes(_decode_base64url(e, field="jwk.e"), "big") < 3:
        raise InvalidJWKError("jwk.e must be at least 3")
    return {"kty": "RSA", "n": n, "e": e}


def jwk_thumbprint(members: Mapping[str, str]) -> str:
    """Return the RFC 7638 JWK thumbprint (unpadded base64url SHA-256).

    The thumbprint hashes the UTF-8 JSON object containing exactly the
    members ``e``, ``kty`` and ``n`` with lexicographically sorted keys
    and no insignificant whitespace.
    """
    canonical = json.dumps(
        {"e": members["e"], "kty": members["kty"], "n": members["n"]},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def validate_token(token: object, *, field: str = "token") -> str:
    """Validate an ACME challenge token: non-empty unpadded base64url."""
    try:
        _decode_base64url(token, field=field)
    except ValueError as exc:
        raise InvalidTokenError(str(exc)) from exc
    return token


def prepare_dns_records(records: list[dict]) -> PreparedDNSRecords:
    """Validate raw TXT/CNAME record dicts and freeze them into an index.

    Owners are normalized case-insensitively with a single trailing dot
    stripped; underscore labels are accepted (``_acme-challenge``).
    Owners mixing TXT and CNAME records, or carrying multiple CNAME
    records, are rejected exactly as the CAA engine does. TXT RRs keep
    their input order; the ordered ``chunks`` of every RR are preserved.
    """
    if len(records) > MAX_RECORDS:
        raise CAAError(
            f"record set has {len(records)} records; at most {MAX_RECORDS} allowed"
        )

    txt_map: dict[str, list[TXTRecord]] = {}
    cname_map: dict[str, str] = {}

    for rec in records:
        kind = rec.get("type")
        owner = normalize_name(
            rec.get("owner", ""), field="owner", allow_underscore=True
        )
        if kind == "TXT":
            if owner in cname_map:
                raise MixedRecordsError(
                    f"owner {owner!r} mixes CNAME and TXT records"
                )
            chunks = tuple(str(chunk) for chunk in rec.get("chunks", []))
            txt_map.setdefault(owner, []).append(TXTRecord(owner, chunks))
        elif kind == "CNAME":
            if owner in txt_map:
                raise MixedRecordsError(
                    f"owner {owner!r} mixes CNAME and TXT records"
                )
            if owner in cname_map:
                raise MultipleCNAMEError(
                    f"owner {owner!r} has multiple CNAME records"
                )
            cname_map[owner] = normalize_name(
                rec.get("target", ""), field="target", allow_underscore=True
            )
        else:  # pragma: no cover - rejected by the schema layer
            raise CAAError(f"unknown record type {kind!r}")

    return PreparedDNSRecords(
        txt_map=MappingProxyType(
            {owner: tuple(rrs) for owner, rrs in txt_map.items()}
        ),
        cname_map=MappingProxyType(cname_map),
    )


def _resolve_cname(
    qname: str, snapshot: PreparedDNSRecords
) -> tuple[str, int, list[str]]:
    """Resolve an exact-name CNAME chain without climbing to parents.

    Returns the terminal name, the number of CNAME hops taken and the
    visited chain (starting with ``qname``). Revisiting any name is a
    loop; following more than :data:`~app.engine.MAX_CNAME_HOPS` aliases
    trips the hop limit — both 422-grade failures.
    """
    cname_map = snapshot.cname_map
    current = qname
    hops = 0
    seen: set[str] = set()
    chain: list[str] = []
    while True:
        if current in seen:
            raise CNAMELoopError(
                f"CNAME loop detected at {current!r} "
                f"(path: {' -> '.join(chain + [current])})"
            )
        seen.add(current)
        chain.append(current)
        target = cname_map.get(current)
        if target is None:
            return current, hops, chain
        if hops >= MAX_CNAME_HOPS:
            raise CNAMELimitError(
                f"CNAME chain exceeds {MAX_CNAME_HOPS} hops from {qname!r}"
            )
        hops += 1
        current = target


def _expected_txt(token: str, thumbprint: str) -> str:
    """Compute the DNS-01 TXT value: base64url(SHA-256(token.thumbprint))."""
    key_authorization = f"{token}.{thumbprint}".encode("ascii")
    digest = hashlib.sha256(key_authorization).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def check_dns01(
    jwk: object, challenges: list[dict], records: list[dict]
) -> dict:
    """Verify a batch of DNS-01 challenges against one record snapshot.

    The RSA JWK and every challenge token are validated first (a bad JWK
    or token rejects the whole request with 422), then the TXT/CNAME
    record set is prepared once and shared by every challenge. Each
    challenge is resolved independently at its exact
    ``_acme-challenge.<domain>`` owner; alias failures (loop, >8 hops,
    mixed records) reject the request, while a missing or mismatching TXT
    RR only fails that challenge. Results are returned in challenge
    input order; the overall ``valid`` is true exactly when every
    challenge passed.
    """
    members = validate_rsa_jwk(jwk)
    thumbprint = jwk_thumbprint(members)

    # Validate every token before touching records so one malformed
    # challenge fails the whole request rather than half the batch.
    for challenge in challenges:
        validate_token(challenge.get("token"), field="token")

    snapshot = prepare_dns_records(records)

    results: list[dict] = []
    for challenge in challenges:
        cid = challenge["id"]
        domain = normalize_name(challenge["domain"], field="domain")
        wildcard = bool(challenge.get("wildcard", False))
        token = challenge["token"]
        qname = normalize_name(
            f"{ACME_CHALLENGE_LABEL}.{domain}",
            field="challenge owner",
            allow_underscore=True,
        )
        expected = _expected_txt(token, thumbprint)

        terminal, hops, chain = _resolve_cname(qname, snapshot)
        observed = ["".join(rr.chunks) for rr in snapshot.txt_map.get(terminal, ())]

        if hops:
            location = f"{qname} -> {terminal}"
            hop_note = f"after {hops} CNAME hop(s), "
        else:
            location = terminal
            hop_note = ""

        if expected in observed:
            valid = True
            reason = (
                f"TXT at {location} ({hop_note}ordered chunk concatenation) "
                f"matches the DNS-01 digest for token {token!r}"
            )
        elif not observed:
            valid = False
            reason = (
                f"no TXT records at {location} ({hop_note}exact-name lookup); "
                f"expected digest {expected!r}"
            )
        else:
            valid = False
            reason = (
                f"no TXT RR at {location} ({hop_note}ordered chunk "
                f"concatenation) equals the expected digest {expected!r}; "
                f"observed {observed}"
            )

        results.append(
            {
                "id": cid,
                "domain": domain,
                "wildcard": wildcard,
                "qname": qname,
                "valid": valid,
                "cname_hops": hops,
                "cname_chain": chain,
                "txt_owner": terminal,
                "expected_txt": expected,
                "observed_txt": observed,
                "reason": reason,
            }
        )

    passed = sum(1 for item in results if item["valid"])
    overall_valid = passed == len(results)
    if overall_valid:
        reason = f"all {len(results)} DNS-01 challenge(s) verified"
    else:
        failed = [item["id"] for item in results if not item["valid"]]
        reason = (
            f"{len(failed)} of {len(results)} DNS-01 challenge(s) failed: {failed}"
        )
    return {
        "thumbprint": thumbprint,
        "valid": overall_valid,
        "reason": reason,
        "results": results,
    }
