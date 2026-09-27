"""Pydantic request/response models for the CAA authorization API."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, Field, StrictBool, StrictStr, field_validator, model_validator

from .engine import normalize_name

ALLOWED_FLAGS = (0, 128)
VALUE_TAGS = ("issue", "issuewild")


class CAARecord(BaseModel):
    """A single CAA resource record."""

    type: Literal["CAA"] = "CAA"
    owner: str = Field(..., min_length=1, description="Record owner name")
    flag: int = Field(..., description="CAA flags byte; only 0 or 128 accepted")
    tag: str = Field(..., min_length=1, max_length=15, description="CAA tag")
    value: str = Field("", description="Tag value; domain or empty for issue/issuewild")

    @field_validator("owner")
    @classmethod
    def _norm_owner(cls, v: str) -> str:
        return normalize_name(v, field="owner")

    @field_validator("flag")
    @classmethod
    def _check_flag(cls, v: int) -> int:
        if v not in ALLOWED_FLAGS:
            raise ValueError("flag must be 0 or 128")
        return v

    @field_validator("tag")
    @classmethod
    def _norm_tag(cls, v: str) -> str:
        tag = v.strip().lower()
        if not tag or len(tag) > 15:
            raise ValueError("tag must be 1-15 characters")
        if not all(c.isascii() and c.isalnum() for c in tag):
            raise ValueError("tag may only contain letters and digits")
        return tag

    @model_validator(mode="after")
    def _norm_value(self) -> "CAARecord":
        if self.tag in VALUE_TAGS:
            if self.value == "":
                return self
            if ";" in self.value or " " in self.value:
                raise ValueError(
                    f"{self.tag} value must be a bare domain or an empty string "
                    "(parameters are not accepted)"
                )
            # normalize_name raises on bad domains -> 422
            object.__setattr__(self, "value", normalize_name(self.value, field="value"))
        return self


class CNAMERecordModel(BaseModel):
    """A single CNAME resource record."""

    type: Literal["CNAME"]
    owner: str = Field(..., min_length=1, description="Record owner name")
    target: str = Field(..., min_length=1, description="CNAME target name")

    @field_validator("owner")
    @classmethod
    def _norm_owner(cls, v: str) -> str:
        return normalize_name(v, field="owner")

    @field_validator("target")
    @classmethod
    def _norm_target(cls, v: str) -> str:
        return normalize_name(v, field="target")


Record = Union[CAARecord, CNAMERecordModel]


class AuthorizeRequest(BaseModel):
    domain: str = Field(..., description="Fully-qualified domain name to authorize")
    wildcard: StrictBool = Field(
        False, description="Whether a wildcard certificate (*.domain) is requested"
    )
    ca: str = Field(..., description="Issuing CA domain name")
    records: list[Record] = Field(
        default_factory=list,
        max_length=100,
        description="Up to 100 CAA/CNAME records used as the offline DNS view",
    )

    @field_validator("domain")
    @classmethod
    def _norm_domain(cls, v: str) -> str:
        return normalize_name(v, field="domain")

    @field_validator("ca")
    @classmethod
    def _norm_ca(cls, v: str) -> str:
        return normalize_name(v, field="ca")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "domain": "www.example.com",
                    "wildcard": False,
                    "ca": "letsencrypt.org",
                    "records": [
                        {
                            "type": "CAA",
                            "owner": "example.com",
                            "flag": 0,
                            "tag": "issue",
                            "value": "letsencrypt.org",
                        }
                    ],
                }
            ]
        }
    }


class TraceStepOut(BaseModel):
    query: str
    kind: str
    cname_target: Optional[str] = None
    cname_hops: int = 0
    caa: Optional[list[dict]] = None


class AuthorizeResponse(BaseModel):
    authorized: bool
    effective_owner: Optional[str]
    matched_tag: Optional[str]
    matched_value: Optional[str]
    reason: str
    trace: list[TraceStepOut]


class ProtectedQuery(BaseModel):
    """A domain/CA pair whose authorization verdict must be preserved."""

    domain: str = Field(..., description="Domain name whose verdict is protected")
    wildcard: StrictBool = Field(
        False, description="Whether the protected query is for a wildcard name"
    )
    ca: str = Field(..., description="CA domain name whose verdict is protected")

    @field_validator("domain")
    @classmethod
    def _norm_domain(cls, v: str) -> str:
        return normalize_name(v, field="domain")

    @field_validator("ca")
    @classmethod
    def _norm_ca(cls, v: str) -> str:
        return normalize_name(v, field="ca")


class PatchPlanRequest(BaseModel):
    domain: str = Field(..., description="Fully-qualified domain name to authorize")
    wildcard: StrictBool = Field(
        False, description="Whether a wildcard certificate (*.domain) is requested"
    )
    ca: str = Field(..., description="Issuing CA domain name")
    records: list[Record] = Field(
        default_factory=list,
        max_length=99,
        description="Up to 99 CAA/CNAME records used as the offline DNS view",
    )
    protected: list[ProtectedQuery] = Field(
        default_factory=list,
        max_length=20,
        description="Up to 20 queries whose authorized verdicts must not change",
    )

    @field_validator("domain")
    @classmethod
    def _norm_domain(cls, v: str) -> str:
        return normalize_name(v, field="domain")

    @field_validator("ca")
    @classmethod
    def _norm_ca(cls, v: str) -> str:
        return normalize_name(v, field="ca")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "domain": "www.example.com",
                    "wildcard": False,
                    "ca": "letsencrypt.org",
                    "records": [
                        {
                            "type": "CAA",
                            "owner": "example.com",
                            "flag": 0,
                            "tag": "issue",
                            "value": "pki.goog",
                        }
                    ],
                    "protected": [
                        {"domain": "api.example.com", "wildcard": False, "ca": "pki.goog"}
                    ],
                }
            ]
        }
    }


class AddedCAARecord(BaseModel):
    """The single CAA record the plan adds to the record set."""

    type: Literal["CAA"] = "CAA"
    owner: str
    flag: int
    tag: str
    value: str


class PatchPlanResponse(BaseModel):
    status: Literal["patched", "already_authorized", "no_solution"]
    added_record: Optional[AddedCAARecord]
    before_effective_owner: Optional[str]
    after_effective_owner: Optional[str]
    reason: str


class CACapacity(BaseModel):
    """A CA and the number of requests it may issue."""

    ca: str = Field(..., description="Issuing CA domain name")
    capacity: int = Field(
        ..., ge=0, le=12, description="How many requests this CA may issue (0-12)"
    )

    @field_validator("ca")
    @classmethod
    def _norm_ca(cls, v: str) -> str:
        return normalize_name(v, field="ca")


class IssuanceRequestItem(BaseModel):
    """One issuance request with an ordered, non-empty candidate CA list."""

    id: str = Field(..., min_length=1, description="Caller-chosen unique request id")
    domain: str = Field(..., description="Fully-qualified domain name to issue for")
    wildcard: StrictBool = Field(
        False, description="Whether a wildcard certificate (*.domain) is requested"
    )
    candidates: list[str] = Field(
        ...,
        min_length=1,
        max_length=4,
        description=(
            "Ordered candidate CA names; non-empty, without duplicates, and "
            "each chosen from the request's capacity list"
        ),
    )

    @field_validator("id")
    @classmethod
    def _non_blank_id(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("id must not be blank")
        return v

    @field_validator("domain")
    @classmethod
    def _norm_domain(cls, v: str) -> str:
        return normalize_name(v, field="domain")

    @field_validator("candidates")
    @classmethod
    def _norm_candidates(cls, v: list[str]) -> list[str]:
        return [normalize_name(c, field="candidate") for c in v]


class IssuanceRouteRequest(BaseModel):
    cas: list[CACapacity] = Field(
        ...,
        min_length=1,
        max_length=4,
        description="1-4 unique CAs and per-CA issuance capacity (0-12)",
    )
    requests: list[IssuanceRequestItem] = Field(
        ..., min_length=1, max_length=12, description="1-12 issuance requests"
    )
    records: list[Record] = Field(
        default_factory=list,
        max_length=100,
        description="Up to 100 CAA/CNAME records used as the offline DNS view",
    )

    @model_validator(mode="after")
    def _check_cross_references(self) -> "IssuanceRouteRequest":
        ca_names = [c.ca for c in self.cas]
        if len(set(ca_names)) != len(ca_names):
            raise ValueError("cas must be unique")
        allowed = set(ca_names)

        ids = [r.id for r in self.requests]
        if len(set(ids)) != len(ids):
            raise ValueError("request ids must be unique")

        for req in self.requests:
            if len(set(req.candidates)) != len(req.candidates):
                raise ValueError(
                    f"candidates of request {req.id!r} must not repeat a CA"
                )
            unknown = [c for c in req.candidates if c not in allowed]
            if unknown:
                raise ValueError(
                    f"candidate {unknown[0]!r} of request {req.id!r} is not in "
                    "the cas capacity list"
                )
        return self

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "cas": [
                        {"ca": "letsencrypt.org", "capacity": 1},
                        {"ca": "pki.goog", "capacity": 2},
                    ],
                    "requests": [
                        {
                            "id": "r1",
                            "domain": "a.example.com",
                            "wildcard": False,
                            "candidates": ["letsencrypt.org", "pki.goog"],
                        },
                        {
                            "id": "r2",
                            "domain": "b.example.com",
                            "wildcard": False,
                            "candidates": ["letsencrypt.org"],
                        },
                    ],
                    "records": [
                        {
                            "type": "CAA",
                            "owner": "example.com",
                            "flag": 0,
                            "tag": "issue",
                            "value": "letsencrypt.org",
                        }
                    ],
                }
            ]
        }
    }


class IssuanceResult(BaseModel):
    id: str
    assigned_ca: Optional[str] = None
    reason: Optional[str] = None


class CAUsage(BaseModel):
    ca: str
    capacity: int
    used: int


class IssuanceRouteResponse(BaseModel):
    assigned: int
    results: list[IssuanceResult]
    usage: list[CAUsage]


class CheckCSRRequest(BaseModel):
    """A PEM PKCS#10 CSR to verify and authorize against the record set."""

    csr: str = Field(
        ...,
        min_length=1,
        description="PEM-encoded PKCS#10 CSR; at most 64 KiB (65536 UTF-8 bytes)",
    )
    ca: str = Field(..., description="Issuing CA domain name")
    records: list[Record] = Field(
        default_factory=list,
        max_length=100,
        description="Up to 100 CAA/CNAME records used as the offline DNS view",
    )

    @field_validator("ca")
    @classmethod
    def _norm_ca(cls, v: str) -> str:
        return normalize_name(v, field="ca")


class CSRIdentifierResult(BaseModel):
    """Authorization outcome for one SAN DNS name, in SAN input order."""

    name: str = Field(
        ..., description="Normalized SAN DNS name ('*.name' for a wildcard)"
    )
    wildcard: bool = Field(
        ..., description="Whether the SAN name is a leftmost '*.name' wildcard"
    )
    domain: str = Field(
        ..., description="Name actually queried against CAA ('*.' stripped)"
    )
    authorized: bool
    effective_owner: Optional[str]
    reason: str
    trace: list[TraceStepOut]


class CheckCSRResponse(BaseModel):
    csr_sha256: str = Field(
        ..., description="SHA-256 of the CSR DER encoding, lowercase hex"
    )
    authorized: bool = Field(
        ..., description="True only when every SAN identifier is authorized"
    )
    reason: str
    identifiers: list[CSRIdentifierResult] = Field(
        ..., description="Per-identifier results in SAN input order"
    )


class RSAJWK(BaseModel):
    """RSA public key in JWK form (RFC 7517 §6.3).

    Only ``kty``/``n``/``e`` participate in validation; any additional
    members (``alg``, ``kid``, ...) are accepted and ignored. The
    base64url/value checks run in the engine and surface as 422.
    """

    kty: str = Field(..., description="Key type; must be the string 'RSA'")
    n: str = Field(..., description="RSA modulus, unpadded base64url")
    e: str = Field(..., description="RSA public exponent, unpadded base64url")


class DNS01TXTRecordModel(BaseModel):
    """A TXT resource record as an ordered list of wire string chunks."""

    type: Literal["TXT"]
    owner: StrictStr = Field(..., min_length=1, description="Record owner name")
    chunks: list[StrictStr] = Field(
        ...,
        description=(
            "TXT character-strings in wire order; concatenated in this order "
            "and compared as one string (a long DNS string is split across "
            "multiple <=255-octet chunks)"
        ),
    )

    @field_validator("owner")
    @classmethod
    def _norm_owner(cls, v: str) -> str:
        return normalize_name(v, field="owner", allow_underscore=True)


class DNS01CNAMERecordModel(BaseModel):
    """A CNAME resource record for the DNS-01 offline view."""

    type: Literal["CNAME"]
    owner: StrictStr = Field(..., min_length=1, description="Record owner name")
    target: StrictStr = Field(..., min_length=1, description="CNAME target name")

    @field_validator("owner")
    @classmethod
    def _norm_owner(cls, v: str) -> str:
        return normalize_name(v, field="owner", allow_underscore=True)

    @field_validator("target")
    @classmethod
    def _norm_target(cls, v: str) -> str:
        return normalize_name(v, field="target", allow_underscore=True)


DNS01Record = Union[DNS01TXTRecordModel, DNS01CNAMERecordModel]


class DNS01Challenge(BaseModel):
    """One ACME DNS-01 challenge to verify offline."""

    id: StrictStr = Field(..., min_length=1, description="Caller-chosen unique id")
    domain: StrictStr = Field(
        ...,
        description=(
            "Challenge domain without the '*' marker; the lookup owner is "
            "_acme-challenge.<domain> for both wildcard and non-wildcard "
            "challenges"
        ),
    )
    wildcard: StrictBool = Field(
        False, description="Whether the challenge authorizes a wildcard name"
    )
    token: StrictStr = Field(
        ..., description="ACME challenge token: non-empty, unpadded base64url"
    )

    @field_validator("id")
    @classmethod
    def _non_blank_id(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("id must not be blank")
        return v

    @field_validator("domain")
    @classmethod
    def _norm_domain(cls, v: str) -> str:
        return normalize_name(v, field="domain")


class CheckDNS01Request(BaseModel):
    """RSA JWK, 1-20 unique-id DNS-01 challenges and the offline TXT/CNAME view."""

    jwk: RSAJWK
    challenges: list[DNS01Challenge] = Field(
        ..., min_length=1, max_length=20, description="1-20 challenges with unique ids"
    )
    records: list[DNS01Record] = Field(
        default_factory=list,
        max_length=100,
        description="Up to 100 TXT/CNAME records used as the offline DNS view",
    )

    @model_validator(mode="after")
    def _check_unique_ids(self) -> "CheckDNS01Request":
        ids = [c.id for c in self.challenges]
        if len(set(ids)) != len(ids):
            raise ValueError("challenge ids must be unique")
        return self

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "jwk": {
                        "kty": "RSA",
                        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                        "e": "AQAB",
                    },
                    "challenges": [
                        {
                            "id": "ch1",
                            "domain": "example.com",
                            "wildcard": False,
                            "token": "DGyRejmCefe7v4NfDGDKfA",
                        }
                    ],
                    "records": [
                        {
                            "type": "TXT",
                            "owner": "_acme-challenge.example.com",
                            "chunks": ["Bs72Q7B-BSSQo4oDjA2qBR07GB6sc3hiG9zqaqvHx7U"],
                        }
                    ],
                }
            ]
        }
    }


class DNS01ChallengeResult(BaseModel):
    """Verification outcome for one challenge, in input order."""

    id: str
    domain: str = Field(..., description="Normalized domain ('*' never included)")
    wildcard: bool
    qname: str = Field(..., description="The exact _acme-challenge.<domain> owner")
    valid: bool
    cname_hops: int = Field(..., description="CNAME hops followed (0-8)")
    cname_chain: list[str] = Field(
        ..., description="Exact-name chain walked, starting with qname"
    )
    txt_owner: str = Field(..., description="Name whose TXT RRs were compared")
    expected_txt: str = Field(..., description="Required digest, unpadded base64url")
    observed_txt: list[str] = Field(
        ..., description="Concatenated chunk strings of every TXT RR at txt_owner"
    )
    reason: str


class CheckDNS01Response(BaseModel):
    thumbprint: str = Field(
        ..., description="RFC 7638 JWK thumbprint, unpadded base64url SHA-256"
    )
    valid: bool = Field(
        ..., description="True only when every challenge verifies"
    )
    reason: str
    results: list[DNS01ChallengeResult]


class ImportZoneRequest(BaseModel):
    """BIND zone text to import under an absolute origin."""

    origin: str = Field(
        ...,
        min_length=1,
        description="Absolute zone origin (must end with '.')",
    )
    zone: str = Field(
        ...,
        description="BIND master-file text; at most 64 KiB (65536 UTF-8 bytes)",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "origin": "example.com.",
                    "zone": (
                        "$TTL 3600\n"
                        "@ IN CAA 0 issue \"letsencrypt.org\"\n"
                        "www 300 IN CNAME edge.cdn.example.\n"
                    ),
                }
            ]
        }
    }


class ExportZoneRequest(BaseModel):
    """CAA/CNAME records to render as a BIND zone fragment."""

    origin: str = Field(
        ...,
        min_length=1,
        description="Absolute zone origin (must end with '.'); every record "
        "owner must equal it or lie below it",
    )
    default_ttl: int = Field(
        ...,
        ge=1,
        le=86400,
        description="Default TTL in seconds, emitted as the $TTL directive",
    )
    records: list[Record] = Field(
        default_factory=list,
        max_length=100,
        description="Up to 100 CAA/CNAME records, exported in this order",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "origin": "example.com.",
                    "default_ttl": 3600,
                    "records": [
                        {
                            "type": "CAA",
                            "owner": "example.com",
                            "flag": 0,
                            "tag": "issue",
                            "value": "letsencrypt.org",
                        },
                        {
                            "type": "CNAME",
                            "owner": "www.example.com",
                            "target": "edge.cdn.example",
                        },
                    ],
                }
            ]
        }
    }


class ChangeImpactEdit(BaseModel):
    """One batch edit: either remove a baseline record by zero-based index
    or add a new record. Exactly one of ``remove`` / ``add`` must be given."""

    remove: Optional[int] = Field(
        None,
        ge=0,
        description="Zero-based index into the baseline records to remove",
    )
    add: Optional[Record] = Field(None, description="New CAA/CNAME record to append")

    @model_validator(mode="after")
    def _exactly_one_action(self) -> "ChangeImpactEdit":
        if self.remove is None and self.add is None:
            raise ValueError("edit must set either 'remove' or 'add'")
        if self.remove is not None and self.add is not None:
            raise ValueError("edit may not set both 'remove' and 'add'")
        return self


class ImpactQuery(BaseModel):
    """A domain/CA pair whose authorization verdict is compared across edits."""

    id: str = Field(..., min_length=1, description="Caller-chosen unique query id")
    domain: str = Field(..., description="Fully-qualified domain name to authorize")
    wildcard: StrictBool = Field(
        False, description="Whether a wildcard certificate (*.domain) is requested"
    )
    ca: str = Field(..., description="Issuing CA domain name")

    @field_validator("id")
    @classmethod
    def _non_blank_id(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("id must not be blank")
        return v

    @field_validator("domain")
    @classmethod
    def _norm_domain(cls, v: str) -> str:
        return normalize_name(v, field="domain")

    @field_validator("ca")
    @classmethod
    def _norm_ca(cls, v: str) -> str:
        return normalize_name(v, field="ca")


class ChangeImpactRequest(BaseModel):
    records: list[Record] = Field(
        default_factory=list,
        max_length=100,
        description="Up to 100 CAA/CNAME records used as the baseline DNS view",
    )
    edits: list[ChangeImpactEdit] = Field(
        ...,
        min_length=1,
        max_length=8,
        description="1-8 edits applied together; remove indices are zero-based "
        "positions in the baseline and must not repeat, adds are appended in order",
    )
    queries: list[ImpactQuery] = Field(
        ...,
        min_length=1,
        max_length=20,
        description="1-20 queries with unique ids compared before vs after the edits",
    )

    @model_validator(mode="after")
    def _check_cross_references(self) -> "ChangeImpactRequest":
        ids = [q.id for q in self.queries]
        if len(set(ids)) != len(ids):
            raise ValueError("query ids must be unique")

        removes = [e.remove for e in self.edits if e.remove is not None]
        if len(set(removes)) != len(removes):
            raise ValueError("remove indices must not repeat")
        out_of_range = [i for i in removes if i >= len(self.records)]
        if out_of_range:
            raise ValueError(
                f"remove index {out_of_range[0]} is out of range for "
                f"{len(self.records)} baseline records"
            )
        return self

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "records": [
                        {
                            "type": "CAA",
                            "owner": "example.com",
                            "flag": 0,
                            "tag": "issue",
                            "value": "pki.goog",
                        }
                    ],
                    "edits": [
                        {
                            "add": {
                                "type": "CAA",
                                "owner": "www.example.com",
                                "flag": 0,
                                "tag": "issue",
                                "value": "letsencrypt.org",
                            }
                        }
                    ],
                    "queries": [
                        {
                            "id": "www-le",
                            "domain": "www.example.com",
                            "wildcard": False,
                            "ca": "letsencrypt.org",
                        }
                    ],
                }
            ]
        }
    }


class ImpactFlip(BaseModel):
    id: str
    before_authorized: bool
    after_authorized: bool
    before_effective_owner: Optional[str]
    after_effective_owner: Optional[str]
    minimal_edits: list[int] = Field(
        ...,
        description="Zero-based indices of the smallest edit subset that alone "
        "reproduces after_authorized; lexicographically smallest list on ties",
    )


class ChangeImpactResponse(BaseModel):
    flips: list[ImpactFlip]


class RolloutWindowRequest(BaseModel):
    """Two-snapshot rollout: find the first second every old/new mix is safe."""

    before: list[Record] = Field(
        default_factory=list,
        max_length=100,
        description="Up to 100 CAA/CNAME records: the old DNS view",
    )
    after: list[Record] = Field(
        default_factory=list,
        max_length=100,
        description="Up to 100 CAA/CNAME records: the new DNS view",
    )
    queries: list[ImpactQuery] = Field(
        ...,
        min_length=1,
        max_length=12,
        description="1-12 queries with unique ids checked on every mixed snapshot",
    )
    stale_seconds: dict[str, Annotated[int, Field(ge=1, le=86400)]] = Field(
        default_factory=dict,
        description="Stale lifetime in seconds (1-86400) per changed owner; "
        "must name exactly the owners whose record multiset changed",
    )

    @field_validator("stale_seconds")
    @classmethod
    def _norm_stale_owners(cls, v: dict[str, int]) -> dict[str, int]:
        out: dict[str, int] = {}
        for owner, secs in v.items():
            name = normalize_name(owner, field="stale_seconds owner")
            if name in out:
                raise ValueError(
                    f"stale_seconds owner {name!r} repeats after normalization"
                )
            out[name] = secs
        return out

    @model_validator(mode="after")
    def _check_unique_ids(self) -> "RolloutWindowRequest":
        ids = [q.id for q in self.queries]
        if len(set(ids)) != len(ids):
            raise ValueError("query ids must be unique")
        return self

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "before": [
                        {
                            "type": "CAA",
                            "owner": "example.com",
                            "flag": 0,
                            "tag": "issue",
                            "value": "pki.goog",
                        }
                    ],
                    "after": [
                        {
                            "type": "CAA",
                            "owner": "example.com",
                            "flag": 0,
                            "tag": "issue",
                            "value": "letsencrypt.org",
                        }
                    ],
                    "queries": [
                        {
                            "id": "q-le",
                            "domain": "www.example.com",
                            "wildcard": False,
                            "ca": "letsencrypt.org",
                        }
                    ],
                    "stale_seconds": {"example.com": 30},
                }
            ]
        }
    }


class FirstUnsafeCombination(BaseModel):
    """The first unsafe mixed snapshot at t=0."""

    old_owners: list[str] = Field(
        ..., description="Sorted changed owners serving their old record group"
    )
    query_id: Optional[str] = Field(
        None,
        description="First query whose authorized/effective_owner differs from "
        "the all-new snapshot; null when an alias error hit first",
    )
    error: Optional[str] = Field(
        None,
        description="Alias error type (e.g. CNAMELoopError) when the "
        "combination cannot be resolved; null on verdict mismatches",
    )


class RolloutWindowResponse(BaseModel):
    changed_owners: list[str] = Field(
        ..., description="Owners whose normalized record multiset changed, sorted"
    )
    safe_from: int = Field(
        ...,
        description="Earliest integer second at which every old/new mix is "
        "safe; 0 when no unsafe mix exists",
    )
    first_unsafe: Optional[FirstUnsafeCombination] = Field(
        ..., description="First unsafe combination at t=0; null when t=0 is safe"
    )


class MinimizeRequest(BaseModel):
    """Record-set minimization: delete records without changing verdicts."""

    records: list[Record] = Field(
        ...,
        min_length=1,
        max_length=12,
        description="1-12 CAA/CNAME records; the minimized result is a "
        "subsequence of this list (deletions only)",
    )
    queries: list[ImpactQuery] = Field(
        ...,
        min_length=1,
        max_length=12,
        description="1-12 queries with unique ids whose authorized and "
        "effective_owner baseline results must be preserved",
    )

    @model_validator(mode="after")
    def _check_unique_ids(self) -> "MinimizeRequest":
        ids = [q.id for q in self.queries]
        if len(set(ids)) != len(ids):
            raise ValueError("query ids must be unique")
        return self

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "records": [
                        {
                            "type": "CAA",
                            "owner": "example.com",
                            "flag": 0,
                            "tag": "issue",
                            "value": "letsencrypt.org",
                        },
                        {
                            "type": "CAA",
                            "owner": "other.net",
                            "flag": 0,
                            "tag": "issue",
                            "value": "pki.goog",
                        },
                    ],
                    "queries": [
                        {
                            "id": "www-le",
                            "domain": "www.example.com",
                            "wildcard": False,
                            "ca": "letsencrypt.org",
                        }
                    ],
                }
            ]
        }
    }


class MinimizeQueryResult(BaseModel):
    """Baseline verdict for one submitted query."""

    id: str
    authorized: bool
    effective_owner: Optional[str]


class MinimizeResponse(BaseModel):
    kept: list[int] = Field(
        ..., description="Zero-based indices of the kept records, ascending"
    )
    removed: list[int] = Field(
        ..., description="Zero-based indices of the deleted records, ascending"
    )
    records: list[Record] = Field(
        ..., description="Minimized records in their original order"
    )
    queries: list[MinimizeQueryResult] = Field(
        ...,
        description="Baseline authorized/effective_owner per query, "
        "in query input order",
    )


class ImportedRecord(BaseModel):
    """One exported record: an authorize-ready CAA/CNAME record plus its line.

    ``flag``/``tag``/``value`` are set for CAA records, ``target`` for
    CNAME records; the response omits the unset fields, so each item can
    be passed straight into the ``records`` list of ``/v1/authorize``
    (the extra ``line`` field is ignored there).
    """

    line: int
    type: Literal["CAA", "CNAME"]
    owner: str
    flag: Optional[int] = None
    tag: Optional[str] = None
    value: Optional[str] = None
    target: Optional[str] = None


class ImportZoneResponse(BaseModel):
    origin: str
    count: int
    records: list[ImportedRecord]


class ExportZoneResponse(BaseModel):
    zone: str = Field(
        ...,
        description="BIND zone fragment (starts with $ORIGIN/$TTL); "
        "re-importing it via /v1/records/import-zone reproduces the "
        "normalized records in their original order",
    )


class CheckOCSPRequest(BaseModel):
    """Leaf/issuer PEM certificates, a Base64 DER OCSP response and the
    UTC verification instant for an offline OCSP check."""

    leaf_certificate: StrictStr = Field(
        ..., min_length=1, description="PEM-encoded leaf (end-entity) certificate"
    )
    issuer_certificate: StrictStr = Field(
        ..., min_length=1, description="PEM-encoded issuer certificate"
    )
    ocsp_response: StrictStr = Field(
        ...,
        min_length=1,
        description=(
            "Base64-encoded DER OCSP response (standard alphabet, whitespace "
            "allowed); at most 64 KiB after decoding"
        ),
    )
    verification_time: datetime = Field(
        ...,
        description=(
            "UTC instant at which the response is evaluated; must carry a "
            "timezone designator (e.g. '2026-01-01T00:00:00Z')"
        ),
    )

    @field_validator("verification_time")
    @classmethod
    def _require_timezone(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError(
                "verification_time must be timezone-aware (use a 'Z' suffix "
                "or an explicit UTC offset)"
            )
        return v

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "leaf_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
                    "issuer_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
                    "ocsp_response": "MIIFzBA...",
                    "verification_time": "2026-01-02T12:00:00Z",
                }
            ]
        }
    }


class CheckOCSPResponse(BaseModel):
    verified: StrictBool = Field(
        ...,
        description=(
            "True only when the response is successful, carries exactly one "
            "SingleResponse for the supplied leaf, is signed by the supplied "
            "issuer, and is fresh at verification_time"
        ),
    )
    reason: StrictStr = Field(..., description="Human-readable verification conclusion")
    cert_status: Optional[Literal["good", "revoked", "unknown"]] = Field(
        None,
        description="Certificate status (good/revoked/unknown); null when not verified",
    )
    produced_at: Optional[str] = Field(
        None, description="OCSP producedAt as RFC 3339 UTC; null when not verified"
    )
    this_update: Optional[str] = Field(
        None, description="SingleResponse thisUpdate as RFC 3339 UTC; null when not verified"
    )
    next_update: Optional[str] = Field(
        None, description="SingleResponse nextUpdate as RFC 3339 UTC; null when absent/not verified"
    )
    revocation_time: Optional[str] = Field(
        None, description="Revocation time as RFC 3339 UTC for revoked certs; null otherwise"
    )
    revocation_reason: Optional[str] = Field(
        None, description="CRL/OCSP revocation reason name for revoked certs; null otherwise"
    )
