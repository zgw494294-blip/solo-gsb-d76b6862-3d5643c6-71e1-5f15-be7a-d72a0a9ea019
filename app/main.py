"""FastAPI application exposing POST /v1/authorize, /v1/authorize/patch-plan,
/v1/authorize/change-impact, /v1/authorize/rollout-window,
/v1/issuance/route, /v1/issuance/check-csr, /v1/issuance/check-dns01,
/v1/issuance/check-ocsp, /v1/records/import-zone, /v1/records/export-zone
and /v1/records/minimize."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .csr import MAX_CSR_BYTES, CSRError, inspect_csr
from .dns01 import check_dns01
from .engine import (
    CAAError,
    change_impact,
    check_csr,
    evaluate,
    minimize_records,
    plan_patch,
    rollout_window,
    route_issuance,
)
from .ocsp import verify_ocsp
from .schemas import (
    AuthorizeRequest,
    AuthorizeResponse,
    ChangeImpactRequest,
    ChangeImpactResponse,
    CheckCSRRequest,
    CheckCSRResponse,
    CheckDNS01Request,
    CheckDNS01Response,
    CheckOCSPRequest,
    CheckOCSPResponse,
    ExportZoneRequest,
    ExportZoneResponse,
    ImportZoneRequest,
    ImportZoneResponse,
    IssuanceRouteRequest,
    IssuanceRouteResponse,
    MinimizeRequest,
    MinimizeResponse,
    PatchPlanRequest,
    PatchPlanResponse,
    RolloutWindowRequest,
    RolloutWindowResponse,
)
from .zonefile import MAX_ZONE_BYTES, ZoneImportError, export_zone, parse_zone

app = FastAPI(
    title="Offline CAA Authorization API",
    version="1.0.0",
    description=(
        "Evaluates CAA issuance authorization against a caller-supplied, "
        "offline DNS record set. No external DNS queries are performed."
    ),
)


@app.exception_handler(CAAError)
async def caa_error_handler(_: Request, exc: CAAError) -> JSONResponse:
    # All engine-level failures (bad names, mixed RRs, multiple CNAMEs,
    # alias loops, >8 hops), CSR parse/signature/SAN failures, JWK/token
    # failures, OCSP PEM/DER/algorithm failures and zone-import failures
    # are client errors and map to HTTP 422. Zone-import errors additionally
    # carry the source line.
    content: dict = {"detail": str(exc), "error_type": exc.__class__.__name__}
    line = getattr(exc, "line", None)
    if line is not None:
        content["line"] = line
    return JSONResponse(status_code=422, content=content)


@app.get("/health", tags=["ops"])
async def health() -> dict:
    return {"status": "ok"}


@app.post(
    "/v1/authorize",
    response_model=AuthorizeResponse,
    tags=["caa"],
    summary="Evaluate CAA authorization for a domain/CA pair",
)
async def authorize(payload: AuthorizeRequest) -> AuthorizeResponse:
    result = evaluate(
        domain=payload.domain,
        wildcard=payload.wildcard,
        ca=payload.ca,
        records=[r.model_dump() for r in payload.records],
    )
    return AuthorizeResponse(**result)


@app.post(
    "/v1/authorize/patch-plan",
    response_model=PatchPlanResponse,
    tags=["caa"],
    summary="Plan a single-record CAA patch that authorizes the target",
)
async def patch_plan(payload: PatchPlanRequest) -> PatchPlanResponse:
    result = plan_patch(
        domain=payload.domain,
        wildcard=payload.wildcard,
        ca=payload.ca,
        records=[r.model_dump() for r in payload.records],
        protected=[p.model_dump() for p in payload.protected],
    )
    return PatchPlanResponse(**result)


@app.post(
    "/v1/authorize/change-impact",
    response_model=ChangeImpactResponse,
    tags=["caa"],
    summary="Review how a batch of CAA/CNAME edits flips issuance authorization",
)
async def authorize_change_impact(
    payload: ChangeImpactRequest,
) -> ChangeImpactResponse:
    result = change_impact(
        records=[r.model_dump() for r in payload.records],
        edits=[
            {"remove": e.remove}
            if e.remove is not None
            else {"add": e.add.model_dump()}
            for e in payload.edits
        ],
        queries=[q.model_dump() for q in payload.queries],
    )
    return ChangeImpactResponse(**result)


@app.post(
    "/v1/authorize/rollout-window",
    response_model=RolloutWindowResponse,
    tags=["caa"],
    summary="Find the first second every old/new snapshot mix is safe",
)
async def authorize_rollout_window(
    payload: RolloutWindowRequest,
) -> RolloutWindowResponse:
    result = rollout_window(
        before=[r.model_dump() for r in payload.before],
        after=[r.model_dump() for r in payload.after],
        queries=[q.model_dump() for q in payload.queries],
        stale_seconds=dict(payload.stale_seconds),
    )
    return RolloutWindowResponse(**result)


@app.post(
    "/v1/issuance/route",
    response_model=IssuanceRouteResponse,
    tags=["caa"],
    summary="Authorize candidate CAs and route issuance requests under capacities",
)
async def issuance_route(payload: IssuanceRouteRequest) -> IssuanceRouteResponse:
    result = route_issuance(
        cas=[c.model_dump() for c in payload.cas],
        requests=[r.model_dump() for r in payload.requests],
        records=[r.model_dump() for r in payload.records],
    )
    return IssuanceRouteResponse(**result)


@app.post(
    "/v1/issuance/check-csr",
    response_model=CheckCSRResponse,
    tags=["caa"],
    summary="Verify a CSR and authorize every SAN DNS name",
)
async def issuance_check_csr(payload: CheckCSRRequest) -> CheckCSRResponse:
    if len(payload.csr.encode("utf-8")) > MAX_CSR_BYTES:
        raise CSRError("CSR exceeds 64 KiB (65536 bytes)")
    info = inspect_csr(payload.csr)
    result = check_csr(
        names=[
            {"name": n.name, "domain": n.domain, "wildcard": n.wildcard}
            for n in info.names
        ],
        ca=payload.ca,
        records=[r.model_dump() for r in payload.records],
    )
    return CheckCSRResponse(csr_sha256=info.sha256, **result)


@app.post(
    "/v1/issuance/check-dns01",
    response_model=CheckDNS01Response,
    tags=["caa"],
    summary="Verify ACME DNS-01 challenges against an offline TXT/CNAME view",
)
async def issuance_check_dns01(payload: CheckDNS01Request) -> CheckDNS01Response:
    result = check_dns01(
        jwk=payload.jwk.model_dump(),
        challenges=[c.model_dump() for c in payload.challenges],
        records=[r.model_dump() for r in payload.records],
    )
    return CheckDNS01Response(**result)


@app.post(
    "/v1/issuance/check-ocsp",
    response_model=CheckOCSPResponse,
    tags=["caa"],
    summary="Offline-verify a Base64 DER OCSP response for a leaf/issuer pair",
)
async def issuance_check_ocsp(payload: CheckOCSPRequest) -> CheckOCSPResponse:
    verdict = verify_ocsp(
        leaf_pem=payload.leaf_certificate,
        issuer_pem=payload.issuer_certificate,
        response_b64=payload.ocsp_response,
        verification_time=payload.verification_time,
    )
    return CheckOCSPResponse(**verdict.__dict__)


@app.post(
    "/v1/records/minimize",
    response_model=MinimizeResponse,
    tags=["records"],
    summary="Minimize a record set while preserving every query verdict",
)
async def records_minimize(payload: MinimizeRequest) -> MinimizeResponse:
    result = minimize_records(
        records=[r.model_dump() for r in payload.records],
        queries=[q.model_dump() for q in payload.queries],
    )
    return MinimizeResponse(**result)


@app.post(
    "/v1/records/import-zone",
    response_model=ImportZoneResponse,
    response_model_exclude_none=True,
    tags=["zone"],
    summary="Import BIND zone text into authorize-ready CAA/CNAME records",
)
async def import_zone(payload: ImportZoneRequest) -> ImportZoneResponse:
    if len(payload.zone.encode("utf-8")) > MAX_ZONE_BYTES:
        raise ZoneImportError("zone text exceeds 64 KiB (65536 bytes)")
    origin, records = parse_zone(payload.origin, payload.zone)
    return ImportZoneResponse(origin=origin, count=len(records), records=records)


@app.post(
    "/v1/records/export-zone",
    response_model=ExportZoneResponse,
    tags=["zone"],
    summary="Export CAA/CNAME records as a BIND zone fragment",
)
async def records_export_zone(payload: ExportZoneRequest) -> ExportZoneResponse:
    zone = export_zone(
        payload.origin,
        payload.default_ttl,
        [r.model_dump() for r in payload.records],
    )
    return ExportZoneResponse(zone=zone)
