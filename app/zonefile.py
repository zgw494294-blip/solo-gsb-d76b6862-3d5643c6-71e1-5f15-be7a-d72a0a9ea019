"""BIND master-file (zone text) importer.

Parses a subset of the DNS master-file format (RFC 1035 section 5) into
the same CAA/CNAME record dicts that ``POST /v1/authorize`` accepts, so a
zone snippet can be turned into an offline DNS view without hand-writing
JSON:

* ``$ORIGIN`` / ``$TTL`` directives (``$INCLUDE`` / ``$GENERATE`` are
  rejected; any other ``$`` directive is a syntax error);
* ``@`` denotes the current origin; relative owner/target names are
  expanded against the current origin;
* an entry starting with whitespace inherits the previous record's
  owner — every resource record updates that owner, including record
  types that are not exported (A, AAAA, SOA, ...);
* TTL and the ``IN`` class may appear before the type in any order;
* parentheses join continuations across physical lines, ``;`` starts a
  comment only outside quotes, and backslash escapes (``\\X`` and the
  decimal ``\\DDD`` form) work inside and outside quoted strings.

Only CAA and CNAME records are exported, in source order, each tagged
with the 1-based line number at which the record starts. All failures
raise :class:`ZoneImportError` carrying the offending source line.

The inverse direction, :func:`export_zone`, renders authorize-ready
CAA/CNAME records back into a zone fragment: a ``$ORIGIN`` / ``$TTL``
header, ``@`` for the origin itself, relative owner names below it,
absolute (trailing-dot) CNAME targets, and quoted CAA values using
backslash escapes. Feeding the fragment to :func:`parse_zone`
reproduces the normalized records in their original order, so the text
can round-trip through ``POST /v1/records/import-zone``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pydantic import ValidationError

from .engine import CAAError, normalize_name, prepare_records
from .schemas import CAARecord, CNAMERecordModel

MAX_ZONE_BYTES = 64 * 1024
MAX_RECORDS = 100

# BIND TTL: plain seconds or unit-suffixed groups such as 30m, 1h30m, 2d.
_TTL_RE = re.compile(r"(?:[0-9]+[smhdw]?)+", re.IGNORECASE)


class ZoneImportError(CAAError):
    """Zone import failure; ``line`` is the 1-based source line (if any)."""

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message)
        self.line = line


class ZoneExportError(CAAError):
    """Zone export failure: out-of-zone owner, non-ASCII value, oversize."""


def _fail(line: int | None, message: str) -> ZoneImportError:
    if line is not None:
        message = f"line {line}: {message}"
    return ZoneImportError(message, line)


@dataclass
class _Token:
    text: str
    line: int
    col: int


@dataclass
class _Entry:
    """One logical entry: the tokens between two unparenthesized newlines."""

    tokens: list[_Token]
    line: int  # line of the first token
    indented: bool  # first token not in column 0 -> owner inherited


def _read_escape(text: str, i: int, line: int) -> tuple[str, int]:
    """Decode the escape starting at ``text[i]`` (a backslash).

    Returns the decoded character and how many input characters it
    consumed. ``\\DDD`` (exactly three digits) is the decimal-octet form;
    any other escaped character stands for itself.
    """
    if i + 1 >= len(text) or text[i + 1] == "\n":
        raise _fail(line, "dangling backslash")
    digits = text[i + 1 : i + 4]
    if len(digits) == 3 and digits.isascii() and digits.isdigit():
        value = int(digits)
        if value > 255:
            raise _fail(line, f"invalid \\DDD escape \\{digits}")
        return chr(value), 4
    return text[i + 1], 2


def _lex(text: str) -> list[_Entry]:
    """Split zone text into logical entries.

    Handles comments, quoted strings, backslash escapes and parentheses;
    raises ZoneImportError on unbalanced quotes/parens and bad escapes.
    """
    entries: list[_Entry] = []
    tokens: list[_Token] = []
    buf: list[str] = []
    tok_start: tuple[int, int] | None = None
    parens: list[int] = []  # lines where each '(' opened
    in_quote = False
    quote_line = 0
    in_comment = False
    line = 1
    col = 0
    i = 0

    def flush_token() -> None:
        nonlocal tok_start
        if tok_start is not None:
            tokens.append(_Token("".join(buf), tok_start[0], tok_start[1]))
            buf.clear()
            tok_start = None

    def flush_entry() -> None:
        flush_token()
        if tokens:
            first = tokens[0]
            entries.append(_Entry(list(tokens), first.line, first.col > 0))
            tokens.clear()

    while i < len(text):
        ch = text[i]

        if ch == "\n":
            if in_quote:
                raise _fail(quote_line, "unterminated quoted string")
            in_comment = False
            if parens:
                flush_token()
            else:
                flush_entry()
            line += 1
            col = 0
            i += 1
            continue

        if in_comment:
            i += 1
            col += 1
            continue

        if in_quote:
            if ch == "\\":
                decoded, used = _read_escape(text, i, line)
                buf.append(decoded)
                i += used
                col += used
                continue
            if ch == '"':
                in_quote = False
            else:
                buf.append(ch)
            i += 1
            col += 1
            continue

        if ch == "\\":
            decoded, used = _read_escape(text, i, line)
            if tok_start is None:
                tok_start = (line, col)
            buf.append(decoded)
            i += used
            col += used
            continue
        if ch == '"':
            if tok_start is None:
                tok_start = (line, col)
            in_quote = True
            quote_line = line
            i += 1
            col += 1
            continue
        if ch == ";":
            flush_token()
            in_comment = True
            i += 1
            col += 1
            continue
        if ch == "(":
            flush_token()
            parens.append(line)
            i += 1
            col += 1
            continue
        if ch == ")":
            flush_token()
            if not parens:
                raise _fail(line, "unbalanced ')'")
            parens.pop()
            i += 1
            col += 1
            continue
        if ch in " \t\r":
            flush_token()
            i += 1
            col += 1
            continue

        if tok_start is None:
            tok_start = (line, col)
        buf.append(ch)
        i += 1
        col += 1

    if in_quote:
        raise _fail(quote_line, "unterminated quoted string")
    if parens:
        raise _fail(parens[-1], "unclosed '('")
    flush_entry()
    return entries


def _normalize(name: str, line: int | None, field: str) -> str:
    try:
        return normalize_name(name, field=field)
    except CAAError as exc:
        raise _fail(line, str(exc)) from exc


def _expand(token: str, origin: str, line: int, field: str) -> str:
    """Expand @/relative/absolute zone names against the current origin."""
    if token == "@":
        return origin
    candidate = token if token.endswith(".") else f"{token}.{origin}"
    return _normalize(candidate, line, field)


def _validation_summary(exc: ValidationError) -> str:
    msgs: list[str] = []
    for error in exc.errors():
        msg = error["msg"]
        if msg.startswith("Value error, "):
            msg = msg[len("Value error, ") :]
        loc = ".".join(str(part) for part in error["loc"])
        msgs.append(f"{loc}: {msg}" if loc else msg)
    return "; ".join(dict.fromkeys(msgs))


def _build_caa(owner: str, rdata: list[_Token], line: int) -> dict:
    if len(rdata) != 3:
        raise _fail(
            line,
            f"CAA expects 3 rdata fields (flag tag value), got {len(rdata)}",
        )
    flag_text, tag, value = (tok.text for tok in rdata)
    if not (flag_text.isascii() and flag_text.isdigit()):
        raise _fail(line, f"CAA flag {flag_text!r} is not a non-negative integer")
    flag = int(flag_text)
    if flag > 255:
        raise _fail(line, f"CAA flag {flag} is out of range (0-255)")
    try:
        record = CAARecord(type="CAA", owner=owner, flag=flag, tag=tag, value=value)
    except ValidationError as exc:
        raise _fail(line, f"invalid CAA record: {_validation_summary(exc)}") from exc
    return record.model_dump()


def _build_cname(owner: str, rdata: list[_Token], origin: str, line: int) -> dict:
    if len(rdata) != 1:
        raise _fail(line, f"CNAME expects exactly one target name, got {len(rdata)}")
    target = _expand(rdata[0].text, origin, line, "target")
    try:
        record = CNAMERecordModel(type="CNAME", owner=owner, target=target)
    except ValidationError as exc:
        raise _fail(line, f"invalid CNAME record: {_validation_summary(exc)}") from exc
    return record.model_dump()


def parse_zone(origin: str, text: str) -> tuple[str, list[dict]]:
    """Parse zone ``text`` under an absolute ``origin`` (trailing dot).

    Returns the normalized origin and the exported CAA/CNAME records in
    source order as ``{"line": n, ...record}`` dicts ready to be used as
    the ``records`` of ``/v1/authorize``.
    """
    origin = origin.strip()
    if not origin.endswith("."):
        raise _fail(None, "origin must be an absolute name ending in '.'")
    current_origin = _normalize(origin, None, "origin")

    records: list[dict] = []
    last_owner: str | None = None

    for entry in _lex(text):
        tokens = entry.tokens
        line = entry.line
        first = tokens[0].text

        if first.startswith("$"):
            directive = first.upper()
            if directive in ("$INCLUDE", "$GENERATE"):
                raise _fail(line, f"{directive} is not supported")
            if directive == "$ORIGIN":
                if len(tokens) != 2:
                    raise _fail(line, "$ORIGIN expects exactly one argument")
                current_origin = _expand(tokens[1].text, current_origin, line, "$ORIGIN")
            elif directive == "$TTL":
                if len(tokens) != 2 or not _TTL_RE.fullmatch(tokens[1].text):
                    raise _fail(line, "$TTL expects a single TTL value")
            else:
                raise _fail(line, f"unknown directive {first!r}")
            continue

        if entry.indented:
            if last_owner is None:
                raise _fail(
                    line, "owner omitted but no previous record to inherit from"
                )
            owner = last_owner
            fields = tokens
        else:
            owner = _expand(first, current_origin, line, "owner")
            fields = tokens[1:]

        # TTL and the IN class may precede the type, in any order.
        idx = 0
        ttl_seen = class_seen = False
        while idx < len(fields):
            word = fields[idx].text
            if not ttl_seen and _TTL_RE.fullmatch(word):
                ttl_seen = True
            elif not class_seen and word.upper() == "IN":
                class_seen = True
            else:
                break
            idx += 1
        if idx >= len(fields):
            raise _fail(line, "missing record type")
        rtype = fields[idx].text.upper()
        rdata = fields[idx + 1 :]

        # Every RR — exported or not — becomes the inheritable owner.
        last_owner = owner

        if rtype == "CAA":
            record = _build_caa(owner, rdata, line)
        elif rtype == "CNAME":
            record = _build_cname(owner, rdata, current_origin, line)
        else:
            continue  # unexported type: skipped, but last_owner is updated

        if len(records) >= MAX_RECORDS:
            raise _fail(line, f"import exceeds {MAX_RECORDS} CAA/CNAME records")
        records.append({"line": line, **record})

    return current_origin, records


def _escape_value(value: str) -> str:
    """Escape an ASCII CAA value for a quoted zone-file string.

    Backslash, double quote and semicolon get a backslash prefix; control
    characters (below 0x20, plus 0x7F) use the decimal ``\\DDD`` form;
    every other printable ASCII character is emitted verbatim.
    """
    out: list[str] = []
    for ch in value:
        code = ord(ch)
        if ch in ('\\', '"', ";"):
            out.append("\\" + ch)
        elif code < 32 or code == 127:
            out.append(f"\\{code:03d}")
        else:
            out.append(ch)
    return "".join(out)


def export_zone(origin: str, default_ttl: int, records: list[dict]) -> str:
    """Render CAA/CNAME ``records`` as a BIND zone fragment.

    The fragment starts with ``$ORIGIN`` / ``$TTL`` lines, then one record
    per line in input order: the origin itself is written ``@``, owners
    below it use relative names, and CNAME targets are absolute names with
    a trailing dot. Records are normalized and checked with the same rules
    as ``/v1/authorize`` (mixed CAA/CNAME owner, multiple CNAMEs); every
    owner must equal the origin or lie below it. CAA values must be ASCII
    and are always quoted, with backslash/quote/semicolon escaped and
    control characters in ``\\DDD`` form (empty string renders as ``""``).

    The result never exceeds 64 KiB, so it can be fed back to
    :func:`parse_zone` (via ``POST /v1/records/import-zone``) and yields
    the normalized records in their original order. All failures raise
    :class:`ZoneExportError` (or a record-validation :class:`CAAError`).
    """
    origin = origin.strip()
    if not origin.endswith("."):
        raise ZoneExportError("origin must be an absolute name ending in '.'")
    try:
        norm_origin = normalize_name(origin, field="origin")
    except CAAError as exc:
        raise ZoneExportError(str(exc)) from exc

    # Shared with /v1/authorize: normalizes names and rejects mixed
    # CAA/CNAME owners and multiple CNAMEs at the same owner.
    prepare_records(records)

    lines = [f"$ORIGIN {norm_origin}.", f"$TTL {default_ttl}"]
    for rec in records:
        owner = normalize_name(rec.get("owner", ""), field="owner")
        if owner != norm_origin and not owner.endswith(f".{norm_origin}"):
            raise ZoneExportError(
                f"owner {owner!r} is not equal to or below origin "
                f"{norm_origin!r}"
            )
        relative = "@" if owner == norm_origin else owner[: -len(norm_origin) - 1]
        if rec.get("type") == "CAA":
            flag = int(rec["flag"])
            tag = str(rec["tag"]).strip().lower()
            value = str(rec["value"])
            if not value.isascii():
                raise ZoneExportError(
                    f"CAA value at owner {owner!r} contains non-ASCII "
                    "characters"
                )
            lines.append(
                f'{relative} IN CAA {flag} {tag} "{_escape_value(value)}"'
            )
        else:
            target = normalize_name(rec.get("target", ""), field="target")
            lines.append(f"{relative} IN CNAME {target}.")

    text = "\n".join(lines) + "\n"
    if len(text.encode("utf-8")) > MAX_ZONE_BYTES:
        raise ZoneExportError("exported zone text exceeds 64 KiB (65536 bytes)")
    return text
