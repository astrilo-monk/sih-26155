"""
Lexicon heuristics: HEURISTIC facts for configurations no confirmed parser reads.

A candidate needs a lexicon keyword, a typed value (IP, number, enum word) or a
polarity resolved on the same line or from the state line of its block
(``remote-console state enabled``). Candidates for the same predicate, subject
and scope that disagree become one undetermined fact citing all of them, so the
control reports UNKNOWN. Heuristic verdicts are provisional: never scored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator, Optional

from app.facts import lexicon as L
from app.facts.predicates import (
    CENTRAL_AAA, DISCOVERY_PROTOCOL, IDLE_TIMEOUT, IPSEC_PROPOSAL, LOG_REMOTE_DESTINATION, LOGIN_BANNER,
    NTP_AUTHENTICATED, NTP_SERVER, PERMIT_ANY, PROTOCOL_ENABLED, SNMP_COMMUNITY, SOURCE_RESTRICTED, SOURCE_ROUTING,
    SSH_VERSION, SecurityFact,
)
from app.models.results import Assurance, Evidence
from app.structure.tokenizer import IP, Statement, tokenize

LIST_PREDICATES = frozenset({LOG_REMOTE_DESTINATION, NTP_SERVER})
_ENCRYPTION = re.compile(r"^(esp-)?(aes|3des|des)(\d|-|$)")
_HASH = re.compile(r"(sha|md5)(\d|-|$)")
_DH = re.compile(r"^(dh-?)?group(\d+)$")
_NUMBER = re.compile(r"^(\d+(?:\.\d+)?)([a-z]*)$")


@dataclass
class _Candidate:
    predicate: str
    value: Any
    lines: list[int]
    subject: Optional[str] = None
    scope: Optional[str] = None
    unit: Optional[str] = None


def heuristic_facts(raw_lines: list[str], skip: frozenset[int] = frozenset()) -> list[SecurityFact]:
    """``skip``: lines answered by a recognizer or rejected by an administrator."""
    return combine(heuristic_candidates(raw_lines, skip), raw_lines)


_HOSTNAME_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


def generic_hostname(raw_lines: list[str]) -> Optional[str]:
    """The device name of a configuration no parser reads, or None.

    A statement names the device when its last token follows a hostname keyword
    (``hostname X``, ``system-name X``, ``set deviceconfig setting management hostname X``).
    Comments, free text and negations never count; different names on different lines are
    conflicting evidence, so no name is reported rather than a guess.
    """
    names = set()
    for statement in tokenize(raw_lines):
        tokens = [t.strip("\"'") for t in statement.text.replace(";", " ").split()]
        if len(tokens) >= 2 and tokens[-2].lower() in L.HOSTNAME and _HOSTNAME_VALUE.match(tokens[-1]):
            names.add(tokens[-1])
    return names.pop() if len(names) == 1 else None


def heuristic_candidates(raw_lines: list[str], skip: frozenset[int] = frozenset()) -> list["_Candidate"]:
    statements = tokenize(raw_lines)
    candidates = [c for extract in _EXTRACTORS for c in extract(statements)]
    # A skipped line still lends its block state to other lines: only candidates stated on it are dropped
    return [c for c in candidates if not (set(c.lines) - state_lines(c, statements)) & skip]


def state_lines(candidate: "_Candidate", statements: list[Statement]) -> set[int]:
    """Cited lines that only switch a block on or off (``remote-console state enabled``)."""
    by_line = {s.line: s for s in statements}
    return {n for n in candidate.lines if n in by_line and by_line[n].scope_path
            and len(candidate.lines) > 1 and _is_state(by_line[n])}


def _is_state(s: Statement) -> bool:
    return s.polarity is not None and {t for t in s.key_tokens if t != s.scope_path[-1]} <= L.STATE_WORDS


# ── token helpers ───────────────────────────────────────────────────────────

def _parts(token: str) -> set[str]:
    return {token, *re.split(r"[-_]", token)}


def _has(tokens, words) -> bool:
    return any(_parts(t) & words for t in tokens)


def _context(s: Statement) -> list[str]:
    """Scope header tokens then the statement's own keywords (a flat block's prefix counted once)."""
    headers = s.scope_path[:-1] if s.scope_path and s.scope_path[-1] == s.key_tokens[0] else s.scope_path
    return [t for header in headers for t in header.lower().split()] + s.key_tokens


def _ips(s: Statement) -> list[str]:
    return [v for v in s.values if IP.match(v)]


def _number(value: str) -> Optional[tuple[float, str]]:
    match = _NUMBER.match(value)
    return (float(match.group(1)), match.group(2)) if match else None


def _polarity(s: Statement, statements: list[Statement]) -> tuple[Optional[bool], list[int]]:
    """Polarity of the line, else of its block's state line(s)."""
    if s.polarity is not None:
        return s.polarity, [s.line]
    if not s.scope_path:
        return None, []
    states = [o for o in statements if (o.scope_path, o.block) == (s.scope_path, s.block) and _is_state(o)]
    if len({o.polarity for o in states}) != 1:
        return None, []
    return states[0].polarity, sorted({s.line, *(o.line for o in states)})


# ── extractors ──────────────────────────────────────────────────────────────

def _protocols(statements) -> Iterator[_Candidate]:
    for s in statements:
        ctx = _context(s)
        if set(ctx) & L.RULE_WORDS:
            continue
        for subject, names in L.MGMT_PROTOCOLS.items():
            index = next((i for i, t in enumerate(ctx) if t in names), None)
            if index is None:
                continue
            server = ctx[index] != subject or set(ctx[index + 1:index + 2]) & L.SERVER_WORDS
            if not (server or set(ctx[:index]) & L.REMOTE_ACCESS):
                continue
            polarity, lines = _polarity(s, statements)
            if polarity is not None:
                yield _Candidate(PROTOCOL_ENABLED, polarity, lines, subject=subject)


def _source_restriction(statements) -> Iterator[_Candidate]:
    for s in statements:
        if not any(t.startswith(word) for t in s.key_tokens for word in L.SOURCE_RESTRICTION):
            continue
        words = set(s.key_tokens)
        if ips := _ips(s):
            value = not all(ip in L.ANY_ADDRESS for ip in ips)
        elif words & L.UNRESTRICTED:
            value = False
        elif words & L.RESTRICTED:
            value = True
        elif s.polarity is not None:
            value = s.polarity
        else:
            continue
        yield _Candidate(SOURCE_RESTRICTED, value, [s.line])


def _ssh_version(statements) -> Iterator[_Candidate]:
    for s in statements:
        if s.polarity is False or not (_has(_context(s), L.SSH) and _has(s.key_tokens, L.VERSION)):
            continue
        number = next((n for v in s.values if (n := _number(v)) and not n[1]), None)
        if number:
            yield _Candidate(SSH_VERSION, int(number[0]) if number[0].is_integer() else number[0], [s.line])


def _idle_timeout(statements) -> Iterator[_Candidate]:
    for s in statements:
        ctx = _context(s)
        keys = set(s.key_tokens)
        if not (_has(s.key_tokens, L.IDLE) or keys & L.TIMEOUT_KEYWORDS
                or ("timeout" in keys and set(ctx) & L.TIMEOUT_CONTEXT)):
            continue
        numbers = [n for v in s.values if (n := _number(v))]
        if not numbers:
            if s.polarity is False:
                yield _Candidate(IDLE_TIMEOUT, 0, [s.line], unit="min")
            continue
        (value, suffix), unit = numbers[0], None
        if "exec-timeout" in keys:
            # exec-timeout <minutes> [<seconds>]
            value, unit = value + (numbers[1][0] / 60 if len(numbers) > 1 else 0), "min"
        else:
            words = {suffix} | keys
            if words & L.MINUTES:
                unit = "min"
            elif words & L.SECONDS:
                value, unit = value / 60, "min"
            elif words & L.HOURS:
                value, unit = value * 60, "min"
        yield _Candidate(IDLE_TIMEOUT, value, [s.line], unit=unit)


def _remote_log(statements) -> Iterator[_Candidate]:
    for s in statements:
        ctx = _context(s)
        if _polarity(s, statements)[0] is not False and not set(ctx) & L.RULE_WORDS and _has(ctx, L.REMOTE_LOG) \
                and (ips := [ip for ip in _ips(s) if "/" not in ip]):
            yield _Candidate(LOG_REMOTE_DESTINATION, ips, [s.line])


def _ntp(statements) -> Iterator[_Candidate]:
    for s in statements:
        if not _has(_context(s), L.TIME_SYNC):
            continue
        if _has(s.key_tokens, L.AUTHENTICATED):
            if s.polarity is not None:
                yield _Candidate(NTP_AUTHENTICATED, s.polarity, [s.line])
        elif _polarity(s, statements)[0] is not False and (ips := [ip for ip in _ips(s) if "/" not in ip]):
            yield _Candidate(NTP_SERVER, ips, [s.line])


def _central_aaa(statements) -> Iterator[_Candidate]:
    for s in statements:
        ctx = _context(s)
        if set(ctx) & L.RULE_WORDS:
            continue
        if _has(ctx, L.AAA_SERVERS) and _ips(s) and _polarity(s, statements)[0] is not False:
            yield _Candidate(CENTRAL_AAA, True, [s.line])
        elif s.polarity is not None and any(_parts(t) & L.CENTRAL and _parts(t) & L.AUTHENTICATED
                                            for t in s.key_tokens):
            yield _Candidate(CENTRAL_AAA, s.polarity, [s.line])


def _ipsec(statements) -> Iterator[_Candidate]:
    marked = [s for s in statements if _has(_context(s), L.IPSEC)]
    blocks = {(s.scope_path, s.block) for s in marked if s.scope_path}
    groups: dict[Any, list[Statement]] = {}
    for s in statements:
        if (s.scope_path, s.block) in blocks:
            groups.setdefault((s.scope_path, s.block), []).append(s)
        elif any(s is m for m in marked):
            groups.setdefault(s.line, []).append(s)

    for key, members in groups.items():
        proposal: dict[str, Any] = {"encryption": None, "hash": None, "dh_group": None}
        lines = []
        for s in members:
            cited = False
            for token in s.key_tokens + s.values:
                if proposal["encryption"] is None and _ENCRYPTION.match(token):
                    proposal["encryption"], cited = token, True
                if proposal["hash"] is None and _HASH.search(token):
                    proposal["hash"], cited = token, True
                if proposal["dh_group"] is None and (match := _DH.match(token)):
                    proposal["dh_group"], cited = int(match.group(2)), True
            numbers = [n for v in s.values if (n := _number(v)) and not n[1]]
            if proposal["dh_group"] is None and set(s.key_tokens) & L.DH_KEYWORDS and numbers:
                proposal["dh_group"], cited = int(numbers[0][0]), True
            # the IKE version belongs to the proposal's evidence
            cited = cited or (_has(s.key_tokens, L.IPSEC) and _has(s.key_tokens, L.VERSION) and bool(numbers))
            if cited:
                lines.append(s.line)
        if proposal["encryption"] or proposal["hash"]:
            if isinstance(key, tuple):
                scope = " ".join(key[0]) + (f" at line {key[1]}" if key[1] else "")
            else:
                scope = f"line {key}"
            yield _Candidate(IPSEC_PROPOSAL, proposal, lines, scope=scope)


def _snmp_community(statements) -> Iterator[_Candidate]:
    index = 0
    for s in statements:
        keys = s.key_tokens
        if s.polarity is False or not (_has(_context(s), L.SNMP) and "community" in keys):
            continue
        after = keys[keys.index("community") + 1:]
        name = after[0] if after else (s.values[0] if s.values else None)
        if name is None:
            continue
        rest = after[1:]
        permission = "RW" if set(rest) & L.READ_WRITE else "RO" if set(rest) & L.READ_ONLY else None
        tail = [t for t in rest if t not in L.READ_WRITE | L.READ_ONLY] + [v for v in s.values if v != name]
        index += 1
        # The community string is a secret: identify it by position only
        yield _Candidate(SNMP_COMMUNITY, {"name": name, "permission": permission,
                                          "acl": tail[0] if permission and tail else None},
                         [s.line], scope=f"snmp community #{index}")


def _source_routing(statements) -> Iterator[_Candidate]:
    for s in statements:
        if s.polarity is not None and set(s.key_tokens) & L.SOURCE_ROUTING:
            yield _Candidate(SOURCE_ROUTING, s.polarity, [s.line])


def _discovery(statements) -> Iterator[_Candidate]:
    for s in statements:
        first = s.key_tokens[0]
        if first in L.DISCOVERY and s.polarity is not None and s.scope_path in ((), (first,)):
            yield _Candidate(DISCOVERY_PROTOCOL, s.polarity, [s.line], subject=first, scope="global")


def _banner(statements) -> Iterator[_Candidate]:
    for s in statements:
        keys = s.key_tokens
        if keys[0] == "banner" and (set(keys[1:2]) & L.BANNER_TYPES or (len(keys) == 1 and s.values)):
            yield _Candidate(LOGIN_BANNER, s.polarity is not False, [s.line])
        elif keys[0] != "banner" and s.polarity is not None and any("banner" in _parts(t) for t in keys):
            yield _Candidate(LOGIN_BANNER, s.polarity, [s.line])


def _permit_any(statements) -> Iterator[_Candidate]:
    for s in statements:
        tokens = set(s.key_tokens)
        wildcards = sum(t in L.UNRESTRICTED for t in s.key_tokens) + sum(v in L.ANY_ADDRESS for v in s.values)
        if s.polarity is not False and tokens & L.PERMIT and wildcards >= 2 and not tokens & L.NARROWING:
            yield _Candidate(PERMIT_ANY, True, [s.line], scope=" ".join(s.scope_path) or f"rule at line {s.line}")


_EXTRACTORS = (
    _protocols, _source_restriction, _ssh_version, _idle_timeout, _remote_log, _ntp, _central_aaa, _ipsec,
    _snmp_community, _source_routing, _discovery, _banner, _permit_any,
)


# ── combination ─────────────────────────────────────────────────────────────

def combine(candidates: list[_Candidate], raw_lines: list[str],
            assurance: Assurance = Assurance.HEURISTIC) -> list[SecurityFact]:
    groups: dict[tuple, list[_Candidate]] = {}
    for c in candidates:
        groups.setdefault((c.predicate, c.subject, c.scope), []).append(c)

    facts = []
    for (predicate, subject, scope), group in groups.items():
        lines = sorted({n for c in group for n in c.lines if 1 <= n <= len(raw_lines)})
        # assurance HEURISTIC records the origin; provenance only explains an undetermined value
        unit, provenance = group[0].unit, ""
        if predicate in LIST_PREDICATES:
            value = list(dict.fromkeys(v for c in group for v in c.value))
        elif len({(repr(c.value), c.unit) for c in group}) == 1:
            value = group[0].value
        else:
            value, unit = None, None
            provenance = f"Conflicting statements on lines {', '.join(map(str, lines))}"
        facts.append(SecurityFact(
            predicate, value, assurance,
            Evidence(line_numbers=lines, text=[raw_lines[n - 1] for n in lines]),
            subject=subject, scope=scope, unit=unit, provenance=provenance,
        ))
    return facts
