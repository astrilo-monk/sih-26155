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
    ADMIN_ACCOUNT, MGMT_EXPOSED, MGMT_WEAK_CRYPTO, NTP_AUTHENTICATED, RULE_LOGGING, NTP_SERVER, PERMIT_ANY, PROTOCOL_ENABLED, SNMP_COMMUNITY, SOURCE_RESTRICTED, SOURCE_ROUTING,
    SSH_VERSION, SecurityFact,
)
from app.models.results import Assurance, Evidence
from app.structure.tokenizer import IP, Statement, tokenize

LIST_PREDICATES = frozenset({LOG_REMOTE_DESTINATION, NTP_SERVER})
# Facts read across several statements joined by the names they share, never from one line
_JOINS = frozenset({MGMT_EXPOSED})
_ENCRYPTION = re.compile(r"^(esp-)?(aes|3des|des)(\d|-|$)")
_HASH = re.compile(r"(sha|md5)(\d|-|$)")
_DH = re.compile(r"^(dh-?)?group(\d+)$")
_NUMBER = re.compile(r"^(\d+(?:\.\d+)?)([a-z]*)$")
# A version may be written with a version prefix (``v2``, ``ver2``, ``version2``). Only a fact that
# asks for a version reads a token this way -elsewhere a letter still means the token is not a number.
_VERSION = re.compile(r"^(?:v|ver|version)?(\d+(?:\.\d+)?)$")


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


# What a file can state about the hardware: a configuration rarely does, but ``show version`` /
# ``show inventory`` output, PAN-OS ``show system info`` and XML exports pasted with it do.
_IDENTITY = {
    "serial": [re.compile(p, re.IGNORECASE) for p in (
        r"\b(?:system\s+|chassis\s+|device\s+)?serial(?:[\s_-]*(?:number|num|no\.?))?\s*[:=]\s*\"?([A-Z0-9][A-Z0-9-]{3,})",
        r"\bserial-number\s+\"?([A-Z0-9][A-Z0-9-]{3,})",
        r"\bprocessor board id\s+([A-Z0-9]{6,})",
        r"\bSN\s*:\s*([A-Z0-9][A-Z0-9-]{3,})",
        r"<serial>\s*([^<\s]+)\s*</serial>",
    )],
    "model": [re.compile(p, re.IGNORECASE) for p in (
        r"\b(?:hardware\s+)?model(?:[\s_-]*(?:number|name))?\s*[:=]\s*\"?([A-Z0-9][\w./+-]{2,})",
        r"<model>\s*([^<\s]+)\s*</model>",
        r"\bPID\s*:\s*([A-Z0-9][\w./+-]{2,})",
        r"^\s*cisco\s+(\S+)\s+\(.*\)\s+processor",
    )],
    # a version is only one the line says is the software's, and it starts with a digit (never ``ssh version 2``)
    "os_version": [re.compile(p, re.IGNORECASE) for p in (
        r"^\s*(?:#+\s*)?(?:junos|sw-version|software\s+version|os\s+version|firmware(?:\s+version)?)\s*[:=]\s*"
        r"([0-9][\w.()-]*)",
        r"^\s*version\s+([0-9][\w.()-]*);?\s*$",
    )],
}


def stated_identity(raw_lines: list[str]) -> dict[str, str]:
    """Serial number, hardware model and OS version, where the file states them; the first statement wins
    (``show inventory`` lists the chassis first). Nothing is inferred: a missing item stays missing."""
    found: dict[str, str] = {}
    for line in raw_lines:
        for item, patterns in _IDENTITY.items():
            if item not in found and (m := next((p.search(line) for p in patterns if p.search(line)), None)):
                found[item] = m.group(1).strip("\"';")
    return found


def heuristic_candidates(raw_lines: list[str], skip: frozenset[int] = frozenset()) -> list["_Candidate"]:
    statements = tokenize(raw_lines)
    candidates = [c for extract in _EXTRACTORS for c in extract(statements)]
    # A skipped line still lends its block state to other lines: only candidates stated on it are dropped.
    # A join is not stated on any one line: a recognizer that answered one of them (``telnet yes`` in a
    # profile) answered that line's own setting, not the relation the join reads across lines.
    return [c for c in candidates if c.predicate in _JOINS or not (set(c.lines) - state_lines(c, statements)) & skip]


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


def _version(value: str) -> Optional[float]:
    match = _VERSION.match(value)
    return float(match.group(1)) if match else None


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
            if _declares_feature(s, ctx, index, statements):
                polarity, lines = True, [s.line]
            if polarity is not None:
                yield _Candidate(PROTOCOL_ENABLED, polarity, lines, subject=subject)


def _declares_feature(s: Statement, ctx: list[str], index: int, statements: list[Statement]) -> bool:
    """Some dialects switch a feature on by naming it alone inside the block that lists features:

        services { telnet; }

    Only a bare statement counts -its single keyword is the feature name, it carries no value and
    states no polarity, and its enclosing block already identified it as a management service. An
    explicit ``no telnet`` / ``telnet disabled`` states its own polarity and never reaches this.
    Absence of the line states nothing.

    A declaration is as strong as a state line, so a block switched off wins over it, but the
    negation of this same feature does not: both are stated, the fact is undetermined, and the
    control reports UNKNOWN instead of trusting whichever came last."""
    if s.polarity is not None or s.values or len(s.key_tokens) != 1 or index != len(ctx) - 1:
        return False
    negated = any(o is not s and o.polarity is False and o.key_tokens == s.key_tokens
                  and (o.scope_path, o.block) == (s.scope_path, s.block) for o in statements)
    return negated or _polarity(s, statements)[0] is None


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
        # values hold plain numbers; a version written as ``v2`` stays a keyword token
        number = next((n for v in s.values + s.key_tokens if (n := _version(v)) is not None), None)
        if number is not None:
            yield _Candidate(SSH_VERSION, int(number) if number.is_integer() else number, [s.line])


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
        # ``community``, or a compound naming it (``snmp-community-string``)
        at = next((n for n, t in enumerate(keys) if "community" in _parts(t)), None)
        if s.polarity is False or at is None or not _has(_context(s), L.SNMP):
            continue
        after = keys[at + 1:]
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


def _wildcards(s: Statement) -> int:
    return sum(t in L.UNRESTRICTED for t in s.key_tokens) + sum(v in L.ANY_ADDRESS for v in s.values)


def _permit_any(statements) -> Iterator[_Candidate]:
    for s in statements:
        if s.polarity is False or not set(s.key_tokens) & L.PERMIT:
            continue
        if _wildcards(s) >= 2:
            if not set(s.key_tokens) & L.NARROWING:
                yield _Candidate(PERMIT_ANY, True, [s.line], scope=" ".join(s.scope_path) or f"rule at line {s.line}")
        elif len(s.key_tokens) <= 2 and not s.values:
            yield from _composed_permit_any(s, statements)


def _composed_permit_any(action: Statement, statements: list[Statement]) -> Iterator[_Candidate]:
    """A rule whose action and selectors are separate statements (``source-address any; … permit;``).

    The rule is the action's own block or its parent -a selector further out than that belongs to
    something else, not to this rule. Within that, the first block wide enough to state both wildcards
    wins, a block holding a second action is never entered (two rules are never merged), and a
    narrowing selector anywhere in the rule means it is not "all traffic" -unless that selector names
    a wildcard itself (``application any``), which widens the rule instead of narrowing it. Purely
    structural: no dialect supplies the block names."""
    for depth in range(len(action.scope_path), max(len(action.scope_path) - 2, 0), -1):
        members = [s for s in statements if s.scope_path[:depth] == action.scope_path[:depth]]
        if len([s for s in members if set(s.key_tokens) & (L.PERMIT | L.DENY)]) > 1:
            return
        if sum(_wildcards(s) for s in members) >= 2:
            if any(set(s.key_tokens) & L.NARROWING and not _wildcards(s) for s in members):
                return
            lines = sorted({s.line for s in members if _wildcards(s)} | {action.line})
            yield _Candidate(PERMIT_ANY, True, lines, scope=" ".join(action.scope_path[:depth]))
            return


_RULE_WILDCARDS = ("source", "destination")
# set on the rule, these must be wildcards too, or the rule is narrower than "all traffic"
_RULE_NARROWING = ("application", "service", "source-user", "category")
_RULE_OFF = ("disabled", "negate-source", "negate-destination")
# stated at all, these carve addresses out of the rule (Junos ``match source-address-excluded``)
_RULE_EXCLUDED = ("source-address-excluded", "destination-address-excluded")
_RULE_FIELD_NAMES = {"source-address": "source", "destination-address": "destination", "then": "action"}


def _flat_rules(statements) -> dict[tuple[str, ...], dict[str, list[tuple[list[str], Statement]]]]:
    """Rules written one field per line, by rule key (everything up to the rule name): field → (values, line)."""
    rules: dict[tuple[str, ...], dict[str, list[tuple[list[str], Statement]]]] = {}
    for s in statements:
        keys = s.key_tokens
        at = next((n for n, t in enumerate(keys) if t in ("rule", "rules", "policy")), None)
        if at is None or len(keys) < at + 2:
            continue
        rest = keys[at + 2:]
        if rest[:1] == ["match"]:
            rest = rest[1:]
        if not rest:
            # ``disabled yes`` is all polarity words, so the field is read from the line itself
            rest = s.text.lower().split()[-2:]
        field = _RULE_FIELD_NAMES.get(rest[0], rest[0])
        values = rest if rest[0] == "then" else rest[1:] + s.values
        rules.setdefault(tuple(keys[:at + 2]), {}).setdefault(field, []).append(
            ([t for t in values if t not in "[]"], s))
    return rules


def _flat_rule_permit_any(statements) -> Iterator[_Candidate]:
    """A rule written one field per line, keyed by its name (set-style exports):

        set rulebase security rules ALLOW-ALL source any                      (PAN-OS)
        set rulebase security rules ALLOW-ALL action allow
        set security policies from-zone A to-zone B policy P match source-address any    (Junos)
        set security policies from-zone A to-zone B policy P then permit

    Lines with the same key up to the rule name are one rule, wherever they sit in the file. It is
    all traffic only when source and destination are both stated as wildcards, the action permits,
    every narrowing field it states is a wildcard, and it is not disabled, negated or excluding."""
    rules = _flat_rules(statements)

    def wildcard(field: str, fields) -> bool:
        stated = fields.get(field, [])
        return bool(stated) and all(v and all(t in L.UNRESTRICTED or t in L.ANY_ADDRESS for t in v) for v, _ in stated)

    for name, fields in rules.items():
        permits = [s for v, s in fields.get("action", []) if set(v) & L.PERMIT]
        if (not permits or not all(wildcard(f, fields) for f in _RULE_WILDCARDS)
                or any(f in fields and not wildcard(f, fields) for f in _RULE_NARROWING)
                or any(s.text.lower().split()[-1] == "yes" for f in _RULE_OFF for _, s in fields.get(f, []))
                or any(f in fields for f in _RULE_EXCLUDED)):
            continue
        cited = [s.line for f in _RULE_WILDCARDS + _RULE_NARROWING for _, s in fields.get(f, [])]
        yield _Candidate(PERMIT_ANY, True, sorted(cited + [s.line for s in permits]), scope=" ".join(name))


def _flat_rule_logging(statements) -> Iterator[_Candidate]:
    """Whether a permitting rule logs: ``log-end no`` switches it off (PAN-OS), ``then log …`` switches it on
    (Junos). A rule that says nothing about logging states nothing: its platform's default decides."""
    for name, fields in _flat_rules(statements).items():
        actions = fields.get("action", [])
        if not any(set(v) & L.PERMIT for v, _ in actions):
            continue
        logs = [s for v, s in actions if "log" in v]
        for s in [s for _, s in fields.get("log-end", [])]:
            if s.text.lower().split()[-1] in ("no", "false"):
                yield _Candidate(RULE_LOGGING, False, [s.line], scope=" ".join(name))
                break
        else:
            if logs or any(s.text.lower().split()[-1] in ("yes", "true") for _, s in fields.get("log-end", [])):
                cited = logs or [s for _, s in fields.get("log-end", [])]
                yield _Candidate(RULE_LOGGING, True, [s.line for s in cited], scope=" ".join(name))


_ALGORITHM_NAME = re.compile(r"^(?:aes|chacha|hmac|sha|ecdh|diffie|curve|3des|des|arcfour|rc4|blowfish|umac|"
                             r"ssh-|rsa|ecdsa|ed25519|kex)", re.IGNORECASE)


def _ssh_algorithms(statements) -> Iterator[_Candidate]:
    """An SSH algorithm list: weak when it names any weak algorithm, strong when every algorithm it names is.

        ssh server cipher aes256_ctr aes128_ctr 3des_cbc      → weak
        set system services ssh ciphers aes256-ctr            → strong"""
    for s in statements:
        if not _has(_context(s), L.SSH):
            continue
        tokens = s.key_tokens + s.values
        at = next((i for i, t in enumerate(tokens) if t in L.ALGORITHM_WORDS), None)
        if at is None:
            continue
        names = [t.strip("[]\"'") for t in tokens[at + 1:] if _ALGORITHM_NAME.match(t.strip("[]\"'"))]
        if not names:
            continue
        weak = [n for n in names if L.is_weak_algorithm(n)]
        yield _Candidate(MGMT_WEAK_CRYPTO, bool(weak), [s.line], scope=f"ssh algorithms at line {s.line}")


def _default_account(statements) -> Iterator[_Candidate]:
    """A local account with a vendor-default name (``username admin …``, ``set system login user root …``).

    Only the default names are read: any other name is just an account, and says nothing either way."""
    for s in statements:
        keys = s.key_tokens
        if _has(_context(s), L.SNMP):
            continue  # an SNMPv3 user is not a login account
        for i, token in enumerate(keys[:-1]):
            if token in L.ACCOUNT_RELATED and keys[i + 1].strip("\"'") in L.DEFAULT_ACCOUNT_NAMES:
                name = keys[i + 1].strip("\"'")
                yield _Candidate(ADMIN_ACCOUNT, name, [s.line], scope=f"account {name}")
                break


# An interface name: letters, then numbers joined by / . : (ethernet1/1, ge-0/0/0.0, ae1, tunnel.1)
_INTERFACE = re.compile(r"^[a-z][a-z-]*\.?\d+(?:[/:.]\d+)*$")
_NOT_INTERFACES = frozenset({"layer2", "layer3", "ipv4", "ipv6", "v1", "v2", "v2c", "v3"})


def _interfaces(tokens) -> list[str]:
    return [t for t in tokens if _INTERFACE.match(t) and t not in _NOT_INTERFACES]


def _exposed_management(statements) -> Iterator[_Candidate]:
    """A management profile with a service switched on, bound to an interface in an external zone:

        set zone untrust network layer3 ethernet1/1
        set network interface ethernet ethernet1/1 layer3 interface-management-profile OUTSIDE
        set network profiles interface-management-profile OUTSIDE https yes

    Three statements joined by the names they share (interface, profile). A zone is external only when its
    name says so (``untrust``, ``outside``, ``internet`` …); nothing is concluded about any other zone."""
    external: dict[str, Statement] = {}
    bound: dict[str, tuple[str, Statement]] = {}
    services: dict[str, list[Statement]] = {}
    for s in statements:
        keys = s.key_tokens
        for i, token in enumerate(keys[:-1]):
            if token in ("zone", "security-zone") and keys[i + 1] in L.EXTERNAL_ZONES:
                for name in _interfaces(keys[i + 2:]):
                    external.setdefault(name, s)
            if token in ("interface-management-profile", "management-profile"):
                profile, rest = keys[i + 1], keys[i + 2:]
                named = _interfaces(keys[:i])
                if named and not rest:
                    bound[named[0]] = (profile, s)
                elif rest and rest[0] in L.MGMT_SERVICES and s.polarity is True:
                    services.setdefault(profile, []).append(s)
    for name, zone in external.items():
        profile, binding = bound.get(name, (None, None))
        enabled = services.get(profile, [])
        if enabled:
            lines = sorted({zone.line, binding.line, *(s.line for s in enabled)})
            yield _Candidate(MGMT_EXPOSED, True, lines, scope=f"interface {name}")


_EXTRACTORS = (
    _protocols, _source_restriction, _ssh_version, _idle_timeout, _remote_log, _ntp, _central_aaa, _ipsec,
    _snmp_community, _source_routing, _discovery, _banner, _permit_any, _flat_rule_permit_any, _exposed_management,
    _default_account, _flat_rule_logging, _ssh_algorithms,
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
