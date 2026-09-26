"""
Recognizers: admin-confirmed templates that answer a security predicate decisively.

    scan → provisional (heuristic) result → admin confirms a line → recognizer saved
         → next scan: the recognizer answers that syntax with a CONFIRMED fact -no heuristic, no AI

A recognizer is a learned mapping with extraction method ``recognizer``:

* ``command_pattern`` -typed-slot template, e.g. ``remote-console protocol {enum:protocol}``
* ``predicate`` / ``subject`` -the fact it produces
* ``scope_template`` -optional: some enclosing block header must match it
* ``dialect_fingerprint`` -top-level keywords of the config it was confirmed on; it only
  applies to configs sharing enough of them (empty = any dialect)
* ``negatives`` -lines it must never match
* ``constant_value`` -JSON: the value of a slot-less template, or an ``{enum:…}`` value table
  (``{"telnet": true, "*": false}``)
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Optional

from app.adaptive.matcher import (
    ANY_TOKEN, EXTRACTION_RECOGNIZER, NEGATION_SLOT, REST_TOKEN, PatternError, compile_pattern, match_recognizer,
    normalize_line, recognizer_slot, strip_terminator,
)
from app.facts import lexicon as L
from app.facts.heuristics import (
    _Candidate, _interfaces, _polarity, _version, combine, external_interfaces, heuristic_candidates, state_lines,
)
from app.facts.predicates import (
    ADMIN_ACCOUNT, CENTRAL_AAA, DISCOVERY_PROTOCOL, IDLE_TIMEOUT, LOG_REMOTE_DESTINATION, LOGIN_BANNER, LOGIN_MAX_ATTEMPTS,
    MGMT_EXPOSED, MGMT_WEAK_CRYPTO, NOT_SET, NTP_AUTHENTICATED, PASSWORD_MIN_LENGTH, ROUTER_UNSAFE_SERVICE, RULE_LOGGING,
    NTP_SERVER, PASSWORD_ENCRYPTION_SERVICE, PASSWORD_STORAGE, PERMIT_ANY, PROTOCOL_ENABLED, SOURCE_RESTRICTED,
    SNMP_COMMUNITY, SOURCE_ROUTING, SSH_VERSION, SecurityFact,
)
from app.models.results import Assurance
from app.structure.tokenizer import IP, NEGATIVE, NEGATORS, NUMBER, POSITIVE, Statement, tokenize, tokenize_line

logger = logging.getLogger(__name__)

BOOL_PREDICATES = frozenset({
    PROTOCOL_ENABLED, SOURCE_RESTRICTED, CENTRAL_AAA, NTP_AUTHENTICATED, LOGIN_BANNER, SOURCE_ROUTING,
    DISCOVERY_PROTOCOL, PERMIT_ANY, PASSWORD_ENCRYPTION_SERVICE, MGMT_EXPOSED, MGMT_WEAK_CRYPTO, RULE_LOGGING,
    ROUTER_UNSAFE_SERVICE,
})
# Settings a configuration states by *naming a thing*: the line exists only to configure them, so the
# address or name it carries is which instance, not whether the setting is on. No dialect writes
# "source restriction: on" -it writes ``permitted-ip 10.0.0.0/24`` or ``allow-address …``, and the
# line being there is the restriction.
#
# Every other boolean is a toggle, where a value says nothing about on or off: ``server 10.0.0.1``
# names an NTP server and states nothing about authenticating it. Adding a predicate here makes a
# line that only mentions the setting able to teach it, so the list stays short and deliberate.
# A login banner is the third: ``set login-banner "…"`` carries the message, and the message is the banner.
PRESENCE_PREDICATES = frozenset({SOURCE_RESTRICTED, CENTRAL_AAA, LOGIN_BANNER})
# How a configuration writes each concept. A line that states nothing of its own is evidence only
# when it is a line *about* the setting, and this is what says so; see ``_names_concept``.
CONCEPT_WORDS = {
    SOURCE_RESTRICTED: (L.SOURCE_RELATED,), IDLE_TIMEOUT: (L.IDLE_RELATED,),
    LOG_REMOTE_DESTINATION: (L.LOG_RELATED,), NTP_SERVER: (L.TIME_RELATED,), CENTRAL_AAA: (L.AAA_RELATED,),
    LOGIN_BANNER: (L.BANNER_RELATED,), SOURCE_ROUTING: (L.SOURCE_ROUTING,),
    PERMIT_ANY: (L.RULE_WORDS | L.PERMIT | L.DENY,), PASSWORD_STORAGE: (L.PASSWORD_RELATED,),
    PASSWORD_ENCRYPTION_SERVICE: (L.PASSWORD_RELATED,), SNMP_COMMUNITY: (L.SNMP,),
    MGMT_EXPOSED: (L.MGMT_EXPOSURE_RELATED,), LOGIN_MAX_ATTEMPTS: (L.LOCKOUT_RELATED,),
    PASSWORD_MIN_LENGTH: (L.PASSWORD_RELATED,), ADMIN_ACCOUNT: (L.ACCOUNT_RELATED,),
    MGMT_WEAK_CRYPTO: (L.CRYPTO_SETTING_RELATED,), RULE_LOGGING: (L.RULE_WORDS | L.RULE_LOG_WORDS,),
    ROUTER_UNSAFE_SERVICE: (L.ROUTER_SERVICE_WORDS,),
    # both sets must appear: a version is an SSH version, authentication is of the time source
    SSH_VERSION: (L.SSH, L.SSH_VERSION_RELATED), NTP_AUTHENTICATED: (L.TIME_RELATED, L.AUTH_RELATED),
}
# The slot kinds a value predicate may be read from; the first is what a draft uses.
# A destination is a ``{host}``: an address or a hostname. ``{ip}`` stays valid for recognizers
# written before ``{host}`` existed (including shipped seeds).
SLOT_PREDICATES = {
    SSH_VERSION: ("int",), IDLE_TIMEOUT: ("duration",), LOG_REMOTE_DESTINATION: ("host", "ip"),
    NTP_SERVER: ("host", "ip"), PASSWORD_STORAGE: ("enum",), SNMP_COMMUNITY: ("community",),
    LOGIN_MAX_ATTEMPTS: ("int",), PASSWORD_MIN_LENGTH: ("int",), ADMIN_ACCOUNT: ("enum",),
}
RECOGNIZER_PREDICATES = BOOL_PREDICATES | frozenset(SLOT_PREDICATES)
# Read by shipped seeds only, never taught: the line that states an SNMP community holds the community string
# itself, so a taught example could only be stored by storing the secret; an account is named by a value table
# of default names, which teaching does not draft.
SEED_ONLY_PREDICATES = frozenset({SNMP_COMMUNITY, ADMIN_ACCOUNT})
TEACHABLE_PREDICATES = RECOGNIZER_PREDICATES - SEED_ONLY_PREDICATES
# Predicates whose every statement is a separate object, never a second opinion on one setting
PER_STATEMENT = {SNMP_COMMUNITY: "snmp community", MGMT_EXPOSED: "management access", ADMIN_ACCOUNT: "account",
                 RULE_LOGGING: "rule", ROUTER_UNSAFE_SERVICE: "interface service"}
# The access a {community:<level>} slot's template states
COMMUNITY_ACCESS = frozenset({"RO", "RW"})
# Settings whose statement may end in ``{rest}``: a destination or an authentication server. What
# follows it (``514 protocol udp``, ``vrf mgmt``, ``key 1``, ``prefer``) says how to reach the server,
# never whether there is one. A toggle is different -a trailing word may be the one that switches it.
REST_PREDICATES = frozenset({LOG_REMOTE_DESTINATION, NTP_SERVER, CENTRAL_AAA})
STOPWORDS = POSITIVE | NEGATIVE | NEGATORS | {"set", "config", "edit", "next", "end", "exit", "state", "status"}
# A recognizer must be this specific. A hierarchical dialect keeps the nouns in the block header
# (``ntp { server 1.2.3.4; }``), so the scope template counts too -but never on its own: the
# statement itself must still carry a keyword, or the recognizer would answer any line in the block.
MIN_KEYWORDS = 2
FINGERPRINT_OVERLAP = 0.5
_DURATION = re.compile(r"^(\d+(?:\.\d+)?)([a-z]*)$")
_WORD = re.compile(r"^[a-z][\w.+-]*$")
# A hostname label chain: letters, digits and hyphens, dot-separated. Never a bare number.
_HOSTNAME = re.compile(r"^(?=.*[a-z])[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$")
_FQDN = re.compile(r"^(?=.*[a-z])[a-z0-9-]+(?:\.[a-z0-9-]+)+$")


class RecognizerError(ValueError):
    """A recognizer failed a safety gate."""


def _keywords(pattern: str) -> list[str]:
    """Literal words of a template: no slots, no punctuation, no stopwords."""
    return [t for t in map(strip_terminator, pattern.split()) if "{" not in t and t.lower() not in STOPWORDS]


# ── values ──────────────────────────────────────────────────────────────────

def recognizer_value(recognizer, slot: tuple) -> Any:
    """Fact value for a template match; None when the line gives no usable value."""
    kind, argument, text = slot
    constant = json.loads(recognizer.constant_value) if recognizer.constant_value else None
    if kind is None:
        return constant
    if kind == "neg":
        # the slot is the leading negator itself: absent means the statement is in force
        return text is None
    if kind == "community":
        # the access level is the template's own words (``authorization read-only``), never guessed; the ACL
        # is not read, so only a template whose line cannot carry one may state RW
        return {"name": text.strip("\"'"), "permission": (argument or "").upper() or None, "acl": None}
    word = text.strip("\"'").lower()
    if kind == "polarity":
        return word in POSITIVE
    if kind == "enum":
        return constant.get(word, constant.get("*")) if isinstance(constant, dict) else word
    if kind == "int":
        number = _version(word)
        return None if number is None else int(number)
    if kind == "ip":
        return [word] if IP.match(word) else None
    if kind == "host":
        # before trailing options a bare word may be one of them (``logging host inside 10.0.0.1``,
        # where "inside" names an interface): only an address or a dotted name is read as the host
        if REST_TOKEN in recognizer.command_pattern.split() and not (IP.match(word) or _FQDN.match(word)):
            return None
        return _host(word)
    number, unit = _DURATION.match(word).groups()
    unit = unit or (argument or "").lower()
    factor = 1 if unit in L.MINUTES else 1 / 60 if unit in L.SECONDS else 60 if unit in L.HOURS else None
    return float(number) * factor if factor else None


def stated_value(recognizer, value: Any, statement: Statement) -> Any:
    """What the whole statement says, where the slot alone would say more: ``permitted-ip 0.0.0.0/0``
    is there, and restricts nothing."""
    if recognizer.predicate == SOURCE_RESTRICTED and value is True \
            and (ips := [v for v in statement.values if IP.match(v)]) and all(ip in L.ANY_ADDRESS for ip in ips):
        return False
    return value


def _host(word: str) -> Optional[list[str]]:
    """``[destination]`` for an address or a hostname, None for anything that names no host.

    A polarity word and a bare number are refused rather than read as a host: an undetermined
    destination must leave the control undecided, never guess one."""
    if IP.match(word):
        return [word]
    return None if word in POSITIVE or word in NEGATIVE else ([word] if _HOSTNAME.match(word) else None)


def validate_recognizer(r) -> None:
    """Safety gates. Raises ``RecognizerError``."""
    if r.predicate not in RECOGNIZER_PREDICATES:
        raise RecognizerError(f"Recognizers cannot answer '{r.predicate}' yet")
    try:
        kind, argument = recognizer_slot(r.command_pattern)
        if r.scope_template:
            compile_pattern(r.scope_template, EXTRACTION_RECOGNIZER)
    except PatternError as e:
        raise RecognizerError(str(e)) from e
    if REST_TOKEN in r.command_pattern.split() and r.predicate not in REST_PREDICATES:
        raise RecognizerError(f"Only a destination or an authentication server may end in {REST_TOKEN}: "
                              "for any other setting a trailing word can change what the line says")

    keywords = _keywords(r.command_pattern)
    scoped = keywords + _keywords(r.scope_template or "")
    if not keywords or len(scoped) < MIN_KEYWORDS and not _one_word_feature(r, keywords, kind):
        raise RecognizerError(f"The template needs at least {MIN_KEYWORDS} keywords besides stopwords, counting "
                              f"its scope (found: {', '.join(scoped) or 'none'})")
    try:
        constant = json.loads(r.constant_value) if r.constant_value else None
    except ValueError as e:
        raise RecognizerError("The value must be JSON (true, false, a number, or an enum table)") from e

    slot = match_recognizer(r.command_pattern, r.example_line or "")
    if slot is None:
        raise RecognizerError("The template does not match its example line")
    if kind == "duration" and not argument and not _DURATION.match(slot[2].lower()).group(2):
        raise RecognizerError("The line states no unit: pick one with {duration:min}, {duration:s} or {duration:h}")
    value = recognizer_value(r, slot)

    example = tokenize_line(r.example_line) or Statement(0, "")
    # A line that states an on/off of its own can be taught in any words -that is the whole point of
    # teaching an unfamiliar dialect (``management-plane legacy-access disabled`` may mean Telnet).
    # A line that states nothing is different: it is evidence only because it is *there*, so it has to
    # be a line about the setting. Without this, ``uid 2001`` or ``login {`` would teach anything.
    # A value slot has no polarity to anchor it, so it always has to: otherwise ``class ops`` reads
    # "ops" as a syslog destination, and ``server 10.0.0.1`` under ``ntp`` teaches a log server.
    if r.predicate not in BOOL_PREDICATES or example.polarity is None:
        if not _names_concept(r.predicate, r.subject, [*example.key_tokens, *(r.scope_template or "").split()]):
            raise RecognizerError("This line states nothing on its own, and it does not name this setting "
                                  "either -so being in the file is not evidence about it. Pick the line "
                                  "that configures the setting, or one that says it is on or off.")

    if r.predicate in BOOL_PREDICATES:
        if kind is None:
            statement = tokenize_line(r.example_line)
            polarity = statement.polarity if statement else None
            if polarity is None and not _declares_presence(r, statement, value):
                raise RecognizerError("Polarity must be stated: a literal such as 'disabled', a {polarity} slot, "
                                      "an {enum:name} slot with a true / false value table, or a scoped bare "
                                      "statement that switches its feature on by existing")
            if polarity is not None and value is not polarity:
                raise RecognizerError(f"The value {json.dumps(value)} contradicts the line, which says "
                                      f"{'enabled' if polarity else 'disabled'}")
        elif kind == "enum":
            if not (isinstance(constant, dict) and constant and all(isinstance(v, bool) for v in constant.values())):
                raise RecognizerError('An {enum:name} slot needs a true / false value table, '
                                      'e.g. {"telnet": true, "*": false}')
        elif kind == "neg":
            # {neg} reads polarity from a negator, so a line without one says "on" by being there.
            # That is only evidence for a setting a configuration states by naming a thing; for a
            # toggle, a line carrying a value mentions the setting without stating it.
            statement = tokenize_line(r.example_line)
            if (statement is not None and statement.polarity is None and statement.values
                    and r.predicate not in PRESENCE_PREDICATES):
                raise RecognizerError("This line states a value for another setting and only mentions "
                                      "this one, so it cannot say whether this one is on or off")
        elif kind != "polarity":
            raise RecognizerError(f"A {{{kind}}} slot cannot say whether a setting is on or off")
        if not isinstance(value, bool):
            raise RecognizerError("The example line gives no true / false value")
    else:
        expected = SLOT_PREDICATES[r.predicate]
        if kind not in expected:
            raise RecognizerError(f"This setting is read from an {{{expected[0]}}} slot")
        if kind == "community" and (argument or "").upper() not in COMMUNITY_ACCESS:
            raise RecognizerError("A community slot states the access its line grants: {community:RO} or "
                                  "{community:RW}")
        if value is None:
            raise RecognizerError("The example line gives no usable value")


def _one_word_feature(r, keywords: list[str], kind: Optional[str]) -> bool:
    """``disable telnet``, ``lldp enable``, ``logging 192.0.2.20``: one word is enough when it is the
    feature itself and the rest of the line is only its switch or an address.

    Nothing else may vary (no ``{any}``), a switch has to be stated -a ``{polarity}`` slot, or ``{neg}``
    with a literal polarity word- and an address slot has to name the concept, so ``logging {ip}`` is
    read and ``buffered {ip}`` is not."""
    tokens = r.command_pattern.split()
    if len(keywords) != 1 or REST_TOKEN in tokens:
        return False
    # ``set login-banner "…"``: a setting stated by naming it, in a word that names nothing else
    if kind == "neg" and r.predicate in PRESENCE_PREDICATES and _names_concept(r.predicate, r.subject, keywords):
        return True
    if ANY_TOKEN in tokens:
        return False
    if kind == "ip":
        return _names_concept(r.predicate, r.subject, keywords)
    if kind not in ("polarity", "neg"):
        return False
    # The switch is spelled out (``disable telnet``, ``lldp enable``, ``set lldp enabled {polarity}``), or the
    # word is a feature compound (``set source-routing {polarity}``). ``set telnet {polarity}`` is neither: in a
    # block it may be a client or a per-interface setting, so it needs a scope.
    return (tokens[0] == "{polarity}" or any(t.lower() in POSITIVE | NEGATIVE for t in tokens)
            or "-" in keywords[0])


def _declares_presence(r, statement, value) -> bool:
    """A bare statement inside a named block switches its feature on by existing (``services { telnet; }``).

    Only ever True, only with a scope: without one the template would answer the same word anywhere in
    the configuration. Absence of the line still matches nothing, so it can never produce a value."""
    return (bool(r.scope_template) and value is True and statement is not None
            and len(statement.key_tokens) == 1 and not statement.values)


# ── matching ────────────────────────────────────────────────────────────────

def dialect_fingerprint(raw_lines: list[str]) -> str:
    return _fingerprint(tokenize(raw_lines))


def _fingerprint(statements: list[Statement]) -> str:
    """Leading keywords of top-level statements (a flat block counts once)."""
    return " ".join(sorted({s.key_tokens[0] for s in statements if s.scope_path in ((), (s.key_tokens[0],))}))


def enclosing_header(s: Statement) -> Optional[str]:
    """The innermost block header a statement sits in, or None at the top level.

    A flat prefix block (``logging host …`` twice in a row) is the tokenizer's own grouping, not a
    header the configuration wrote, so it is never the scope."""
    headers = s.scope_path[:-1] if s.block else s.scope_path
    return headers[-1] if headers else None


def _scope_matches(scope_template: str, s: Statement) -> bool:
    """The scope is the block the statement is *in*, never some outer ancestor: an NTP ``server``
    recognizer must not answer ``ntp { traceoptions { server … } }``."""
    header = enclosing_header(s)
    return header is not None and compile_pattern(scope_template, EXTRACTION_RECOGNIZER).match(header) is not None


def _dialect_matches(stored: Optional[str], current: set[str]) -> bool:
    words = set((stored or "").split())
    return not words or len(words & current) >= FINGERPRINT_OVERLAP * min(len(words), len(current))


def recognizer_facts(raw_lines: list[str], extra: Iterable = ()) -> tuple[list[SecurityFact], frozenset[int]]:
    """CONFIRMED facts from stored (+ ``extra``) recognizers, and the lines heuristics must skip:
    lines a recognizer answered or an administrator rejected."""
    facts, skip, _ = recognize(raw_lines, extra)
    return facts, skip


def recognize(raw_lines: list[str], extra: Iterable = ()):
    """``recognizer_facts`` plus a function that reads absence once every other fact is known (see ``_absence``)."""
    recognizers, rejected = _stored_knowledge()
    recognizers = [*recognizers, *extra]
    statements = tokenize(raw_lines)
    current = set(_fingerprint(statements).split())
    candidates, recognized, matched = [], set(), []
    external = external_interfaces(statements)

    for s in statements:
        for r in recognizers:
            try:
                if (normalize_line(s.text) in r.negatives or not _dialect_matches(r.dialect_fingerprint, current)
                        or r.scope_template and not _scope_matches(r.scope_template, s)
                        or (slot := match_recognizer(r.command_pattern, s.text)) is None):
                    continue
                value = recognizer_value(r, slot)
            except (PatternError, ValueError, AttributeError) as e:
                logger.warning("Recognizer #%s skipped: %s", getattr(r, "id", None), e)
                continue
            polarity, lines = _polarity(s, statements)
            if s.polarity is None and polarity is False:
                # a disabled block switches its settings off; its values configure nothing
                if r.predicate not in BOOL_PREDICATES:
                    continue
                value = False
            if value is None:
                continue
            value = stated_value(r, value, s)
            recognized.add(s.line)
            matched.append(r)
            # every community (every exposed zone) is its own fact: two of them are not a conflict about one setting
            scope = f"{PER_STATEMENT[r.predicate]} at line {s.line}" if r.predicate in PER_STATEMENT else None
            # a discovery protocol on an interface an external zone holds: the judge needs to know it is external
            if r.predicate == DISCOVERY_PROTOCOL and (wan := [n for n in _interfaces(s.key_tokens) if n in external]):
                scope, lines = f"interface {wan[0]}", sorted({*(lines or [s.line]), external[wan[0]].line})
            candidates.append(_Candidate(r.predicate, value, lines or [s.line], subject=r.subject, scope=scope,
                                         unit="min" if r.predicate == IDLE_TIMEOUT else None))

    from app.db.mappings import rejection_key  # the store imports this module for its gates

    skip = recognized | {n for n, text in enumerate(raw_lines, 1) if text.strip() and rejection_key(text) in rejected}
    dialect = _dialect(matched, recognizers, current)
    return (combine(candidates, raw_lines, Assurance.CONFIRMED), frozenset(skip),
            lambda known: _absence(known, dialect, statements))


def understood_dialect(raw_lines: list[str]) -> Optional[tuple[str, list]]:
    """The dialect this configuration is written in, as learned knowledge knows it (see ``_dialect``)."""
    recognizers, _ = _stored_knowledge()
    statements = tokenize(raw_lines)
    current = set(_fingerprint(statements).split())
    matched = [r for s in statements for r in recognizers
               if normalize_line(s.text) not in r.negatives and _dialect_matches(r.dialect_fingerprint, current)
               and not (r.scope_template and not _scope_matches(r.scope_template, s))
               and _safe_match(r, s.text)]
    return _dialect(matched, recognizers, current)


def _safe_match(r, text: str) -> bool:
    try:
        return match_recognizer(r.command_pattern, text) is not None
    except (PatternError, ValueError, AttributeError):
        return False


# Settings no device ships with: a remote log server, an AAA server, a login banner, a time source and its
# authentication exist only when someone configures them. For these alone, a setting the configuration
# does not state is a setting the device does not have -once we know the configuration would state it.
NO_FACTORY_DEFAULT = (CENTRAL_AAA, LOG_REMOTE_DESTINATION, LOGIN_BANNER, NTP_SERVER, NTP_AUTHENTICATED)
# A configuration is understood when one dialect's taught syntax answered at least this many settings
MIN_UNDERSTOOD = 3


def _dialect(matched: list, recognizers: list, current: set[str]) -> Optional[tuple[str, list]]:
    """(name, its recognizers) when one dialect's learned knowledge understands this configuration, else None.

    Learned knowledge only, no vendor code: the dialect is the vendor label of the seeds that matched
    (the clear winner) together with taught recognizers whose fingerprint matches this configuration,
    and it must have answered ``MIN_UNDERSTOOD`` settings here."""
    def local(r) -> bool:
        return bool(r.dialect_fingerprint) and _dialect_matches(r.dialect_fingerprint, current)

    def labels(r) -> set[str]:
        return {v.strip() for v in (r.vendor or "").split("/") if v.strip()}

    by_label: dict[str, set[str]] = defaultdict(set)
    for r in matched:
        for label in labels(r):
            by_label[label].add(r.predicate)
    ranked = sorted(by_label, key=lambda v: len(by_label[v]), reverse=True)
    if len(ranked) > 1 and len(by_label[ranked[0]]) == len(by_label[ranked[1]]):
        return None  # two dialects fit equally well: this configuration is not understood
    family = ranked[0] if ranked else None
    if len({r.predicate for r in matched if local(r) or family in labels(r)}) < MIN_UNDERSTOOD:
        return None
    return family or "this configuration's dialect", [r for r in recognizers if local(r) or family in labels(r)]


def _absence(known: list[SecurityFact], dialect: Optional[tuple[str, list]],
             statements: list[Statement]) -> list[SecurityFact]:
    """NOT_SET for each no-factory-default setting nothing states, when the dialect is understood.

    The dialect must know how it states the missing setting: absence of a syntax nobody taught is never
    read as absence of the setting. Any fact about the setting (a heuristic, an AI proposal, an
    undetermined value), or any line that so much as names it (``server-profile tacplus …`` in a variant
    the seed does not know), means it may be stated somewhere, and absence says nothing."""
    if dialect is None:
        return []
    name, own = dialect
    unset_by_default = _factory_defaults().get(name, {})
    eligible = (*NO_FACTORY_DEFAULT, *unset_by_default)
    syntax = {}
    for r in own:
        if r.predicate in eligible:
            syntax.setdefault(r.predicate, r.command_pattern)
    stated = {f.predicate for f in known}
    stated |= {p for p in syntax for st in statements if _mentions_setting(p, st)}
    return [SecurityFact(p, NOT_SET, Assurance.CONFIRMED,
                         provenance=f"no line states it; {name} states it as '{_shown(syntax[p])}'"
                                    + (f". {unset_by_default[p]}" if p in unset_by_default else ""))
            for p in eligible if p in syntax and p not in stated]


@lru_cache(maxsize=1)
def _factory_defaults() -> dict[str, dict[str, str]]:
    """data/factory_defaults.json: per dialect, settings its devices do not enforce until configured."""
    path = Path(__file__).resolve().parents[2] / "data" / "factory_defaults.json"
    return {k: v for k, v in json.loads(path.read_text(encoding="utf-8")).items() if not k.startswith("_")}


# Password words alone name a password (a hash, a user's secret), not its policy: a line may only be the length
# setting stated some other way when it also speaks of length or complexity
ABSENCE_WORDS = {PASSWORD_MIN_LENGTH: frozenset({"length", "len", "minlen", "complexity"})}


def _mentions_setting(predicate: str, st: Statement) -> bool:
    words = [*st.key_tokens, *(w for h in st.scope_path for w in h.split())]
    if not _names_concept(predicate, None, words):
        return False
    extra = ABSENCE_WORDS.get(predicate)
    return not extra or bool({p for w in words for p in {w.lower(), *re.split(r"[-_./]", w.lower())}} & extra)


def _shown(pattern: str) -> str:
    """A template as a person reads it: ``set system syslog host {host} {rest}`` → ``set system syslog host …``."""
    text = re.sub(r"\{[^{}]*\}", "…", pattern.replace(NEGATION_SLOT, "").replace(REST_TOKEN, ""))
    return re.sub(r"\s+", " ", re.sub(r"…(\s*…)+", "…", text)).strip()


def _stored_knowledge() -> tuple[list, set[str]]:
    """Active confirmed recognizers and rejected line keys; a store failure means no knowledge."""
    try:
        from app.db.mappings import MappingRepository  # the store imports this module for its gates

        repository = MappingRepository()
        recognizers = [m for m in repository.list_mappings()
                       if m.confirmed and m.extraction_method == EXTRACTION_RECOGNIZER]
        return recognizers, repository.rejected_line_keys()
    except Exception as e:
        logger.warning("Recognizer store unavailable -continuing without it: %s", e)
        return [], set()


# ── review queue and drafting ───────────────────────────────────────────────

def provisional_lines(raw_lines: list[str], needs: Iterable[str],
                      extra: Iterable[_Candidate] = ()) -> list[tuple[int, _Candidate]]:
    """Heuristic statements (and ``extra``: verified AI judge proposals) an administrator can confirm, by line."""
    _, skip = recognizer_facts(raw_lines)
    statements = tokenize(raw_lines)
    found: dict[int, _Candidate] = {}
    for c in [*heuristic_candidates(raw_lines, skip), *extra]:
        if c.predicate in needs and c.predicate in TEACHABLE_PREDICATES:
            for n in set(c.lines) - state_lines(c, statements) - skip:
                found.setdefault(n, c)
    return sorted(found.items(), key=lambda item: item[0])


def draft_recognizer(raw_lines: list[str], needs: Iterable[str], line_number: int,
                     extra: Iterable[_Candidate] = (), asserted: Optional[_Candidate] = None) -> dict:
    """Recognizer fields drafted from a line (the admin reviews them before saving).

    The line is one a heuristic or a verified AI proposal read, or -``asserted`` -any line of the
    configuration whose meaning an administrator stated. Either way the draft is only a proposal:
    ``validate_recognizer`` still has to find that meaning on the line itself.
    """
    candidate = asserted or dict(provisional_lines(raw_lines, needs, extra)).get(line_number)
    if candidate is None:
        raise LookupError(f"Line {line_number} holds no provisional statement for this control")
    statement = next(s for s in tokenize(raw_lines) if s.line == line_number)
    scope = _draft_scope(statement)
    template, value = _draft_template(statement, candidate, scope)
    return dict(
        command_pattern=template,
        constant_value=None if value is None else json.dumps(value),
        predicate=candidate.predicate,
        subject=candidate.subject,
        scope_template=scope,
        dialect_fingerprint=dialect_fingerprint(raw_lines),
        example_line=statement.text.strip(),
    )


def _names_concept(predicate: str, subject: Optional[str], words: Iterable[str]) -> bool:
    """Do these words name the concept, the way configurations write it? (``permitted-ip`` yes, ``uid`` no)

    Words are compared whole and by their parts, the way the lexicon is matched everywhere else. A
    protocol is named by its own name, so ``telnet`` is what a Telnet recognizer has to find."""
    if predicate == PROTOCOL_ENABLED:
        required = (L.MGMT_PROTOCOLS.get(subject, frozenset()),)
    elif predicate == DISCOVERY_PROTOCOL:
        required = (frozenset({subject}) if subject in L.DISCOVERY else frozenset(),)
    else:
        required = CONCEPT_WORDS.get(predicate, ())
    if not required or not all(required):
        return False
    parts = {p for w in words for p in ({w.lower()} | set(re.split(r"[-_./]", w.lower())))}
    return all(parts & vocabulary for vocabulary in required)


def _states_by_presence(predicate: str, s: Statement, scope: Optional[str]) -> bool:
    """A setting this line states simply by being there -and it must be a line about that setting."""
    if predicate not in PRESENCE_PREDICATES:
        return False
    words = [*s.key_tokens, *(t for header in s.scope_path for t in header.split()), *(scope or "").split()]
    return _names_concept(predicate, None, words)


def _addresses(tokens: list[str], s: Statement) -> list[str]:
    """The statement's own value tokens among ``tokens``: addresses and numbers, never quoted prose.

    Only these are generalized, because each is one whole token: a quoted string can be any number of
    tokens, so replacing it would tie the template to how many words this one example happened to have."""
    return [t for t in tokens if (bare := strip_terminator(t).strip("\"'").lower()) in s.values
            and (IP.match(bare) or NUMBER.match(bare))]


def _specific_enough(template: str, scope: Optional[str]) -> bool:
    """The keyword gate of ``validate_recognizer``, asked before a draft trades a literal for a slot."""
    keywords = _keywords(template)
    return bool(keywords) and len(keywords + _keywords(scope or "")) >= MIN_KEYWORDS


def _draft_template(s: Statement, c: _Candidate, scope: Optional[str] = None) -> tuple[str, Any]:
    # Template tokens are the statement's words: block punctuation and statement terminators are not part
    # of any token, so a drafted value slot lines up with the value the candidate was read from.
    tokens = [t for t in map(strip_terminator, s.text.split()) if t not in ("{", "}")]
    words = [t.strip("\"'").lower() for t in tokens]

    def slot(index: int, kind: str, tail: bool = False) -> str:
        """The template with token ``index`` replaced by a typed slot.

        ``tail``: the tokens after it become ``{any}`` -a facility, an id or an index qualifies the
        value, it does not state it, so keeping it literal would tie the recognizer to one instance."""
        name = words[index - 1] if index and _WORD.match(words[index - 1]) else "value"
        placeholder = f"{{enum:{name}}}" if kind == "enum" else f"{{{kind}}}"
        rest = [ANY_TOKEN] * (len(tokens) - index - 1) if tail else tokens[index + 1:]
        return " ".join([*tokens[:index], placeholder, *rest])

    def generalized(index: int, kind: str) -> str:
        """``slot(index, kind)`` with its tail generalized, unless that would cost the keyword gate."""
        wide = slot(index, kind, tail=True)
        return wide if _specific_enough(wide, scope) else slot(index, kind)

    if c.predicate in BOOL_PREDICATES:
        # A leading negator states the polarity of the whole statement, so it outranks any
        # enabled / on / active word inside it. {neg} makes one recognizer of both forms.
        if len(tokens) > 1 and words[0] in NEGATORS and c.value is False:
            return " ".join([NEGATION_SLOT, *tokens[1:]]), None
        polar = [i for i, w in enumerate(words) if w in POSITIVE | NEGATIVE and not (i == 0 and w in NEGATORS)]
        if polar and (words[polar[-1]] in POSITIVE) == c.value:
            return slot(polar[-1], "polarity"), None
        # A setting stated by naming a thing: the address or name is which instance is configured, so
        # it becomes {any} and the line's presence is what says "on" -negated, the same recognizer
        # says "off". Keeping the address literal would tie the recognizer to one subnet.
        if _states_by_presence(c.predicate, s, scope) and c.value is True and _addresses(tokens, s):
            return " ".join([NEGATION_SLOT, *(ANY_TOKEN if _addresses([t], s) else t for t in tokens)]), None
        names = L.MGMT_PROTOCOLS.get(c.subject, {c.subject}) if c.subject else set()
        # A protocol named *after* a keyword is one choice among several (``remote-console protocol
        # telnet``). Leading the statement it is the feature itself (``telnet server``), and turning it
        # into a slot would throw away the one word that says which feature this line configures.
        if len(words) > 1 and (index := next((i for i, w in enumerate(words) if i and w in names), None)) is not None:
            # a selector: naming another protocol means this one is off
            return slot(index, "enum"), {words[index]: c.value, "*": not c.value}
        # the last word as a value table -but not when trading it for a slot costs the keyword gate,
        # because then the statement's own words, read with {neg} below, say more than the table would
        if len(words) > 1 and _WORD.match(words[-1]) and _specific_enough(slot(len(words) - 1, "enum"), scope):
            return slot(len(words) - 1, "enum"), {words[-1]: c.value}
        # The statement is the feature itself: on where it stands, off where it is negated. Only a
        # statement carrying no value can mean that -``server 10.0.0.1`` names a server and says
        # nothing about a true/false setting, so reading {neg} off it would be a guess. The keyword
        # gate still decides whether what is left is specific enough to answer with.
        if c.value is True and not s.values:
            return " ".join([NEGATION_SLOT, *tokens]), None
        return " ".join(tokens), c.value

    kind = SLOT_PREDICATES[c.predicate][0]
    # what counts as a value here is what the fact was read from, so the slot lands on the same token;
    # a destination is looked for as an address first, then an FQDN, then a bare hostname
    matchers = {"int": (_version,), "duration": (_DURATION.match,), "enum": (_WORD.match,),
                "host": (IP.match, _FQDN.match, _host)}[kind]
    index = next((i for match in matchers
                  for i in reversed(range(1, len(words))) if match(words[i]) is not None), None)
    if index is None:
        return " ".join(tokens), c.value
    # a duration whose line states no unit carries the unit the fact was read with, so the draft validates
    if kind == "duration" and c.unit and not _DURATION.match(words[index]).group(2):
        return generalized(index, f"duration:{c.unit}"), None
    return generalized(index, kind), None


def _draft_scope(s: Statement) -> Optional[str]:
    """The innermost enclosing block header (not a flat prefix), with its arguments as ``{any}``."""
    header = enclosing_header(s)
    if header is None:
        return None
    tokens = [t for t in header.split() if "{" not in t and "}" not in t]
    return " ".join(t if _WORD.match(t.lower()) else "{any}" for t in tokens) or None
