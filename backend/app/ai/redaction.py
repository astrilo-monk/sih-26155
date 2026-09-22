"""
Secret redaction for everything sent to the AI provider.

Configuration lines carry passwords, hashes, pre-shared keys and SNMP
communities. None of those values may leave the process, but the *kind* of
secret is still useful (a weak-encoding control needs to know a password is
``type7``), so values are replaced by typed placeholders:

    enable password 7 0822455D0A16   →  enable password 7 <SECRET:type7>
    snmp-server community public RO  →  snmp-server community <SECRET:snmp-community> RO
    set psksecret ENC abc123==       →  set psksecret ENC <SECRET:psk>

Redaction is vendor-neutral and errs on the side of removing too much:

* secret keywords are whole tokens or hyphenated compounds
  (``password``, ``sso-password``, ``ppk-secret``, ``wpa-psk``,
  ``message-digest-key`` …)
* storage / mode words between keyword and value are kept
  (``7``, ``level 15``, ``cipher``, ``ENC``, ``ascii-text`` …)
* an unquoted value runs until a known trailing option (``address``,
  ``privilege``, ``encrypted`` …), so secrets with spaces are removed whole
* ``key=value``, ``key: value``, JSON pairs and XML elements are handled, as
  are secrets without a keyword (``snmp-server host … <community>``,
  ``authentication text …``) and base64 key material
* scope-dependent rules (FortiOS ``set name`` inside an SNMP community block)
  use each line's own block path; an unknown path is treated conservatively

A :class:`Redactor` remembers every value it removed (plus values registered
with :meth:`Redactor.add_secret`), so free text built from the same
configuration can be cleaned with :meth:`Redactor.scrub`.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional, Sequence

_PLACEHOLDER_PREFIX = "<SECRET:"

# Block path used when a line's real path is unknown: every scope-dependent rule applies
UNKNOWN_SCOPE = ("(block path unknown - treated as an snmp community block)",)

_EXACT_KEYWORDS = {
    "password": "password",
    "passwd": "password",
    "passphrase": "password",
    "secret": "password",
    "phash": "password",
    "password-hash": "password",
    "password-encrypt": "key",
    "key": "key",
    "key-string": "key",
    "token": "key",
    "psk": "psk",
    "psksecret": "psk",
    "pwd": "password",
    "passcode": "password",
    "credential": "password",
    "credentials": "password",
    "hash": "password",
}
_COMPOUND_KEYWORDS = (
    (re.compile(r"^[a-z0-9][\w-]*-(?:password|passwd|passphrase|pwd|secret|pass|passcode|credentials?)(?:-value)?$"
                r"|^(?:[\w-]+-)?(?:auth|secret|password)-string$"), "password"),
    (re.compile(r"^(?:[\w-]+-)?community(?:-string)?$"), "snmp-community"),
    (re.compile(r"^[a-z0-9][\w-]*-token$"), "key"),
    (re.compile(r"^(?:[\w-]+-)?(?:pre-shared|preshared|shared|psk|wep|wpa|ppk)-key$|^[a-z0-9][\w-]*-(?:psk|psksecret)$"), "psk"),
    (re.compile(
        r"^(?:[\w-]+-)?(?:authentication|message-digest|auth|api|private|secret|tacacs|radius|server|md5|hmac|encryption)"
        r"-key(?:-string)?$"
    ), "key"),
)

# Storage-type and mode words that sit between a keyword and its value
_STORAGE_TOKENS = frozenset({
    "enc", "encrypted", "hashed", "plaintext", "plain-text", "cleartext", "unencrypted",
    "ascii", "ascii-text", "hex", "hexadecimal", "simple", "cipher", "ciphertext", "irreversible-cipher",
    "sha512", "sha384", "sha256", "sha1", "sha", "md5", "scrypt", "pbkdf2", "local", "remote", "level",
})
_COMMUNITY_SKIP = frozenset({"read", "write", "ro", "rw", "cipher", "simple", "plain", "encrypted", "ascii"})

# A keyword followed by one of these is a sub-command, not a secret
_NOT_A_VALUE = frozenset({
    "encryption", "policy", "generate", "zeroize", "chain", "config-key", "config", "view",
    "mode", "required", "none", "enable", "disable", "enabled", "disabled", "rotation",
    "strength", "min-length", "lifetime", "recovery", "import", "export", "hostname",
    "pubkey-chain", "address", "{", "}", "[", "]", "];",
})

# Options that may follow a secret on the same line; the secret ends before them
_TRAILING_OPTIONS = frozenset({
    "address", "privilege", "encrypted", "pbkdf2", "nt-encrypted", "mschap", "timeout", "port",
    "auth-port", "acct-port", "single-connection", "level", "role", "group", "vrf", "view",
    "access-class", "autocommand", "nopassword", "noescape", "nohangup", "one-time", "ro", "rw",
    "version", "udp-port", "source", "interface", "priority", "retransmit", "no-xauth",
    "hostname", "mask", "identity", "peer", "remote", "local", "expire", "type", "host",
    "server", "user", "username", "description",
})

_KEYWORD_TOKEN = re.compile(r"(?<![\w<-])[A-Za-z][\w-]*(?![\w-])")
_SEPARATOR = re.compile(r"\s*=\s*|\s*:\s*|\s+")
_TOKEN = re.compile(r'"[^"]*"?|\'[^\']*\'?|\S+')
_SENTENCE_END = re.compile(r"[.,;!?](?=\s|$)")
_ISAKMP = re.compile(r"\bisakmp\b", re.IGNORECASE)

# Base64 key material: long runs, runs mixing letters and digits, or padded tails
_BLOB = re.compile(
    r"^(?P<indent>\s*)(?:[A-Za-z0-9+/]{40,}={0,2}"
    r"|(?=[A-Za-z0-9+/]*\d)(?=[A-Za-z0-9+/]*[A-Za-z])[A-Za-z0-9+/]{16,}={0,2}"
    r"|[A-Za-z0-9+/]{8,}={1,2})\s*$"
)
_JSON_PAIR = re.compile(r'(?P<head>"(?P<kw>[A-Za-z][\w-]*)"\s*:\s*")(?P<value>(?:[^"\\]|\\.)*)(?=")')
_XML_ELEMENT = re.compile(r"(?P<head><(?P<kw>[A-Za-z][\w-]*)(?:\s[^>]*)?>)(?P<value>[^<]+)(?=</(?P=kw)>)")
_SNMP_CONTEXT = re.compile(r"\bsnmp|\bv3\b", re.IGNORECASE)
_SNMP_V3 = re.compile(
    r"(?<![\w-])(?P<head>(?:auth\s+(?:md5|sha[\w-]*)|priv(?:\s+(?:des[\w-]*|3des|aes[\w-]*)(?:\s+\d+)?)?)\s+)"
    r"(?P<value>(?!<SECRET:)[^\s;]+)",
    re.IGNORECASE,
)
# Cisco: snmp-server host <addr> [vrf X] [traps|informs] [version 1|2c|3 [auth|noauth|priv]] <community>
_SNMP_HOST = re.compile(
    r"^(?P<head>\s*snmp-server\s+host\s+\S+(?:\s+vrf\s+\S+)?(?:\s+(?:traps|informs))?"
    r"(?:\s+version\s+(?:1|2c|3(?:\s+(?:auth|noauth|priv))?))?\s+)"
    r"(?P<value>(?!community\b)(?!\d{1,3}(?:\.\d{1,3}){3}\b)(?!<SECRET:)[^\s;]+)",
    re.IGNORECASE,
)
# EXOS: configure account <user> [encrypted] <password> -the secret has no keyword of its own
_EXOS_ACCOUNT = re.compile(r"^(?P<head>\s*configure\s+account\s+(?!add\b|delete\b)\S+\s+(?:encrypted\s+)?)"
                           r"(?P<value>(?!<SECRET:)(?!(?:password-policy|encrypted)\b)[^\s;]+)", re.IGNORECASE)
_AUTH_TEXT = re.compile(r"(?<![\w-])(?P<head>authentication\s+text\s+)(?P<value>(?!<SECRET:)[^\s;]+)", re.IGNORECASE)
# Routing peers: bgp neighbor <addr> [...] md5 <key>
_PEER_MD5 = re.compile(r"(?<![\w-])(?P<head>(?:neighbor|peer)\s+\S+\s+(?:\S+\s+)*?md5\s+)(?P<value>(?!<SECRET:)[^\s;]+)",
                       re.IGNORECASE)
_SNMP_COMMUNITY_SCOPE = re.compile(r"snmp.*communit", re.IGNORECASE)
_SET_NAME = re.compile(r'(?<![\w-])(?P<head>set\s+name\s+)(?P<value>"[^"]*"|\'[^\']*\'|[^\s;]+)', re.IGNORECASE)


def placeholder(kind: str) -> str:
    return f"{_PLACEHOLDER_PREFIX}{kind}>"


def keyword_kind(token: str) -> Optional[str]:
    """Placeholder kind for a secret keyword token, or None if it is not one."""
    lowered = token.lower()
    if lowered in _EXACT_KEYWORDS:
        return _EXACT_KEYWORDS[lowered]
    for pattern, kind in _COMPOUND_KEYWORDS:
        if pattern.match(lowered):
            return kind
    return None


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


class Redactor:
    """Redacts configuration lines and remembers the secret values it removed."""

    def __init__(self) -> None:
        self.secrets: set[str] = set()

    def add_secret(self, value: Optional[str]) -> None:
        """Register a secret known from parsed data (e.g. an SNMP community name)."""
        if value:
            self._remember(value)

    def line(self, text: str, scope: Sequence[str] = (), prose: bool = False) -> str:
        """Redact one line. ``scope`` is its ancestor block headers; ``prose`` is for chat text."""
        if not text:
            return text

        blob = _BLOB.match(text)
        if blob and not prose:
            self._remember(text)
            return blob.group("indent") + placeholder("key")

        text = _JSON_PAIR.sub(self._structured, text)
        text = _XML_ELEMENT.sub(self._structured, text)
        if _SNMP_CONTEXT.search(text):
            text = _SNMP_V3.sub(lambda m: self._swap(m, "password"), text)
        text = _SNMP_HOST.sub(lambda m: self._swap(m, "snmp-community"), text)
        text = _AUTH_TEXT.sub(lambda m: self._swap(m, "password"), text)
        text = _EXOS_ACCOUNT.sub(lambda m: self._swap(m, "password"), text)
        text = _PEER_MD5.sub(lambda m: self._swap(m, "key"), text)
        if any(_SNMP_COMMUNITY_SCOPE.search(h) for h in scope):
            text = _SET_NAME.sub(lambda m: self._swap(m, "snmp-community"), text)
        return self._keyword_values(text, prose)

    def lines(self, texts: Iterable[str], scope: Sequence[str] = ()) -> list[str]:
        return [self.line(t, scope) for t in texts]

    def text(self, text: str, prose: bool = False) -> str:
        """Redact every line of a multi-line block."""
        return "\n".join(self.line(t, prose=prose) for t in (text or "").split("\n"))

    def scrub(self, text: str) -> str:
        """Replace every known secret value in free text; prose is otherwise untouched."""
        if not text:
            return text
        for secret in sorted(self.secrets, key=len, reverse=True):
            if len(secret) < 2:
                continue
            text = re.sub(rf"(?<![\w$]){re.escape(secret)}(?![\w$])", placeholder("redacted"), text)
        return text

    # ── internals ───────────────────────────────────────────────────────────

    def _remember(self, value: str) -> None:
        value = _unquote(value)
        if value and _PLACEHOLDER_PREFIX not in value:
            self.secrets.add(value)

    def _swap(self, match: re.Match, kind: str) -> str:
        self._remember(match.group("value"))
        return match.group("head") + placeholder(kind)

    def _structured(self, match: re.Match) -> str:
        kind = keyword_kind(match.group("kw"))
        value = match.group("value")
        if kind is None or not value.strip() or value.startswith(_PLACEHOLDER_PREFIX):
            return match.group(0)
        return self._swap(match, kind)

    def _keyword_values(self, text: str, prose: bool) -> str:
        out: list[str] = []
        pos = 0
        for match in _KEYWORD_TOKEN.finditer(text):
            if match.start() < pos:
                continue
            kind = keyword_kind(match.group(0))
            if kind is None:
                continue
            span = self._value_span(text, match, kind, prose)
            if span is None:
                continue
            start, end, kind = span
            self._remember(text[start:end])
            out.append(text[pos:start])
            out.append(placeholder(kind))
            pos = end
        out.append(text[pos:])
        return "".join(out)

    def _value_span(self, text: str, match: re.Match, kind: str, prose: bool) -> Optional[tuple[int, int, str]]:
        separator = _SEPARATOR.match(text, match.end())
        if not separator:
            return None
        single_token = "=" in separator.group(0) and not prose
        tokens = [(t.start(), t.end(), t.group(0)) for t in _TOKEN.finditer(text, separator.end())]

        community = kind == "snmp-community"
        skip_words = _COMMUNITY_SKIP if community else _STORAGE_TOKENS
        skipped: list[str] = []
        idx = 0
        if not single_token:
            while idx < len(tokens) and (
                tokens[idx][2].lower() in skip_words
                or (not community and tokens[idx][2].isdigit() and len(tokens[idx][2]) <= 3)
            ):
                skipped.append(tokens[idx][2])
                idx += 1
        if idx == len(tokens):
            return None

        start, end, token = tokens[idx]
        if token.startswith(_PLACEHOLDER_PREFIX) or _unquote(token).lower() in _NOT_A_VALUE:
            return None

        if token[0] in "\"'":
            pass
        elif prose:
            sentence_end = _SENTENCE_END.search(text, start)
            end = sentence_end.start() if sentence_end else len(text)
        elif not (single_token or community):
            for t_start, t_end, t in tokens[idx + 1:]:
                if (
                    t.lower() in _TRAILING_OPTIONS
                    or keyword_kind(t)
                    or t.startswith(("#", "!", _PLACEHOLDER_PREFIX))
                    or (len(t) == 1 and t.isdigit() and t_end == tokens[-1][1])
                ):
                    break
                end = t_end
        while end > start and (text[end - 1] == ";" or text[end - 1].isspace()):
            end -= 1
        if end <= start:
            return None

        if kind == "key" and _ISAKMP.search(text):
            kind = "psk"
        if kind in ("password", "key") and len(skipped) == 1 and len(skipped[0]) == 1 and skipped[0].isdigit():
            kind = f"type{skipped[0]}"
        return start, end, kind


def redact_line(text: str, scope: Sequence[str] = ()) -> str:
    """Stateless convenience wrapper around :meth:`Redactor.line`."""
    return Redactor().line(text, scope)


def redact_text(text: str, prose: bool = False) -> str:
    """Redact every line of a multi-line block (``prose=True`` for chat messages)."""
    return Redactor().text(text, prose=prose)
