"""Remove final flags from searchable copies of parsed source text."""

from __future__ import annotations

import html
import re
from typing import NamedTuple
from urllib.parse import unquote, urlsplit, urlunsplit

EXCLUDED_FLAG = "<EXCLUDED_FLAG>"

_MAX_DECODE_INPUT_CHARS = 65_536
_MAX_DECODE_ROUNDS = 8
_MAX_DECODE_WORK_CHARS = 262_144
_ENCODING_MARKER_RE = re.compile(r"%(?:[0-9A-Fa-f]{2})|&")

_HTB_FLAG_RE = re.compile(r"HTB\{[^}]*\}", re.IGNORECASE)
_HTB_OPEN_MARKER_RE = re.compile(r"HTB\{", re.IGNORECASE)
_HTB_ENCODED_FLAG_RE = re.compile(r"HTB%7B(?:(?!%7D).)*%7D", re.IGNORECASE)
_HTB_ENCODED_OPEN_MARKER_RE = re.compile(r"HTB%7B", re.IGNORECASE)
_STANDALONE_32_HEX_RE = re.compile(r"(?<![A-Za-z0-9])[0-9A-Fa-f]{32}(?![A-Za-z0-9])")
_EXACT_HEX_FLAG_HEADINGS = frozenset(
    {
        "flag",
        "root",
        "root txt",
        "user",
        "user txt",
    }
)
_FLAG_WORDS = frozenset({"flag", "flags"})
_DIRECT_FLAG_CONTEXTS = frozenset({"final", "root", "user"})
_CAPTURE_VERBS = frozenset({"read", "retrieve", "submit"})


class _DecodeResult(NamedTuple):
    value: str
    stable: bool


def sanitize_searchable_text(text: str, heading_path: tuple[str, ...]) -> str:
    """Return a searchable copy with deterministic final-flag redaction.

    HTB flag tokens are excluded in every context. Bare 32-character hexadecimal
    values are ambiguous, so they are removed only under an explicit flag or a
    conventional machine ``User``/``Root`` heading. The input string and parsed
    source document remain untouched.
    """
    return _sanitize_searchable_text(text, heading_path, frozenset())


def sanitize_asset_target(target: str) -> str:
    """Return a retrieval-safe asset locator while raw metadata stays parsed-only.

    Asset locators are not strategic evidence and opaque 32-hex path components have
    no retrieval value, so this boundary redacts them conservatively in every context.
    """
    decoded = _recursively_decode(target)
    if not decoded.stable:
        return EXCLUDED_FLAG
    safe_target = _strip_unsafe_asset_locator_components(target)
    safe_decoded = _strip_unsafe_asset_locator_components(decoded.value)
    sanitized = _sanitize_asset_target_once(safe_target)
    decoded_sanitized = _sanitize_asset_target_once(safe_decoded)
    return decoded_sanitized if decoded_sanitized != decoded.value else sanitized


def _contextual_hex_flag_values(
    text: str,
    heading_path: tuple[str, ...],
) -> frozenset[str]:
    if not _is_hex_flag_context(heading_path):
        return frozenset()
    decoded = _recursively_decode(text)
    if not decoded.stable:
        return frozenset()
    return frozenset(
        match.group().casefold() for match in _STANDALONE_32_HEX_RE.finditer(decoded.value)
    )


def _sanitize_searchable_text(
    text: str,
    heading_path: tuple[str, ...],
    known_hex_flags: frozenset[str],
) -> str:
    sanitized = _sanitize_searchable_text_once(text, heading_path, known_hex_flags)
    decoded = _recursively_decode(text)
    if not decoded.stable:
        return EXCLUDED_FLAG
    decoded_sanitized = _sanitize_searchable_text_once(
        decoded.value,
        heading_path,
        known_hex_flags,
    )
    return decoded_sanitized if decoded_sanitized != decoded.value else sanitized


def _sanitize_searchable_text_once(
    text: str,
    heading_path: tuple[str, ...],
    known_hex_flags: frozenset[str],
) -> str:
    sanitized = _HTB_FLAG_RE.sub(EXCLUDED_FLAG, text)
    sanitized = _HTB_OPEN_MARKER_RE.sub(EXCLUDED_FLAG, sanitized)
    if _is_hex_flag_context(heading_path):
        sanitized = _STANDALONE_32_HEX_RE.sub(EXCLUDED_FLAG, sanitized)
    elif known_hex_flags:
        sanitized = _STANDALONE_32_HEX_RE.sub(
            lambda match: (
                EXCLUDED_FLAG if match.group().casefold() in known_hex_flags else match.group()
            ),
            sanitized,
        )
    return sanitized


def _sanitize_asset_target_once(target: str) -> str:
    sanitized = _HTB_ENCODED_FLAG_RE.sub(EXCLUDED_FLAG, target)
    sanitized = _HTB_ENCODED_OPEN_MARKER_RE.sub(EXCLUDED_FLAG, sanitized)
    sanitized = _HTB_FLAG_RE.sub(EXCLUDED_FLAG, sanitized)
    sanitized = _HTB_OPEN_MARKER_RE.sub(EXCLUDED_FLAG, sanitized)
    return _STANDALONE_32_HEX_RE.sub(EXCLUDED_FLAG, sanitized)


def _strip_unsafe_asset_locator_components(target: str) -> str:
    """Remove URL credentials and non-provenance components from a locator copy."""
    try:
        parsed = urlsplit(target)
    except ValueError:
        return "<REDACTED_ASSET_LOCATOR>"
    if not parsed.scheme and not parsed.netloc:
        return urlunsplit(("", "", parsed.path, "", "")) or "<REDACTED_ASSET_LOCATOR>"

    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"} or parsed.hostname is None:
        return "<REDACTED_ASSET_LOCATOR>"

    hostname = parsed.hostname
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    try:
        port = parsed.port
    except ValueError:
        return "<REDACTED_ASSET_LOCATOR>"
    authority = f"{hostname}:{port}" if port is not None else hostname
    return urlunsplit((scheme, authority, parsed.path, "", ""))


def _recursively_decode(text: str) -> _DecodeResult:
    if not _ENCODING_MARKER_RE.search(text):
        return _DecodeResult(text, True)
    if len(text) > _MAX_DECODE_INPUT_CHARS:
        return _DecodeResult(text, False)

    decoded = text
    work_chars = 0
    for _ in range(_MAX_DECODE_ROUNDS):
        if work_chars + len(decoded) > _MAX_DECODE_WORK_CHARS:
            return _DecodeResult(decoded, False)
        url_decoded = unquote(decoded)
        work_chars += len(decoded)
        if work_chars + len(url_decoded) > _MAX_DECODE_WORK_CHARS:
            return _DecodeResult(url_decoded, False)
        next_value = html.unescape(url_decoded)
        work_chars += len(url_decoded)
        if next_value == decoded:
            return _DecodeResult(decoded, True)
        decoded = next_value
    return _DecodeResult(decoded, not _ENCODING_MARKER_RE.search(decoded))


def _is_hex_flag_context(heading_path: tuple[str, ...]) -> bool:
    for part in heading_path:
        decoded = _recursively_decode(part)
        if not decoded.stable or _heading_is_hex_flag_context(decoded.value):
            return True
    return False


def _heading_is_hex_flag_context(heading: str) -> bool:
    normalized = _normalize_heading(heading)
    if normalized in _EXACT_HEX_FLAG_HEADINGS:
        return True
    words = tuple(normalized.split())
    if any(
        word in _DIRECT_FLAG_CONTEXTS and index + 1 < len(words) and words[index + 1] in _FLAG_WORDS
        for index, word in enumerate(words)
    ):
        return True
    if not any(word in _DIRECT_FLAG_CONTEXTS for word in words):
        return False
    return any(_is_capture_flag_phrase(words, index) for index in range(len(words)))


def _is_capture_flag_phrase(words: tuple[str, ...], index: int) -> bool:
    if words[index] not in _CAPTURE_VERBS or index + 1 >= len(words):
        return False
    following = words[index + 1]
    if following in _FLAG_WORDS:
        return True
    return following == "the" and index + 2 < len(words) and words[index + 2] in _FLAG_WORDS


def _normalize_heading(heading: str) -> str:
    return re.sub(r"[\W_]+", " ", heading.casefold()).strip()
