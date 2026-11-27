#!/usr/bin/env python3
"""Fetch configured public filter sources and merge them without rule rewriting."""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_SOURCES = ROOT / "sources.txt"
DEFAULT_OUTPUT = ROOT / "rules.txt"
USER_AGENT = "adguard-rule-aggregator/1.0"
MAX_SOURCE_BYTES = 32 * 1024 * 1024


def read_sources(path: Path) -> list[str]:
    urls = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            validate_url(value)
            urls.append(value)
    if not urls:
        raise ValueError("No source URLs configured")
    return urls


def validate_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"Only credential-free HTTPS source URLs are allowed: {url}")
    if parsed.port not in (None, 443):
        raise ValueError(f"Nonstandard source port is not allowed: {url}")
    try:
        addresses = [ipaddress.ip_address(parsed.hostname)]
    except ValueError:
        try:
            addresses = [
                ipaddress.ip_address(record[4][0])
                for record in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
            ]
        except OSError as exc:
            raise ValueError(f"Cannot resolve source host {parsed.hostname}: {exc}") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError(f"Source host must resolve only to public IP addresses: {parsed.hostname}")


class PublicRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def extract_rules(text: str) -> list[str]:
    """Unwrap a YAML filter using a real YAML parser; otherwise retain source lines."""
    lines = text.lstrip("\ufeff").splitlines()
    if any(line.strip() == "rules:" for line in lines):
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("PyYAML is required to parse YAML filter sources") from exc
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML filter: {exc}") from exc
        if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
            raise ValueError("YAML filter must contain a rules list")
        if any(not isinstance(rule, str) for rule in document["rules"]):
            raise ValueError("Every YAML filter rule must be a string")
        return document["rules"]
    return lines


def convert_known_titles(lines: list[str]) -> list[str]:
    """Turn the two known source title rows into comments, without editing rules."""
    titles = {"[Host 10007]", "[Adblock Plus 2.0]"}
    return [f"! {line.strip()}" if line.strip() in titles else line for line in lines]


def validate_filter_lines(lines: list[str]) -> None:
    """Reject syntax whose meaning depends on the original source file boundary."""
    depth = 0
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            raise ValueError(f"Unsupported bracketed section at line {number}: {stripped}")
        if not stripped.startswith("!#"):
            continue
        directive = stripped.split(None, 1)[0].lower()
        if directive == "!#if":
            depth += 1
        elif directive == "!#endif":
            if depth == 0:
                raise ValueError(f"Unmatched !#endif at line {number}")
            depth -= 1
        elif directive == "!#include":
            raise ValueError(
                f"!#include at line {number} depends on the original source location"
            )
        else:
            raise ValueError(f"Unsupported filter directive at line {number}: {directive}")
    if depth:
        raise ValueError("Unclosed !#if conditional block")


def fetch_source(url: str) -> list[str]:
    validate_url(url)
    opener = urllib.request.build_opener(PublicRedirectHandler)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=30) as response:
            content = response.read(MAX_SOURCE_BYTES + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(f"Failed to fetch {url}: {exc}") from exc
    if len(content) > MAX_SOURCE_BYTES:
        raise RuntimeError(f"Source exceeds {MAX_SOURCE_BYTES} bytes: {url}")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"Source is not valid UTF-8: {url}") from exc
    rules = convert_known_titles(extract_rules(text))
    if not any(line.strip() and not line.lstrip().startswith(("!", "#")) for line in rules):
        raise RuntimeError(f"Source contains no rules: {url}")
    validate_filter_lines(rules)
    return rules


def _read_rules_snapshot(path: Path, *, allow_empty: bool = False) -> tuple[list[str], bytes]:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Cannot read local rules file {path}: {exc}") from exc
    try:
        rules = content.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError(f"Local rules file is not valid UTF-8: {path}") from exc
    if not rules or not any(line.strip() for line in rules):
        if allow_empty:
            return [], content
        raise ValueError(f"Local rules file is empty: {path}")
    if any("\n" in line or "\r" in line for line in rules):
        raise ValueError(f"Local rules file contains multiline entries: {path}")
    validate_filter_lines(rules)
    return rules, content


def read_local_rules(path: Path, *, allow_empty: bool = False) -> list[str]:
    rules, _ = _read_rules_snapshot(path, allow_empty=allow_empty)
    return rules


def _ensure_unchanged(path: Path, expected: bytes) -> None:
    try:
        current = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Cannot recheck local rules file {path}: {exc}") from exc
    if current != expected:
        raise RuntimeError(
            f"Local rules file changed during update; no output written: {path}"
        )


def _open_exclusive_file(path: Path):
    """Open for update while excluding concurrent writers where the OS permits."""
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        create_file.restype = wintypes.HANDLE
        handle = create_file(
            str(path),
            0xC0000000,  # GENERIC_READ | GENERIC_WRITE
            0x00000001,  # FILE_SHARE_READ only
            None,
            3,  # OPEN_EXISTING
            0x00000080,  # FILE_ATTRIBUTE_NORMAL
            None,
        )
        if handle is None or handle == wintypes.HANDLE(-1).value:
            error = ctypes.get_last_error()
            raise OSError(error, "new_rules.txt is busy or cannot be opened", str(path))
        fd = msvcrt.open_osfhandle(int(handle), os.O_RDWR | os.O_BINARY)
        return os.fdopen(fd, "r+b")

    import fcntl

    stream = path.open("r+b")
    try:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        stream.close()
        raise
    return stream


def clear_new_rules_if_unchanged(path: Path, expected: bytes) -> bool:
    """Clear the queue only if its exact snapshot is still present and writable."""
    if not expected:
        try:
            return path.read_bytes() == b""
        except OSError:
            return False
    try:
        stream = _open_exclusive_file(path)
    except OSError:
        return False
    with stream:
        stream.seek(0)
        if stream.read() != expected:
            return False
        if os.name != "nt":
            try:
                current = path.stat()
                opened = os.fstat(stream.fileno())
            except OSError:
                return False
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                return False
        stream.seek(0)
        stream.truncate(0)
        stream.flush()
        os.fsync(stream.fileno())
    return True


def _contains_conditional_directives(rules: list[str]) -> bool:
    return any(
        line.strip().lower().startswith(("!#if", "!#endif"))
        for line in rules
    )


def _is_contiguous_subsequence(needle: list[str], haystack: list[str]) -> bool:
    return any(
        haystack[index : index + len(needle)] == needle
        for index in range(len(haystack) - len(needle) + 1)
    )


def merge_user_rules(existing: list[str], additions: list[str]) -> list[str]:
    """Persist staged additions once without deduping across conditional scopes."""
    if not additions:
        return list(existing)
    validate_filter_lines(existing)
    validate_filter_lines(additions)
    if not _contains_conditional_directives(existing + additions):
        merged: list[str] = []
        seen: set[str] = set()
        for line in existing + additions:
            if not line.strip() or line in seen:
                continue
            seen.add(line)
            merged.append(line)
        return merged

    # Keep a conditional addition as a source-scoped block. On repeat runs its
    # exact contiguous occurrence identifies that it has already been merged.
    if _is_contiguous_subsequence(additions, existing):
        return list(existing)
    overlap = 0
    for size in range(min(len(existing), len(additions)), 0, -1):
        if existing[-size:] == additions[:size]:
            overlap = size
            break
    return existing + additions[overlap:]


def merge_sources(
    urls: list[str],
    fetch=fetch_source,
    local_rules: list[str] | None = None,
) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    failures: list[str] = []
    sources = [("user_rules.txt", local_rules or [])]
    sources.extend((url, None) for url in urls)
    for label, rules in sources:
        try:
            source_rules = rules if rules is not None else fetch(label)
        except Exception as exc:
            failures.append(f"{label}: {exc}")
            continue
        # Conditional blocks are source-scoped. Keep their contents untouched,
        # including duplicates, rather than deduplicating across scopes.
        has_conditionals = any(
            line.strip().lower().startswith(("!#if", "!#endif"))
            for line in source_rules
        )
        for line in source_rules:
            # Preserve each non-empty source line byte-for-byte (apart from line endings).
            if not line.strip():
                continue
            if not has_conditionals:
                if line in seen:
                    continue
                seen.add(line)
            merged.append(line)
    if failures:
        raise RuntimeError("One or more sources failed; no output written:\n" + "\n".join(failures))
    if not merged:
        raise RuntimeError("All configured sources were empty")
    return merged


def update_rule_files(
    user_rules_path: Path,
    new_rules_path: Path,
    output_path: Path,
    urls: list[str],
    fetch=fetch_source,
) -> list[str]:
    original_user_rules, user_rules_snapshot = _read_rules_snapshot(user_rules_path)
    new_rules, new_rules_snapshot = _read_rules_snapshot(new_rules_path, allow_empty=True)
    updated_user_rules = merge_user_rules(original_user_rules, new_rules)
    # Fetch and validate every subscription before touching either persistent
    # output, so a source failure cannot partially apply the pending additions.
    merged = merge_sources(urls, fetch=fetch, local_rules=updated_user_rules)
    _ensure_unchanged(user_rules_path, user_rules_snapshot)
    _ensure_unchanged(new_rules_path, new_rules_snapshot)
    if updated_user_rules != original_user_rules:
        _ensure_unchanged(user_rules_path, user_rules_snapshot)
        atomic_write(user_rules_path, updated_user_rules)
    atomic_write(output_path, merged)
    if not clear_new_rules_if_unchanged(new_rules_path, new_rules_snapshot):
        raise RuntimeError(
            "new_rules.txt changed or is busy after output generation; "
            "the input was preserved for a safe retry"
        )
    return merged


def atomic_write(output: Path, rules: list[str]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = ("\n".join(rules) + "\n").encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--user-rules", type=Path, default=ROOT / "user_rules.txt")
    parser.add_argument("--new-rules", type=Path, default=ROOT / "new_rules.txt")
    args = parser.parse_args()
    try:
        urls = read_sources(args.sources)
        rules = update_rule_files(
            args.user_rules,
            args.new_rules,
            args.output,
            urls,
        )
    except Exception as exc:
        parser.exit(1, f"error: {exc}\n")
    print(f"Wrote {len(rules)} unique lines to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
