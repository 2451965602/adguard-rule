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


def merge_sources(urls: list[str], fetch=fetch_source) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    failures: list[str] = []
    for url in urls:
        try:
            source_rules = fetch(url)
        except Exception as exc:
            failures.append(f"{url}: {exc}")
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
    args = parser.parse_args()
    try:
        rules = merge_sources(read_sources(args.sources))
        atomic_write(args.output, rules)
    except Exception as exc:
        parser.exit(1, f"error: {exc}\n")
    print(f"Wrote {len(rules)} unique lines to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
