#!/usr/bin/env python3
"""Render an Nginx allowlist from the official OpenAI connector ranges."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import tempfile
from typing import Any
import urllib.parse
import urllib.request


DEFAULT_SOURCE = "https://openai.com/chatgpt-connectors.json"


def parse_prefixes(payload: Any) -> tuple[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    """Return the source timestamp and validated public networks."""
    if not isinstance(payload, dict):
        raise ValueError("OpenAI connector data must be a JSON object")
    creation_time = payload.get("creationTime")
    entries = payload.get("prefixes")
    if not isinstance(creation_time, str) or not creation_time.strip():
        raise ValueError("OpenAI connector data has no creationTime")
    if not isinstance(entries, list):
        raise ValueError("OpenAI connector data has no prefixes array")

    networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("OpenAI connector prefix entry must be an object")
        raw = entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
        if not isinstance(raw, str):
            raise ValueError("OpenAI connector prefix entry has no IP prefix")
        network = ipaddress.ip_network(raw, strict=True)
        if not network.is_global:
            raise ValueError(f"OpenAI connector prefix is not public: {network}")
        networks.add(network)

    if len(networks) < 10:
        raise ValueError("OpenAI connector data contains fewer than 10 public prefixes")
    return creation_time.strip(), sorted(networks, key=lambda item: (item.version, int(item.network_address), item.prefixlen))


def render_allowlist(creation_time: str, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> str:
    """Return an Nginx include file for validated networks."""
    lines = [
        "# Generated from https://openai.com/chatgpt-connectors.json.",
        f"# Source creationTime: {creation_time}",
        "allow 127.0.0.1;",
        "allow ::1;",
    ]
    lines.extend(f"allow {network};" for network in networks)
    return "\n".join(lines) + "\n"


def fetch_payload(source_url: str) -> Any:
    """Download and parse the official connector data."""
    parsed = urllib.parse.urlparse(source_url)
    if parsed.scheme != "https" or parsed.hostname != "openai.com" or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Connector source must be the official OpenAI HTTPS URL")
    request = urllib.request.Request(source_url, headers={"User-Agent": "power-wiki-allowlist/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def atomic_write(path: Path, content: str) -> None:
    """Write one generated file with an atomic replacement."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    """Render the current allowlist."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-url", default=DEFAULT_SOURCE)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()

    creation_time, networks = parse_prefixes(fetch_payload(arguments.source_url))
    atomic_write(arguments.output, render_allowlist(creation_time, networks))
    print(json.dumps({"status": "ok", "creationTime": creation_time, "prefixes": len(networks), "output": str(arguments.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
