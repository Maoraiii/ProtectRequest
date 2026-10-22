"""Parser registry + auto-detection."""

from __future__ import annotations

from typing import Dict, Iterable, List, Type

from .base import Parser
from .http import CombinedParser, NginxErrorParser, RequestShieldParser
from .iis import IISParser
from .jsonl import JSONLinesParser
from .ssh import SSHAuthParser

# Order matters for auto-detect ties: more specific formats first.
PARSERS: Dict[str, Type[Parser]] = {
    p.name: p for p in (
        RequestShieldParser, CombinedParser, NginxErrorParser,
        SSHAuthParser, IISParser, JSONLinesParser,
    )
}


def get_parser(name: str) -> Parser:
    try:
        return PARSERS[name]()
    except KeyError:
        raise ValueError(f"Unknown format '{name}'. Choose from: {', '.join(PARSERS)}, auto")


def detect_format(lines: Iterable[str], sample: int = 25) -> str:
    """Try every parser on the first non-empty lines, pick the best match."""
    picked: List[str] = []
    for line in lines:
        if line.strip():
            picked.append(line)
        if len(picked) >= sample:
            break
    if not picked:
        raise ValueError("Log file is empty")
    best, best_hits = None, 0
    for name, cls in PARSERS.items():
        parser = cls()
        hits = sum(1 for ln in picked if parser.matches(ln))
        if hits > best_hits:
            best, best_hits = name, hits
    if best is None:
        raise ValueError("Could not detect log format. Use --format to pick one.")
    return best


__all__ = ["Parser", "PARSERS", "get_parser", "detect_format"]
