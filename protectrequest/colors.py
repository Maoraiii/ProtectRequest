"""Tiny colour helper. Uses colorama on Windows if present; plain text if not a TTY."""

from __future__ import annotations

import os
import sys


class C:
    RESET = BOLD = DIM = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = ""


def init(force_off: bool = False) -> None:
    if force_off or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return
    try:
        import colorama
        colorama.just_fix_windows_console()
    except Exception:
        pass
    C.RESET, C.BOLD, C.DIM = "\033[0m", "\033[1m", "\033[2m"
    C.RED, C.GREEN, C.YELLOW = "\033[91m", "\033[92m", "\033[93m"
    C.BLUE, C.MAGENTA, C.CYAN = "\033[94m", "\033[95m", "\033[96m"
