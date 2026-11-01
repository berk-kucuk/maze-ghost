"""What the welcome window reports: is Tor carrying traffic, is there swap on
disk. Plain functions, no Qt, so they can be tested on their own.
"""
from __future__ import annotations

import json
import urllib.request

CHECK_URL = "https://check.torproject.org/api/ip"


def tor_check(timeout: float = 20.0, opener=urllib.request.urlopen) -> tuple[bool, str]:
    """(through Tor, address the world sees). In a Ghost session the request
    goes through the Ghost Tor like everything else — the firewall leaves it
    no other way — so a True answer is a check of the session itself."""
    try:
        req = urllib.request.Request(CHECK_URL, headers={"User-Agent": "maze-ghost"})
        with opener(req, timeout=timeout) as resp:
            data = json.loads(resp.read(4096).decode())
        return bool(data.get("IsTor")), str(data.get("IP", ""))
    except Exception:  # noqa: BLE001 — not connected (yet) is an answer, not an error
        return False, ""


def disk_swap(proc_swaps: str | None = None) -> list[str]:
    """Swap areas that are on disk. zram lives in memory and is fine."""
    if proc_swaps is None:
        try:
            with open("/proc/swaps") as f:
                proc_swaps = f.read()
        except OSError:
            return []
    out = []
    for line in proc_swaps.splitlines()[1:]:
        parts = line.split()
        if parts and not parts[0].startswith("/dev/zram"):
            out.append(parts[0])
    return out
