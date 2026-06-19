"""AmneziaWG parameter validation.

Python port of AmneziaWG-Architect's awgValidate.ts (MIT). Returns findings
rather than raising — every check is optional and skipped when its field is
absent, so partial param sets validate cleanly. errors block a config; warnings
flag DPI-fingerprinting / fragmentation risks.
"""
from __future__ import annotations

import re
from typing import Optional

# CPS DSL grammar for I1-I5 (must match the generator's emitted tags exactly).
I_TAG_RE = re.compile(r"^(<(b 0x[0-9a-fA-F]*|t|c|r \d+|rc \d+|rd \d+|d|ds|dz)>)+$")

DEFAULT_MTU = 1280


def _to_int(v) -> Optional[int]:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _parse_range(v) -> Optional[tuple[int, int]]:
    """Parse an H-header value 'N' or 'N-M' into (start, end)."""
    s = str(v).strip()
    if "-" in s:
        a, _, b = s.partition("-")
        ai, bi = _to_int(a), _to_int(b)
        if ai is None or bi is None:
            return None
        return (ai, bi) if ai <= bi else (bi, ai)
    i = _to_int(s)
    return (i, i) if i is not None else None


def validate(params: dict, mtu: int = DEFAULT_MTU) -> dict:
    """Validate a dict of AWG params. Returns {ok, errors, warnings}."""
    errors: list[str] = []
    warnings: list[str] = []

    def has(k):
        return params.get(k) not in (None, "")

    # --- Jc ---
    if has("Jc"):
        jc = _to_int(params["Jc"])
        if jc is None or jc < 1 or jc > 128:
            errors.append("Jc must be an integer in 1..128")
        elif jc > 64:
            warnings.append("Jc > 64 increases handshake latency")

    # --- Jmin / Jmax ---
    jmin = _to_int(params.get("Jmin")) if has("Jmin") else None
    jmax = _to_int(params.get("Jmax")) if has("Jmax") else None
    if jmin is not None and jmax is not None and jmin >= jmax:
        errors.append("Jmin must be < Jmax")
    if jmax is not None and jmax >= mtu:
        warnings.append(f"Jmax ({jmax}) >= MTU ({mtu}) risks fragmentation")

    # --- S1 / S2 (sizes + the init==response fingerprint) ---
    s1 = _to_int(params.get("S1")) if has("S1") else None
    s2 = _to_int(params.get("S2")) if has("S2") else None
    if s1 is not None and (s1 < 0 or s1 > 1132):
        errors.append("S1 must be in 0..1132")
    if s2 is not None and (s2 < 0 or s2 > 1188):
        errors.append("S2 must be in 0..1188")
    if s1 is not None and s2 is not None and s1 + 56 == s2:
        warnings.append("S1+56 == S2 is a known DPI fingerprint; re-roll S2")

    # --- H1-H4 ranges: parseable + non-overlapping + not in WG reserved 1..4 ---
    h_ranges = []
    for key in ("H1", "H2", "H3", "H4"):
        if not has(key):
            continue
        rng = _parse_range(params[key])
        if rng is None:
            errors.append(f"{key} must be 'N' or 'N-M'")
            continue
        if rng[0] <= 4:
            warnings.append(f"{key} starts in the WireGuard reserved range (1..4)")
        h_ranges.append((key, rng))
    for i in range(len(h_ranges)):
        for j in range(i + 1, len(h_ranges)):
            (ka, (a0, a1)), (kb, (b0, b1)) = h_ranges[i], h_ranges[j]
            if a0 <= b1 and b0 <= a1:
                errors.append(f"{ka} and {kb} magic-header ranges overlap")

    # --- I1-I5 CPS tags ---
    for key in ("I1", "I2", "I3", "I4", "I5"):
        v = params.get(key)
        if v in (None, "", "0"):
            continue
        if not I_TAG_RE.match(str(v)):
            errors.append(f"{key} is not a valid CPS tag sequence")

    return {"ok": not errors, "errors": errors, "warnings": warnings}
