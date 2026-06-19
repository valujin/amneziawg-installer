"""AmneziaWG obfuscation-parameter generator.

Python port of the generation logic in AmneziaWG-Architect's generator.ts (MIT).
Produces a Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5 parameter set that satisfies
validate.validate(). Uniqueness/ordering constraints are enforced by re-rolling.

No cryptographic strength is needed for these junk parameters (they are padding,
not keys), so a plain PRNG is fine; pass `seed` for reproducible output in tests.
"""
from __future__ import annotations

import random
from typing import Optional

from .validate import validate

# Jmin/Jmax ranges per intensity (from Architect).
_JMIN = {"low": (64, 256), "medium": (128, 512), "high": (256, 768)}
_JMAX = {"low": (256, 512), "medium": (512, 1024), "high": (768, 1280)}
# Non-overlapping H magic-header base bands.
_H_BASES = (100_000_000, 1_200_000_000, 2_400_000_000, 3_600_000_000)
_INTENSITY_IV = {"low": 1, "medium": 2, "high": 3}


def _mk_rng(seed: Optional[int]) -> random.Random:
    return random.Random(seed)


def _even_hex(rng: random.Random, nbytes: int) -> str:
    """nbytes of random data as a lowercase hex string (always even length)."""
    return "".join(f"{rng.randrange(256):02x}" for _ in range(max(1, nbytes)))


def _split_pad(tag: str, n: int) -> str:
    """Emit one or more <tag N> tags, capping each at 1000 bytes."""
    out = []
    while n > 1000:
        out.append(f"<{tag} 1000>")
        n -= 1000
    out.append(f"<{tag} {max(0, n)}>")
    return "".join(out)


def _gen_i_tag(rng: random.Random, iv: int, mtu: int) -> str:
    """One CPS-mimicry I-value: a small binary magic header + random padding.

    Kept deliberately simple vs Architect's full per-protocol profiles, but emits
    only valid tags (passes I_TAG_RE), even-length hex, and <=1000 bytes per pad.
    """
    header = _even_hex(rng, rng.randint(1, 4))           # 1-4 byte fake magic
    pad = min(rng.randint(20, 80) * iv, 500, max(0, mtu - 80))
    return f"<b 0x{header}>" + _split_pad("r", pad)


def generate(
    version: str = "2.0",
    intensity: str = "medium",
    extreme: bool = False,
    router_mode: bool = False,
    cps: bool = True,
    mtu: int = 1280,
    seed: Optional[int] = None,
    max_tries: int = 200,
) -> dict:
    """Generate a valid AWG obfuscation parameter set.

    version: "1.0" enforces Jc>=4; otherwise Jc>=3.
    intensity: low|medium|high. extreme: widen S3/S4 + Jc upper bound.
    router_mode: cap S1/S2 small for low-power routers. cps: emit I1-I5.
    """
    if intensity not in _JMIN:
        raise ValueError("intensity must be low|medium|high")
    rng = _mk_rng(seed)

    for _ in range(max_tries):
        params: dict = {}

        # Jc
        min_jc = 4 if version == "1.0" else 3
        max_jc = 128 if extreme else 15
        params["Jc"] = rng.randint(min_jc, max_jc)

        # Jmin / Jmax (Jmax > Jmin + 64)
        jmin = rng.randint(*_JMIN[intensity])
        jmax_lo, jmax_hi = _JMAX[intensity]
        jmax = rng.randint(max(jmax_lo, jmin + 65), jmax_hi)
        params["Jmin"], params["Jmax"] = jmin, jmax

        # S1-S4
        s1_hi = 20 if router_mode else 150
        s2_hi = 20 if router_mode else 150
        params["S1"] = rng.randint(1, s1_hi)
        params["S2"] = rng.randint(1, s2_hi)
        params["S3"] = rng.randint(65, 256) if extreme else rng.randint(1, 64)
        params["S4"] = rng.randint(33, 128) if extreme else rng.randint(1, 32)
        # uniqueness: avoid the known fingerprints
        if params["S1"] + 56 == params["S2"]:
            continue
        if params["S1"] + 56 == params["S3"] or params["S2"] + 92 == params["S3"]:
            continue

        # H1-H4 non-overlapping ranges
        spread = 10_000_000 if extreme else 100_000_000
        for idx, base in enumerate(_H_BASES, start=1):
            start = base + rng.randint(0, spread)
            params[f"H{idx}"] = f"{start}-{start + rng.randint(1_000_000, spread)}"

        # I1-I5 CPS mimicry
        if cps and version != "1.0":
            iv = _INTENSITY_IV[intensity] + (1 if extreme else 0)
            for idx in range(1, 6):
                params[f"I{idx}"] = _gen_i_tag(rng, iv, mtu)

        result = validate(params, mtu=mtu)
        if result["ok"]:
            return params

    raise RuntimeError("could not generate a valid parameter set within max_tries")
