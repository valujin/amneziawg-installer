"""AmneziaWG obfuscation-parameter generator — full Python port of
AmneziaWG-Architect's generator.ts (MIT — Vadim Khristenko & @VoidWaifu's
"Special Junk Packet List").

This is a faithful, byte-compatible port of the upstream generator:

  * ``hostPools``    — the exact domain/IP pools per mimicry profile, lifted from
                       generator.ts into ``data/hostpools.json``.
  * ``BFP``          — browser-fingerprint UDP-payload size tables
                       (chrome/edge/firefox/safari/yandex_desktop/yandex_mobile).
  * primitives       — rnd, rh, hex_pad, assert_even_hex, r_range, split_pad,
                       tag_overhead, calc_padding, align_to_128.
  * protocol builders— mk_quic_i, mk_quic_0, mk_tls, mk_noise, mk_dtls,
                       mk_http3, mk_sip, mk_dns, mk_entropy.
  * gen_i1 / gen_cfg — the dispatcher and the full config assembler, including
                       composite profiles (tls_to_quic, quic_burst), DNS
                       mimicry, router mode, extreme mode, and iter-count boost.

``gen_cfg`` is valid-by-construction (it enforces every uniqueness/ordering
invariant inline), so it never needs to re-roll against validate().

These junk parameters are padding, not keys, so a plain PRNG is fine. A
module-level Random mirrors generator.ts's global ``Math.random``; pass ``seed``
to ``gen_cfg``/``generate`` for reproducible output in tests.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .validate import validate

# ─────────────────────────────────────────────────────────────────────────────
# Data: host pools (lifted verbatim from generator.ts) + browser fingerprints
# ─────────────────────────────────────────────────────────────────────────────
_DATA_DIR = Path(__file__).resolve().parent / "data"

with (_DATA_DIR / "hostpools.json").open(encoding="utf-8") as _f:
    HOST_POOLS: dict[str, list[str]] = json.load(_f)

# Richer tiered dataset (Architect's published api/v1/index.json) — host + tier +
# note per entry, for the panel's custom-host picker. Optional: generation uses
# the flat HOST_POOLS above; this only annotates them.
_TIERED_PATH = _DATA_DIR / "hostpools_tiered.json"
if _TIERED_PATH.exists():
    with _TIERED_PATH.open(encoding="utf-8") as _f:
        _TIERED: dict = json.load(_f)
else:  # pragma: no cover
    _TIERED = {"profiles": {}, "tiers": {}}

# Browser Fingerprint (BFP) tables — [min, max] UDP-payload bytes per slot.
# Slots: qi (QUIC Initial), q0 (QUIC 0-RTT), h3 (HTTP/3 DATA), tls (TLS CH),
#        nx (Noise_IK initiation), dtls (DTLS CH). Ported from generator.ts.
BFP: dict[str, dict[str, tuple[int, int]]] = {
    "chrome": {"qi": (1250, 1250), "q0": (1250, 1350), "h3": (1250, 1350),
               "tls": (512, 800), "nx": (1200, 1250), "dtls": (1100, 1200)},
    "edge": {"qi": (1250, 1250), "q0": (1250, 1350), "h3": (1250, 1350),
             "tls": (512, 800), "nx": (1200, 1250), "dtls": (1100, 1200)},
    "firefox": {"qi": (1200, 1252), "q0": (1200, 1300), "h3": (1200, 1350),
                "tls": (512, 700), "nx": (1200, 1250), "dtls": (1050, 1200)},
    "safari": {"qi": (1250, 1252), "q0": (1250, 1300), "h3": (1250, 1350),
               "tls": (512, 750), "nx": (1200, 1250), "dtls": (1100, 1200)},
    "yandex_desktop": {"qi": (1250, 1250), "q0": (1250, 1350), "h3": (1350, 1350),
                       "tls": (512, 800), "nx": (1200, 1250), "dtls": (1100, 1200)},
    "yandex_mobile": {"qi": (1232, 1232), "q0": (1250, 1350), "h3": (1350, 1350),
                      "tls": (512, 800), "nx": (1200, 1250), "dtls": (1100, 1200)},
}

YANDEX_UNSTABLE_PROFILES = ("yandex_desktop", "yandex_mobile")

# All mimicry profiles + their human labels (for the panel UI dropdown).
PROFILE_LABELS: dict[str, str] = {
    "quic_initial": "QUIC Initial",
    "quic_0rtt": "QUIC 0-RTT",
    "tls_client_hello": "TLS 1.3",
    "wireguard_noise": "Noise_IK",
    "dtls": "DTLS 1.3",
    "http3": "HTTP/3",
    "sip": "SIP",
    "tls_to_quic": "TLS → QUIC",
    "quic_burst": "QUIC Burst",
    "dns_query": "DNS Query",
    "random": "Random",
}
MIMIC_PROFILES = tuple(PROFILE_LABELS.keys())
BROWSER_PROFILES = tuple(BFP.keys())
INTENSITIES = ("low", "medium", "high")
VERSIONS = ("1.0", "1.5", "2.0")

_CHROMIUM_PROFILES = frozenset(
    ("chrome", "edge", "yandex_desktop", "yandex_mobile"))

# ─────────────────────────────────────────────────────────────────────────────
# RNG — module-level, mirrors generator.ts's global Math.random()
# ─────────────────────────────────────────────────────────────────────────────
_RNG = random.Random()


def _seed(seed: Optional[int]) -> None:
    if seed is not None:
        _RNG.seed(seed)


# ─────────────────────────────────────────────────────────────────────────────
# GeneratorInput — every knob generator.ts read from the DOM
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class GeneratorInput:
    version: str = "2.0"               # "1.0" | "1.5" | "2.0"
    intensity: str = "medium"         # low | medium | high
    profile: str = "quic_initial"     # one of MIMIC_PROFILES
    custom_host: str = ""
    mimic_all: bool = False

    use_tag_c: bool = True
    use_tag_t: bool = True
    use_tag_r: bool = True
    use_tag_rc: bool = True
    use_tag_rd: bool = False

    use_browser_fp: bool = False
    browser_profile: str = ""         # one of BROWSER_PROFILES or ""
    mtu: int = 1280
    junk_level: int = 5

    iter_count: int = 0
    router_mode: bool = False
    use_extreme_max: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Primitives (pure ports of the generator.ts utilities)
# ─────────────────────────────────────────────────────────────────────────────
def rnd(a: int, b: int) -> int:
    """Random integer in [a, b] inclusive (== Math.floor(rand*(b-a+1))+a)."""
    return _RNG.randint(a, b)


def rh(n: int) -> str:
    """n random bytes as lowercase hex (length exactly n*2, always even)."""
    n = max(0, int(n))
    return "".join("%02x" % _RNG.randrange(256) for _ in range(n))


def hex_pad(value: int, byte_len: int) -> str:
    """Integer → hex of exactly byte_len bytes (zero-padded, overflow truncated)."""
    h = format(int(value), "x")
    h = h.rjust(byte_len * 2, "0")
    return h[-(byte_len * 2):] if byte_len > 0 else ""


def assert_even_hex(hex_str: str, label: str = "?") -> str:
    """Safety net: pad an odd-length hex string with a trailing 0."""
    if len(hex_str) % 2 != 0:
        return hex_str + "0"
    return hex_str


def r_range(base: int, spread: int = 500_000) -> str:
    """Generate an H-header range string "start-end" (end-start in [1000,50000])."""
    s = base + rnd(0, spread)
    return f"{s}-{s + rnd(1000, 50_000)}"


def split_pad(n: int, tag: str = "r") -> str:
    """Split N padding bytes into <tag N> chunks, ≤1000 bytes per tag."""
    n = max(0, int(n))
    if n == 0:
        return ""
    out = ""
    while n > 1000:
        out += f"<{tag} 1000>"
        n -= 1000
    out += f"<{tag} {n}>"
    return out


def tag_overhead(use_c: bool, use_t: bool) -> int:
    """Fixed byte weight of the <c> (4B counter) and <t> (4B timestamp) tags."""
    return (4 if use_c else 0) + (4 if use_t else 0)


def calc_padding(
    header_b: int,
    extra_b: int,
    rng_range: Optional[tuple[int, int]],
    iv: int,
    mtu: int,
) -> int:
    """Compute padding size in bytes (see generator.ts calcPadding).

    With a BFP range: pad occupied up to min, jitter (≤20) toward max, ≤ MTU.
    Without: entropy size rnd(20,80)*iv capped at 500 and MTU headroom.
    """
    max_pad = max(0, mtu - header_b - extra_b)
    if rng_range is None:
        return min(rnd(20, 80) * iv, 500, max_pad)

    occupied = header_b + extra_b
    lo, hi = rng_range
    clamped_min = min(lo, mtu)
    clamped_max = min(hi, mtu)
    needed = max(0, clamped_min - occupied)
    jitter = max(0, min(clamped_max - clamped_min,
                        clamped_max - occupied - needed, 20))
    pad = needed + (rnd(0, jitter) if jitter > 0 else 0)
    return min(pad, max_pad)


def align_to_128(n: int) -> int:
    """Round up to the nearest multiple of 128 (Chrome TLS ClientHello padding)."""
    return ((n + 127) // 128) * 128


# ─────────────────────────────────────────────────────────────────────────────
# Data accessors
# ─────────────────────────────────────────────────────────────────────────────
def _get_host(inp: GeneratorInput, pool_key: str) -> str:
    if inp.custom_host.strip():
        return inp.custom_host.strip()
    actual = "dns" if pool_key == "dns_query" else pool_key
    pool = HOST_POOLS.get(actual) or HOST_POOLS["tls_client_hello"]
    return pool[rnd(0, len(pool) - 1)]


def _get_fp_range(inp: GeneratorInput, slot: str) -> Optional[tuple[int, int]]:
    if not inp.use_browser_fp or not inp.browser_profile:
        return None
    table = BFP.get(inp.browser_profile)
    if not table:
        return None
    return table.get(slot)


# ─────────────────────────────────────────────────────────────────────────────
# Protocol builders (I1 mimicry packets)
# ─────────────────────────────────────────────────────────────────────────────
def mk_quic_i(inp: GeneratorInput, iv: int) -> str:
    """QUIC Initial (RFC 9000, Long Header 0xC0–0xC3, UDP 443)."""
    host = _get_host(inp, "quic_initial")
    dcid = rnd(8, 20)
    scid = rnd(0, 20)
    token_len = 0 if rnd(0, 1) == 0 else rnd(8, 32)
    sni_rc = min(len(host) + rnd(0, 6), 64)

    hex_str = assert_even_hex(
        hex_pad(0xC0 | rnd(0, 3), 1)
        + "00000001"
        + hex_pad(dcid, 1) + rh(dcid)
        + hex_pad(scid, 1) + rh(scid)
        + hex_pad(token_len, 1) + rh(token_len)
        + rh(4),
        "mk_quic_i",
    )
    header_b = len(hex_str) // 2
    extra_b = (sni_rc if inp.use_tag_rc else 0) + tag_overhead(inp.use_tag_c, inp.use_tag_t)
    pad = calc_padding(header_b, extra_b, _get_fp_range(inp, "qi"), iv, inp.mtu)

    return (
        f"<b 0x{hex_str}>"
        + (f"<rc {sni_rc}>" if inp.use_tag_rc else "")
        + ("<c>" if inp.use_tag_c else "")
        + ("<t>" if inp.use_tag_t else "")
        + (split_pad(pad) if inp.use_tag_r else "")
    )


def mk_quic_0(inp: GeneratorInput, iv: int) -> str:
    """QUIC 0-RTT Early Data (Long Header 0xD0–0xD3)."""
    host = _get_host(inp, "quic_0rtt")
    dcid = rnd(8, 20)
    scid = rnd(0, 20)
    ticket_hint = min(len(host) + rnd(4, 16), 48)

    hex_str = assert_even_hex(
        hex_pad(0xD0 | rnd(0, 3), 1)
        + "00000001"
        + hex_pad(dcid, 1) + rh(dcid)
        + hex_pad(scid, 1) + rh(scid)
        + rh(4),
        "mk_quic_0",
    )
    header_b = len(hex_str) // 2
    extra_b = (ticket_hint if inp.use_tag_rc else 0) + tag_overhead(inp.use_tag_c, inp.use_tag_t)
    pad = calc_padding(header_b, extra_b, _get_fp_range(inp, "q0"), iv, inp.mtu)

    return (
        f"<b 0x{hex_str}>"
        + ("<t>" if inp.use_tag_t else "")
        + (split_pad(pad) if inp.use_tag_r else "")
        + (f"<rc {ticket_hint}>" if inp.use_tag_rc else "")
        + ("<c>" if inp.use_tag_c else "")
    )


def mk_tls(inp: GeneratorInput, iv: int) -> str:
    """TLS 1.3 Client Hello (TCP 443 or inside a QUIC Initial)."""
    host = _get_host(inp, "tls_client_hello")
    sni_ext = 2 + 2 + 2 + 1 + 2 + len(host)
    sni_rc = min(sni_ext, 64)

    fp_range = _get_fp_range(inp, "tls")
    base_len = rnd(fp_range[0], fp_range[1]) if fp_range else rnd(300, 550)
    rec_len = align_to_128(base_len) if inp.browser_profile in _CHROMIUM_PROFILES else base_len
    hs_len = rec_len - rnd(4, 9)

    r_len = min(
        rnd(20, 60) * iv,
        300,
        max(0, inp.mtu - 44 - sni_rc - tag_overhead(inp.use_tag_c, inp.use_tag_t)),
    )

    hex_str = assert_even_hex(
        "160301"
        + hex_pad(rec_len, 2)
        + "01"
        + hex_pad(hs_len, 3)
        + "0303"
        + rh(32),
        "mk_tls",
    )

    return (
        f"<b 0x{hex_str}>"
        + (f"<rc {sni_rc}>" if inp.use_tag_rc else "")
        + (split_pad(r_len) if inp.use_tag_r else "")
        + ("<c>" if inp.use_tag_c else "")
        + ("<t>" if inp.use_tag_t else "")
    )


def mk_noise(inp: GeneratorInput, iv: int) -> str:
    """WireGuard Noise_IK Handshake Initiation (strict 148 B, optionally padded)."""
    rc_len = rnd(4, 12)
    header_b = 148

    extra_b = (rc_len if inp.use_tag_rc else 0) + tag_overhead(inp.use_tag_c, inp.use_tag_t)
    rng_range = _get_fp_range(inp, "nx")
    if rng_range:
        pad = calc_padding(header_b, extra_b, rng_range, iv, inp.mtu)
    else:
        pad = min(rnd(10, 40) * iv, 200, max(0, inp.mtu - header_b - extra_b))

    return (
        f"<b 0x01000000{rh(4)}>"
        + f"<b 0x{rh(32)}>"
        + f"<b 0x{rh(48)}>"
        + f"<b 0x{rh(28)}>"
        + f"<b 0x{rh(32)}>"
        + (split_pad(pad) if inp.use_tag_r else "")
        + ("<t>" if inp.use_tag_t else "")
        + (f"<rc {rc_len}>" if inp.use_tag_rc else "")
    )


def mk_dtls(inp: GeneratorInput, iv: int) -> str:
    """DTLS 1.2 Client Hello (WebRTC)."""
    host = _get_host(inp, "dtls")
    frag_len = rnd(100, 300)
    sni_rc = min(len(host) + rnd(2, 8), 60)
    epoch = rnd(0, 255)

    hex_str = assert_even_hex(
        "16"
        + "fefd"
        + hex_pad(epoch, 2)
        + rh(6)
        + hex_pad(frag_len, 2)
        + "01"
        + rh(6)
        + "fefd0000"
        + rh(4)
        + rh(32),
        "mk_dtls",
    )
    header_b = len(hex_str) // 2
    extra_b = (sni_rc if inp.use_tag_rc else 0) + tag_overhead(inp.use_tag_c, inp.use_tag_t)
    pad = calc_padding(header_b, extra_b, _get_fp_range(inp, "dtls"), iv, inp.mtu)

    return (
        f"<b 0x{hex_str}>"
        + (f"<rc {sni_rc}>" if inp.use_tag_rc else "")
        + ("<c>" if inp.use_tag_c else "")
        + ("<t>" if inp.use_tag_t else "")
        + (split_pad(pad) if inp.use_tag_r else "")
    )


def mk_http3(inp: GeneratorInput, iv: int) -> str:
    """HTTP/3 host mimicry (QUIC Long Header, extended type bytes, DATA→MTU)."""
    host = _get_host(inp, "quic_initial")
    ptypes = (0xC0, 0xC1, 0xC2, 0xC3, 0xE0, 0xE1, 0xE2)
    dcid = rnd(8, 20)
    scid = rnd(0, 20)
    sni_len = min(len(host) + 9 + rnd(0, 6), 64)

    hex_str = assert_even_hex(
        hex_pad(ptypes[rnd(0, len(ptypes) - 1)], 1)
        + "00000001"
        + hex_pad(dcid, 1) + rh(dcid)
        + hex_pad(scid, 1) + rh(scid)
        + rh(4),
        "mk_http3",
    )
    header_b = len(hex_str) // 2
    extra_b = (sni_len if inp.use_tag_rc else 0) + tag_overhead(inp.use_tag_c, inp.use_tag_t)
    pad = calc_padding(header_b, extra_b, _get_fp_range(inp, "h3"), iv, inp.mtu)

    return (
        f"<b 0x{hex_str}>"
        + (f"<rc {sni_len}>" if inp.use_tag_rc else "")
        + (split_pad(pad) if inp.use_tag_r else "")
        + ("<c>" if inp.use_tag_c else "")
        + ("<t>" if inp.use_tag_t else "")
    )


def mk_sip(inp: GeneratorInput, iv: int) -> str:
    """SIP REGISTER request (VoIP signaling). BFP not applicable."""
    host = _get_host(inp, "sip")
    host_hex = "".join("%02x" % ord(c) for c in host)

    hex_str = assert_even_hex(
        "524547495354455220736970"  # "REGISTER sip"
        + "3a"                       # ":"
        + host_hex
        + "20"                       # " "
        + rh(4),
        "mk_sip",
    )
    header_b = len(hex_str) // 2
    rc_val = min(len(host) + rnd(8, 24) * iv, 150)
    r_len = min(
        rnd(5, 30) * iv,
        120,
        max(0, inp.mtu - header_b - rc_val - tag_overhead(inp.use_tag_c, inp.use_tag_t)),
    )

    return (
        f"<b 0x{hex_str}>"
        + (f"<rc {rc_val}>" if inp.use_tag_rc else "")
        + ("<c>" if inp.use_tag_c else "")
        + ("<t>" if inp.use_tag_t else "")
        + (split_pad(r_len) if inp.use_tag_r else "")
    )


def mk_dns(inp: GeneratorInput, iv: int) -> str:
    """DNS query mimicry (UDP 53) — label-encoded host + A/AAAA query."""
    host = _get_host(inp, "dns_query")
    query_name_hex = ""
    for label in host.split("."):
        query_name_hex += format(len(label), "02x")
        query_name_hex += "".join("%02x" % ord(c) for c in label)
    query_name_hex += "00"  # null terminator

    txid = rh(2)
    flags = "0100"
    qdcount, ancount, nscount, arcount = "0001", "0000", "0000", "0000"
    qtype = "0001" if iv % 2 == 0 else "001c"  # A or AAAA
    qclass = "0001"

    hex_str = assert_even_hex(
        txid + flags + qdcount + ancount + nscount + arcount
        + query_name_hex + qtype + qclass,
        "mk_dns",
    )
    header_b = len(hex_str) // 2
    target_size = rnd(64, min(512, inp.mtu - 20))
    r_len = max(0, target_size - header_b)

    return (
        f"<b 0x{hex_str}>"
        + (split_pad(min(r_len, 200)) if (inp.use_tag_r and r_len > 0) else "")
        + ("<t>" if inp.use_tag_t else "")
        + ("<c>" if inp.use_tag_c else "")
    )


def mk_entropy(inp: GeneratorInput, idx: int, iv: int) -> str:
    """Entropy packets I2–I5 — varied tag mixes to defeat statistical DPI."""
    is_big = rnd(1, 10) > 6  # ~40% big (DATA-like), ~60% small (ACK-like)
    base_len = rnd(200, 500) if is_big else rnd(4, 20)
    r_len = min(
        base_len * iv,
        500 if is_big else 60,
        max(0, inp.mtu - 20 - tag_overhead(inp.use_tag_c, inp.use_tag_t)),
    )
    rc_len = rnd(4, 12)
    rd_len = rnd(4, 8)

    c = "<c>" if inp.use_tag_c else ""
    t = "<t>" if inp.use_tag_t else ""
    r = split_pad(r_len) if inp.use_tag_r else ""
    rc = f"<rc {rc_len}>" if inp.use_tag_rc else ""
    rd = f"<rd {rd_len}>" if inp.use_tag_rd else ""
    b = f"<b 0x{rh(rnd(4, 8 * iv))}>" if iv >= 2 else ""
    b2 = f"<b 0x{rh(rnd(2, 4))}>" if iv >= 3 else ""

    patterns = (
        b + r + t + rc + c + rd,
        c + t + b + r + rc + rd,
        rc + b + r + c + t + rd,
        t + r + c + rc + b + rd,
        r + rc + b + t + c + rd,
        b2 + t + r + b + rc + c + rd,
        rd + b + rc + r + t + c + b2,
        c + b + b2 + t + rc + r + rd,
    )
    result = patterns[(idx + rnd(0, len(patterns) - 1)) % len(patterns)]
    return result or "<r 10>"


# ─────────────────────────────────────────────────────────────────────────────
# I1 dispatcher + full config assembler
# ─────────────────────────────────────────────────────────────────────────────
_DISPATCH = {
    "quic_initial": mk_quic_i,
    "quic_0rtt": mk_quic_0,
    "tls_client_hello": mk_tls,
    "wireguard_noise": mk_noise,
    "dtls": mk_dtls,
    "http3": mk_http3,
    "sip": mk_sip,
    "dns_query": mk_dns,
    "tls_to_quic": mk_tls,    # I1 = TLS, I2 = QUIC (set in gen_cfg)
    "quic_burst": mk_quic_i,  # I1 = QUIC Initial, I2-I3 set in gen_cfg
}


def gen_i1(inp: GeneratorInput, profile: str, iv: int) -> str:
    """Pick and call the I1 builder for ``profile`` ("random" → random choice)."""
    if profile == "random":
        keys = list(_DISPATCH.keys())
        return gen_i1(inp, keys[rnd(0, len(keys) - 1)], iv)
    fn = _DISPATCH.get(profile, mk_quic_i)
    return fn(inp, iv)


def gen_cfg(inp: GeneratorInput) -> dict:
    """Assemble a full AWG config dict (lowercase keys, like Architect's AWGConfig).

    Returns h1-h4 (ranges), h1s-h4s (singles for 1.x), s1-s4, jc/jmin/jmax,
    i1-i5 plus the echoed version/profile. Valid by construction.
    """
    version = inp.version
    intensity = inp.intensity
    profile = inp.profile

    imap = {"low": 1, "medium": 2, "high": 3}
    iv = imap[intensity] + (1 if inp.iter_count > 3 else 0)

    # ── H1–H4 ranges (AWG 2.0) ──────────────────────────────────────────────
    h1_spread = 10_000_000 if inp.use_extreme_max else 100_000_000
    h2_spread = 10_000_000 if inp.use_extreme_max else 100_000_000
    h3_spread = 10_000_000 if inp.use_extreme_max else 100_000_000
    h4_spread = 15_000_000 if inp.use_extreme_max else 150_000_000

    h1 = r_range(rnd(100_000_000, 900_000_000), h1_spread)
    h2 = r_range(rnd(1_200_000_000, 2_000_000_000), h2_spread)
    h3 = r_range(rnd(2_400_000_000, 3_200_000_000), h3_spread)
    h4 = r_range(rnd(3_600_000_000, 4_000_000_000), h4_spread)

    # ── H1s–H4s single values (AWG 1.x) ─────────────────────────────────────
    h1s_spread = 10_000_000 if inp.use_extreme_max else 4_000_000
    h1s = 100_000_000 + rnd(0, h1s_spread)
    h2s = 1_200_000_000 + rnd(0, h2_spread)
    h3s = 2_400_000_000 + rnd(0, h3_spread)
    h4s = 3_600_000_000 + rnd(0, h4_spread)

    # ── S1–S4 with the official client's uniqueness rules ───────────────────
    s1 = rnd(1, 150)
    s2 = rnd(1, 150)
    while s2 == s1 + 56:  # size(init) ≠ size(response)
        s2 = rnd(1, 150)

    s3 = rnd(1, 64)
    s3_attempts = 0
    while (s3 == s1 + 56 or s3 == s2 + 92) and s3_attempts < 10:
        s3 = rnd(1, 64)
        s3_attempts += 1

    s4 = rnd(1, 32)

    if inp.use_extreme_max:
        s3 = rnd(65, 256)
        s4 = rnd(33, 128)
        s3_attempts = 0
        while (s3 == s1 + 56 or s3 == s2 + 92) and s3_attempts < 10:
            s3 = rnd(65, 256)
            s3_attempts += 1

    # ── Junk train ──────────────────────────────────────────────────────────
    min_jc = 4 if version == "1.0" else 3
    max_jc = 128 if inp.use_extreme_max else 15

    jcv = inp.junk_level
    if version == "1.0":
        jcv = max(4, jcv)
    elif jcv > 0:
        jcv = max(1, min(max_jc, jcv + rnd(-1, 1)))
    if inp.use_extreme_max and inp.junk_level == 0 and version != "1.0":
        jcv = rnd(1, 8)

    jmin_ranges = {"low": (64, 256), "medium": (128, 512), "high": (256, 768)}
    jmax_ranges = {"low": (256, 512), "medium": (512, 1024), "high": (768, 1280)}
    jmin = rnd(*jmin_ranges[intensity])
    jmax = rnd(*jmax_ranges[intensity])
    min_jmax = jmin + 64
    if jmax <= min_jmax:
        jmax = min_jmax + rnd(64, 256)
    if version == "1.0" and jmax <= 81:
        jmax = 82 + rnd(50, 200)

    # ── Router low-power mode (only lowers values) ──────────────────────────
    if inp.router_mode:
        s1 = min(s1, 20)
        s2 = min(s2, 20)
        if s2 == s1 + 56:
            s2 = min(s2 + 1, 20)
        jcv = max(min_jc, min(jcv, 2))
        jmin = min(jmin, 40)
        jmax = min(jmax, 128)

    # ── CPS signature chain I1–I5 ───────────────────────────────────────────
    has_cps = version != "1.0"
    is_composite = profile in ("tls_to_quic", "quic_burst")
    is_dns = profile == "dns_query"

    i1 = i2 = i3 = i4 = i5 = ""
    if not has_cps:
        pass
    elif is_composite and profile == "tls_to_quic":
        i1 = mk_tls(inp, iv)
        i2 = mk_quic_i(inp, iv)
        i3 = mk_entropy(inp, 2, iv)
        i4 = mk_entropy(inp, 3, iv)
        i5 = mk_entropy(inp, 4, iv)
    elif is_composite and profile == "quic_burst":
        i1 = mk_quic_i(inp, iv)
        i2 = mk_quic_0(inp, iv)
        i3 = mk_http3(inp, iv)
        i4 = mk_entropy(inp, 3, iv)
        i5 = mk_entropy(inp, 4, iv)
    elif is_dns:
        i1 = mk_dns(inp, iv)
        i2 = mk_dns(inp, iv + 1) if inp.mimic_all else mk_entropy(inp, 1, iv)
        i3 = mk_dns(inp, iv + 2) if inp.mimic_all else mk_entropy(inp, 2, iv)
        i4 = mk_dns(inp, iv + 3) if inp.mimic_all else mk_entropy(inp, 3, iv)
        i5 = mk_dns(inp, iv + 4) if inp.mimic_all else mk_entropy(inp, 4, iv)
    else:
        i1 = gen_i1(inp, profile, iv)
        i2 = gen_i1(inp, profile, iv) if inp.mimic_all else mk_entropy(inp, 1, iv)
        i3 = gen_i1(inp, profile, iv) if inp.mimic_all else mk_entropy(inp, 2, iv)
        i4 = gen_i1(inp, profile, iv) if inp.mimic_all else mk_entropy(inp, 3, iv)
        i5 = gen_i1(inp, profile, iv) if inp.mimic_all else mk_entropy(inp, 4, iv)

    if inp.router_mode and has_cps:
        i2 = i3 = i4 = i5 = ""

    return {
        "version": version, "profile": profile,
        "h1": h1, "h2": h2, "h3": h3, "h4": h4,
        "h1s": h1s, "h2s": h2s, "h3s": h3s, "h4s": h4s,
        "s1": s1, "s2": s2, "s3": s3, "s4": s4,
        "jc": jcv, "jmin": jmin, "jmax": jmax,
        "i1": i1, "i2": i2, "i3": i3, "i4": i4, "i5": i5,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Friendly entry point — uppercase AWG param dict consumed by the agent/panel
# ─────────────────────────────────────────────────────────────────────────────
def cfg_to_params(cfg: dict, version: str, cps: bool = True) -> dict:
    """Map a gen_cfg() result to the canonical {Jc,Jmin,Jmax,S1-4,H1-4,I1-5} dict.

    AWG 2.0/1.5 → H1-H4 ranges + I1-I5 (when cps). AWG 1.0 → H1-H4 singles, no I.
    """
    params: dict = {
        "Jc": cfg["jc"], "Jmin": cfg["jmin"], "Jmax": cfg["jmax"],
        "S1": cfg["s1"], "S2": cfg["s2"], "S3": cfg["s3"], "S4": cfg["s4"],
    }
    if version == "1.0":
        params["H1"], params["H2"] = str(cfg["h1s"]), str(cfg["h2s"])
        params["H3"], params["H4"] = str(cfg["h3s"]), str(cfg["h4s"])
    else:
        params["H1"], params["H2"] = cfg["h1"], cfg["h2"]
        params["H3"], params["H4"] = cfg["h3"], cfg["h4"]
        if cps:
            for n in range(1, 6):
                v = cfg[f"i{n}"]
                if v:
                    params[f"I{n}"] = v
    return params


def generate(
    version: str = "2.0",
    intensity: str = "medium",
    extreme: bool = False,
    router_mode: bool = False,
    cps: bool = True,
    mtu: int = 1280,
    profile: str = "quic_initial",
    browser_profile: str = "",
    use_browser_fp: bool = False,
    mimic_all: bool = False,
    custom_host: str = "",
    junk_level: int = 5,
    iter_count: int = 0,
    use_tag_c: bool = True,
    use_tag_t: bool = True,
    use_tag_r: bool = True,
    use_tag_rc: bool = True,
    use_tag_rd: bool = False,
    seed: Optional[int] = None,
    max_tries: int = 50,
) -> dict:
    """Generate a valid AWG obfuscation parameter set (uppercase keys).

    Thin wrapper over the faithful ``gen_cfg`` port. ``cps=False`` drops I1-I5
    even on AWG 2.0 (used by router/legacy presets). Output is validated and,
    defensively, re-rolled if a roll somehow fails (gen_cfg is valid-by-design).
    """
    if intensity not in INTENSITIES:
        raise ValueError("intensity must be low|medium|high")
    if profile not in MIMIC_PROFILES:
        raise ValueError(f"profile must be one of {MIMIC_PROFILES}")
    if browser_profile and browser_profile not in BFP:
        raise ValueError(f"browser_profile must be one of {BROWSER_PROFILES} or ''")

    _seed(seed)
    inp = GeneratorInput(
        version=version, intensity=intensity, profile=profile,
        custom_host=custom_host, mimic_all=mimic_all,
        use_tag_c=use_tag_c, use_tag_t=use_tag_t, use_tag_r=use_tag_r,
        use_tag_rc=use_tag_rc, use_tag_rd=use_tag_rd,
        use_browser_fp=use_browser_fp, browser_profile=browser_profile,
        mtu=mtu, junk_level=junk_level, iter_count=iter_count,
        router_mode=router_mode, use_extreme_max=extreme,
    )

    last_errors: list[str] = []
    for _ in range(max(1, max_tries)):
        cfg = gen_cfg(inp)
        params = cfg_to_params(cfg, version, cps=cps)
        result = validate(params, mtu=mtu)
        if result["ok"]:
            return params
        last_errors = result["errors"]
    raise RuntimeError(f"could not generate a valid parameter set: {last_errors}")


# ─────────────────────────────────────────────────────────────────────────────
# Introspection helpers (power the panel generator UI)
# ─────────────────────────────────────────────────────────────────────────────
def list_profiles() -> list[dict]:
    """[{key,label}] for every mimicry profile (UI dropdown)."""
    return [{"key": k, "label": v} for k, v in PROFILE_LABELS.items()]


def list_browsers() -> list[str]:
    """Browser-fingerprint profile names."""
    return list(BROWSER_PROFILES)


def host_pool(profile: str) -> list[str]:
    """The host/IP pool for a profile ("dns_query" → the DNS-IP pool)."""
    key = "dns" if profile == "dns_query" else profile
    return list(HOST_POOLS.get(key, []))


def host_pool_summary() -> dict[str, int]:
    """{pool: host count} across all pools."""
    return {k: len(v) for k, v in HOST_POOLS.items()}


def host_pool_tiered(profile: str) -> list[dict]:
    """[{host,tier,note}] for a profile, using Architect's tiered dataset.

    Falls back to the flat pool with tier "unknown" for profiles the tiered
    dataset doesn't cover (http3 reuses quic_initial; dns/random have no tiers).
    """
    key = "quic_initial" if profile == "http3" else (
        "dns" if profile == "dns_query" else profile)
    prof = _TIERED.get("profiles", {}).get(key)
    if prof and prof.get("hosts"):
        return [
            {"host": h["host"], "tier": h.get("tier", "unknown"),
             "note": h.get("note", "")}
            for h in prof["hosts"]
        ]
    return [{"host": h, "tier": "unknown", "note": ""} for h in host_pool(profile)]


def tier_definitions() -> dict:
    """The tier taxonomy (ru-domestic / cdn-infra / public-stun / …) for the UI."""
    return dict(_TIERED.get("tiers", {}))
