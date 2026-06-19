"""vpn:// codec + obfuscation merge.

Python port of AmneziaWG-Architect's mergekeys.ts
(https://github.com/Vadim-Khristenko/AmneziaWG-Architect, MIT — Vadim Khristenko
& @VoidWaifu). The wire format must match byte-for-byte or Amnezia clients reject
the link:

    vpn://  +  base64url( <4-byte big-endian uncompressed-JSON-length> || zlib(JSON) )

with base64url '+'->'-', '/'->'_', and trailing '=' stripped. The 4-byte prefix
is the length of the *uncompressed* JSON (decoders use it as a sanity hint; the
payload itself is everything after byte 4, zlib-deflated). A legacy fallback
treats the whole blob as raw (uncompressed) JSON.
"""
from __future__ import annotations

import base64
import json
import re
import struct
import zlib
from typing import Any

VPN_PREFIX = "vpn://"

# Obfuscation fields patched into an Amnezia awg container.
_BASE_FIELDS = ("Jc", "Jmin", "Jmax")
_CPS_FIELDS = ("I1", "I2", "I3", "I4", "I5")


def _b64url_to_bytes(s: str) -> bytes:
    s = s.strip()
    if s.startswith(VPN_PREFIX):
        s = s[len(VPN_PREFIX):]
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s)


def vpn_decode(s: str) -> Any:
    """Decode a vpn:// link to the VpnConfig dict (raises ValueError on garbage)."""
    raw = _b64url_to_bytes(s)
    try:
        decompressed = zlib.decompress(raw[4:])
        return json.loads(decompressed.decode("utf-8"))
    except (zlib.error, UnicodeDecodeError, json.JSONDecodeError):
        # Legacy: some encoders emit raw uncompressed JSON with no length prefix.
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(f"not a valid vpn:// payload: {e}") from e


def vpn_encode(obj: Any) -> str:
    """Encode a VpnConfig dict back to a vpn:// link.

    JSON is serialized with 4-space indent and ensure_ascii=False to mirror JS
    `JSON.stringify(obj, null, 4)` (which does not escape non-ASCII).
    """
    js = json.dumps(obj, ensure_ascii=False, indent=4).encode("utf-8")
    combined = struct.pack(">I", len(js)) + zlib.compress(js)
    b64 = base64.b64encode(combined).decode("ascii")
    return VPN_PREFIX + b64.replace("+", "-").replace("/", "_").rstrip("=")


# --------------------------------------------------------------------------
# Patching obfuscation params into the Amnezia container(s)
# --------------------------------------------------------------------------
def _patch_wgquick(text: str, params: dict) -> str:
    """Replace/insert KEY = value lines in a wg-quick-format [Interface] block."""
    out = text
    for key, val in params.items():
        line_re = re.compile(rf"(?m)^[ \t]*{re.escape(key)}[ \t]*=.*$")
        if line_re.search(out):
            out = line_re.sub(f"{key} = {val}", out)
        else:
            # insert right after the [Interface] header
            out = re.sub(r"(?m)^(\[Interface\][ \t]*)$", rf"\1\n{key} = {val}", out, count=1)
    return out


def _patch_json_string(s: str, params: dict) -> str:
    try:
        obj = json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return s
    obj.update({k: str(v) for k, v in params.items()})
    return json.dumps(obj, ensure_ascii=False)


def _apply_to_awg(awg: dict, params: dict) -> None:
    """Patch obfuscation params into all three Amnezia locations of one container."""
    str_params = {k: str(v) for k, v in params.items()}
    # 1. top-level fields
    awg.update(str_params)
    # 2. last_config (a JSON string)
    if isinstance(awg.get("last_config"), str):
        awg["last_config"] = _patch_json_string(awg["last_config"], params)
    # 3. config (wg-quick text)
    if isinstance(awg.get("config"), str):
        awg["config"] = _patch_wgquick(awg["config"], params)


def merge_obfuscation(vpn_config: dict, params: dict) -> dict:
    """Patch Jc/Jmin/Jmax (+ I1-I5 when present) into every awg container.

    `params` keys are taken from {Jc,Jmin,Jmax,I1..I5}; others are ignored.
    Returns the same (mutated) dict for convenience.
    """
    allowed = set(_BASE_FIELDS) | set(_CPS_FIELDS)
    patch = {k: v for k, v in params.items() if k in allowed and v not in (None, "")}
    if not patch:
        return vpn_config
    for entry in vpn_config.get("containers", []) or []:
        awg = entry.get("awg") if isinstance(entry, dict) else None
        if isinstance(awg, dict):
            _apply_to_awg(awg, patch)
    return vpn_config


def merge_into_link(vpn_link: str, params: dict) -> str:
    """Convenience: decode a vpn:// link, patch obfuscation, re-encode."""
    return vpn_encode(merge_obfuscation(vpn_decode(vpn_link), params))
