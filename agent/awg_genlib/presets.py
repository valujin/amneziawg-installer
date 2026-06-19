"""Named scenario presets — the layer Architect leaves to the operator.

A preset bundles generator knobs for a situation. Operators add/edit their own;
these are sensible starters. Resolve with generate_preset(name).
"""
from __future__ import annotations

from .generator import generate

# name -> generator kwargs. Keep these conservative + valid.
PRESETS: dict[str, dict] = {
    # Balanced default for desktops on a normal home line.
    "home": {"version": "2.0", "intensity": "medium", "extreme": False,
             "router_mode": False, "cps": True, "mtu": 1280},
    # Mobile / cellular: lower MTU headroom, lighter junk to save battery/latency.
    "mobile": {"version": "2.0", "intensity": "low", "extreme": False,
               "router_mode": False, "cps": True, "mtu": 1280},
    # Low-power router (OpenWrt/Keenetic): minimal sizes, no heavy CPS.
    "weak-router": {"version": "2.0", "intensity": "low", "extreme": False,
                    "router_mode": True, "cps": False, "mtu": 1280},
    # Aggressive DPI environments: max obfuscation.
    "stealth": {"version": "2.0", "intensity": "high", "extreme": True,
                "router_mode": False, "cps": True, "mtu": 1280},
    # AmneziaWG 1.x peers (no I1-I5 CPS).
    "legacy-1x": {"version": "1.0", "intensity": "medium", "extreme": False,
                  "router_mode": False, "cps": False, "mtu": 1280},
}


def list_presets() -> list[str]:
    return sorted(PRESETS)


def generate_preset(name: str, seed=None) -> dict:
    """Generate a parameter set for a named preset."""
    if name not in PRESETS:
        raise KeyError(f"unknown preset '{name}' (have: {', '.join(list_presets())})")
    return generate(seed=seed, **PRESETS[name])
