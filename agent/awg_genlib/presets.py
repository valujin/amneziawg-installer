"""Named scenario presets — the layer Architect leaves to the operator.

Architect exposes raw knobs (version/intensity/profile/browser/mtu/router/
extreme/tags). A preset bundles them for a real situation. These are sensible
starters mapped onto the full generator; operators add/edit their own via the
panel. Resolve a preset with ``generate_preset(name)``.
"""
from __future__ import annotations

from .generator import generate

# name -> {label, description, params(generate kwargs)}.
PRESETS: dict[str, dict] = {
    "home": {
        "label": "Home desktop",
        "description": "Balanced QUIC mimicry for a desktop on a normal home line.",
        "params": {
            "version": "2.0", "intensity": "medium", "profile": "quic_initial",
            "browser_profile": "chrome", "use_browser_fp": True,
            "extreme": False, "router_mode": False, "cps": True, "mtu": 1280,
        },
    },
    "mobile": {
        "label": "Mobile / cellular",
        "description": "Lighter junk + Yandex-mobile QUIC fingerprint to save "
                       "battery and latency on LTE/5G.",
        "params": {
            "version": "2.0", "intensity": "low", "profile": "quic_initial",
            "browser_profile": "yandex_mobile", "use_browser_fp": True,
            "extreme": False, "router_mode": False, "cps": True, "mtu": 1280,
        },
    },
    "weak-router": {
        "label": "Low-power router",
        "description": "Minimal sizes, no heavy CPS — for OpenWrt/Keenetic/NanoPi.",
        "params": {
            "version": "2.0", "intensity": "low", "profile": "quic_initial",
            "extreme": False, "router_mode": True, "cps": False, "mtu": 1280,
        },
    },
    "stealth": {
        "label": "Aggressive DPI (stealth)",
        "description": "Max obfuscation — composite QUIC burst, extreme ranges, "
                       "full mimicry chain. Highest overhead.",
        "params": {
            "version": "2.0", "intensity": "high", "profile": "quic_burst",
            "browser_profile": "chrome", "use_browser_fp": True, "mimic_all": True,
            "extreme": True, "router_mode": False, "cps": True, "mtu": 1280,
        },
    },
    "tls-stealth": {
        "label": "TLS→QUIC stealth",
        "description": "Composite TLS ClientHello → QUIC profile; good where UDP "
                       "is throttled but TLS-on-443 looks native.",
        "params": {
            "version": "2.0", "intensity": "high", "profile": "tls_to_quic",
            "browser_profile": "firefox", "use_browser_fp": True,
            "extreme": False, "router_mode": False, "cps": True, "mtu": 1280,
        },
    },
    "voip": {
        "label": "VoIP / SIP mimicry",
        "description": "Mimics SIP REGISTER signaling — blends with operator "
                       "softphone traffic.",
        "params": {
            "version": "2.0", "intensity": "medium", "profile": "sip",
            "extreme": False, "router_mode": False, "cps": True, "mtu": 1280,
        },
    },
    "legacy-1x": {
        "label": "AmneziaWG 1.x",
        "description": "For AmneziaWG 1.x peers — Jc/S/H only, no I1-I5 CPS chain.",
        "params": {
            "version": "1.0", "intensity": "medium", "profile": "quic_initial",
            "extreme": False, "router_mode": False, "cps": False, "mtu": 1280,
        },
    },
}


def list_presets() -> list[str]:
    """Sorted preset names."""
    return sorted(PRESETS)


def describe_presets() -> list[dict]:
    """[{name,label,description}] for the panel preset picker."""
    return [
        {"name": n, "label": p["label"], "description": p["description"]}
        for n, p in sorted(PRESETS.items())
    ]


def generate_preset(name: str, seed=None) -> dict:
    """Generate a parameter set for a named preset."""
    if name not in PRESETS:
        raise KeyError(f"unknown preset '{name}' (have: {', '.join(list_presets())})")
    return generate(seed=seed, **PRESETS[name]["params"])
