"""awg_genlib — AmneziaWG obfuscation config generation, validation, and vpn://
codec. Python port of AmneziaWG-Architect (MIT, Vadim Khristenko & @VoidWaifu),
plus a named-preset layer. Shared by the awg-agent (minting configs / /generate)
and the panel (config-generator UI).
"""
from .generator import generate
from .validate import validate
from .mergekeys import vpn_decode, vpn_encode, merge_obfuscation, merge_into_link
from .presets import generate_preset, list_presets, PRESETS

__all__ = [
    "generate", "validate",
    "vpn_decode", "vpn_encode", "merge_obfuscation", "merge_into_link",
    "generate_preset", "list_presets", "PRESETS",
]
