"""awg_genlib — AmneziaWG obfuscation config generation, validation, and vpn://
codec. Full Python port of AmneziaWG-Architect (MIT, Vadim Khristenko &
@VoidWaifu's "Special Junk Packet List"), plus a named-preset layer. Shared by
the awg-agent (minting configs / /generate) and the panel (config-generator UI).
"""
from .generator import (
    generate, gen_cfg, cfg_to_params, GeneratorInput,
    list_profiles, list_browsers, host_pool, host_pool_summary,
    host_pool_tiered, tier_definitions,
    PROFILE_LABELS, MIMIC_PROFILES, BROWSER_PROFILES, INTENSITIES, VERSIONS,
)
from .validate import validate
from .mergekeys import (
    vpn_decode, vpn_encode, merge_obfuscation, merge_into_link,
    merge_vpn_configs, merge_links, build_obfuscation_patch, get_client_fields,
)
from .presets import generate_preset, list_presets, describe_presets, PRESETS

__all__ = [
    # generation
    "generate", "gen_cfg", "cfg_to_params", "GeneratorInput",
    "list_profiles", "list_browsers", "host_pool", "host_pool_summary",
    "host_pool_tiered", "tier_definitions",
    "PROFILE_LABELS", "MIMIC_PROFILES", "BROWSER_PROFILES", "INTENSITIES", "VERSIONS",
    # validation
    "validate",
    # vpn:// codec + merge
    "vpn_decode", "vpn_encode", "merge_obfuscation", "merge_into_link",
    "merge_vpn_configs", "merge_links", "build_obfuscation_patch", "get_client_fields",
    # presets
    "generate_preset", "list_presets", "describe_presets", "PRESETS",
]
