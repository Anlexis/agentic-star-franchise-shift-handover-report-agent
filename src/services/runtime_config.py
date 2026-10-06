"""AgentCore Platform v1.0"""

# RET-C2-256 — runtime configuration loader.
#
# config/agent.yaml is the static manifest: identity, entry point, trust level and
# the compile-time `requires` gates. It holds NO runtime values. Everything
# tunable at runtime lives in config/config.yaml and is read from here.
#
# One loader, so there is exactly one answer to "where does this value come
# from". A reader pointed at the manifest instead would not fail: it would find no
# such key, fall back to its own default, and every declared value in
# config/config.yaml would be dead while the tests stayed green. The flat manifest
# has no `agent.config` block at all, so that failure mode is one migration away
# from any repo that keeps a second reader.
#
# Every numeric read goes through the same finite + bounded parser the caller
# contract uses, for the same reason: `float()` accepts "NaN", and a NaN
# `max_retry` compares False against every retry count.

from pathlib import Path
from typing import Any, Dict

from src.services.input_guard import finite_in_range

# src/services/runtime_config.py -> parents[2] is the repository root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_PATH = _REPO_ROOT / "config" / "config.yaml"

# Bounds for the declared values. Out of range is a deployment mistake rather than
# a runtime condition, so the loader substitutes the documented default instead of
# letting an unusable number reach the backbone.
_MAX_RETRY_MIN, _MAX_RETRY_MAX = 0, 9
_TIMEOUT_MIN, _TIMEOUT_MAX = 1, 600

# Last-resort values, used only when config/config.yaml cannot be read at all (an
# exotic deployment layout). They mirror the shipped file, so an unreadable config
# degrades to the documented behaviour rather than to an empty mapping.
FALLBACK_AGENT: Dict[str, Any] = {
    "max_retry": 3,
    "timeout_s": 30,
}


def load_runtime_config() -> Dict[str, Any]:
    """Read config/config.yaml. Returns {} only if it is genuinely unreadable."""
    try:
        import yaml

        loaded = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - an unreadable config must degrade, not crash
        return {}
    return loaded if isinstance(loaded, dict) else {}


def agent_config() -> Dict[str, Any]:
    """The graph-level runtime block, bounds-checked.

    This is what the entry point passes as ``Graph(config=...)``. `max_retry` is
    read by the framework backbone's own routing decision
    (`AgentBaseGraph.route`), so a value declared here genuinely changes where a
    RETRY status sends the graph; `timeout_s` is the declared per-call budget
    carried on the graph config for the hosting runtime. Constructing the graph
    with no config at all would leave both unread and the framework silently
    substituting its built-in defaults.
    """
    declared = load_runtime_config()
    merged: Dict[str, Any] = dict(FALLBACK_AGENT)

    max_retry = finite_in_range(declared.get("max_retry"), _MAX_RETRY_MIN, _MAX_RETRY_MAX)
    if max_retry is not None:
        merged["max_retry"] = int(max_retry)
    timeout_s = finite_in_range(declared.get("timeout_s"), _TIMEOUT_MIN, _TIMEOUT_MAX)
    if timeout_s is not None:
        merged["timeout_s"] = int(timeout_s)

    return merged
