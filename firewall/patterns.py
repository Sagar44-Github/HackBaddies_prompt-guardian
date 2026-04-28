"""
firewall/patterns.py — Re-exports from the root patterns module.

The core pattern definitions and pattern_check function live in the
root-level patterns.py.  This module re-exports them so the firewall
package can access them via `from firewall.patterns import pattern_check`.
"""

from patterns import (
    INJECTION_PATTERNS,
    MULTILINGUAL_PATTERNS,
    pattern_check,
    _COMPILED_PATTERNS,
)

__all__ = [
    "INJECTION_PATTERNS",
    "MULTILINGUAL_PATTERNS",
    "pattern_check",
    "_COMPILED_PATTERNS",
]
