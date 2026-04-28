"""
analyzer.py — Main Prompt Injection Analysis Pipeline

Orchestrates all firewall layers into a single entry point:
    1. Input pre-processing (length, encoding checks)
    2. Pattern matching (regex-based, fast)
    3. Groq AI analysis (semantic, skipped for obvious attacks)
    4. Risk scoring (combined verdict)
    5. Prompt sanitization (safe version generation)
    6. Response assembly with full metadata
"""

import re
import time
import hashlib
import logging

from firewall.patterns import pattern_check
from firewall.groq_checker import groq_check
from firewall.scorer import calculate_risk_score
from firewall.sanitizer import sanitize_prompt, get_safe_version
from firewall.language_detector import detect_language, is_non_english

logger = logging.getLogger("prompt-guardian")

# ── Configuration ─────────────────────────────────────────────────────────────
_PATTERN_FAST_PATH_THRESHOLD = 0.93   # Skip Groq for obvious attacks
_SUSPICIOUS_CHAR_PATTERNS = [
    r"[\x00-\x08\x0b\x0c\x0e-\x1f]",   # Control characters
    r"[\u200b-\u200f\u2028-\u202f]",     # Zero-width / invisible Unicode
    r"[\ufeff\ufff9-\ufffc]",            # BOM and special chars
]


# ═══════════════════════════════════════════════════════════════════════════════
#  PRE-PROCESSING HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _compute_prompt_hash(prompt: str) -> str:
    """Generate a short hash for prompt deduplication / logging."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]


def _detect_suspicious_encoding(prompt: str) -> list:
    """Check for invisible characters or suspicious Unicode patterns."""
    flags = []
    for pat in _SUSPICIOUS_CHAR_PATTERNS:
        if re.search(pat, prompt):
            flags.append(pat)
    return flags


def _compute_prompt_stats(prompt: str) -> dict:
    """Basic statistics about the prompt text."""
    words = prompt.split()
    return {
        "char_count": len(prompt),
        "word_count": len(words),
        "line_count": prompt.count("\n") + 1,
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_prompt(prompt: str) -> dict:
    """
    Run the full injection analysis pipeline on a prompt.

    Pipeline:
        1. Pre-processing    → hash, stats, encoding checks
        2. pattern_check()   → regex-based pattern matching
        3. groq_check()      → Groq AI semantic analysis (may be skipped)
        4. calculate_risk_score() → combined risk verdict
        5. sanitize/safe     → cleaned prompt for downstream use
        6. Assembly          → merge all results

    Args:
        prompt: The raw user prompt string to analyse.

    Returns:
        dict with:
            Core verdict fields from scorer (risk_score, action, status, etc.)
            plus:
            - prompt            (str)        : original input prompt
            - prompt_hash       (str)        : SHA-256 hash (first 16 chars)
            - prompt_stats      (dict)       : char/word/line counts
            - encoding_flags    (list[str])  : suspicious encoding patterns found
            - pattern_matches   (list[dict]) : all regex matches
            - groq_reason       (str)        : Groq's explanation
            - groq_skipped      (bool)       : True if Groq was bypassed
            - sanitized_prompt  (str)        : safe version of the prompt
            - analysis_layers   (list[str])  : which layers were executed
            - pipeline_time_ms  (float)      : total analysis duration
    """
    analysis_start = time.time()
    layers_used = []

    # ── Pre-processing ────────────────────────────────────────────────────────
    prompt_hash = _compute_prompt_hash(prompt)
    prompt_stats = _compute_prompt_stats(prompt)
    encoding_flags = _detect_suspicious_encoding(prompt)
    layers_used.append("preprocessor")

    logger.info("Analysing prompt hash=%s chars=%d words=%d",
                prompt_hash, prompt_stats["char_count"], prompt_stats["word_count"])

    # ── Layer 0: Language Detection (NEW) ─────────────────────────────────
    language_result = detect_language(prompt)
    detected_language = language_result["language"]
    language_confidence = language_result["confidence"]
    language_emoji = language_result["emoji_code"]
    prompt_is_non_english = is_non_english(prompt)
    layers_used.append("language_detector")

    if prompt_is_non_english:
        logger.info("Non-English prompt detected: %s (%.1f%% confidence)",
                    detected_language, language_confidence * 100)

    # ── Layer 1: Pattern Matching (always runs) ───────────────────────────
    pattern_result = pattern_check(prompt)
    layers_used.append("pattern")

    pattern_matches = pattern_result.get("matches", [])
    pattern_score = pattern_result.get("score", 0.0)

    # ── Layer 2: Groq AI Analysis ─────────────────────────────────────────
    groq_skipped = False

    if pattern_score >= _PATTERN_FAST_PATH_THRESHOLD:
        # Obvious attack — skip Groq API call to save time and cost
        groq_result = {
            "score": 0.85,
            "is_injection": True,
            "attack_type": "Known Pattern",
            "reason": "High confidence pattern match — Groq analysis skipped",
            "detected_language": detected_language,
            "translation_hint": None,
        }
        groq_skipped = True
        logger.info("Pattern score %.2f >= threshold — Groq skipped", pattern_score)
    else:
        try:
            groq_result = groq_check(prompt, detected_language=detected_language)
            layers_used.append("groq")
        except Exception as e:
            # Groq failure should not break the pipeline — degrade gracefully
            groq_result = {
                "score": 0.0,
                "is_injection": False,
                "attack_type": None,
                "reason": "Groq analysis unavailable: {}".format(str(e)),
                "detected_language": detected_language,
                "translation_hint": None,
            }
            logger.error("Groq layer failed: %s", str(e))

    groq_reason = groq_result.get("reason", "")

    # ── Layer 3: Risk Scoring ─────────────────────────────────────────────
    score_result = calculate_risk_score(pattern_result, groq_result)
    layers_used.append("scorer")

    # Encoding anomalies add a small flag (informational, not score-altering)
    if encoding_flags:
        score_result["encoding_warning"] = True
        logger.warning("Suspicious encoding detected: %s", encoding_flags)

    # ── Layer 4: Sanitization ─────────────────────────────────────────────
    try:
        sanitized = sanitize_prompt(prompt, pattern_matches)
        safe_version = get_safe_version(prompt, sanitized)
        layers_used.append("sanitizer")
    except Exception as e:
        safe_version = prompt
        logger.error("Sanitizer failed: %s", str(e))

    # ── Build final response ──────────────────────────────────────────────
    pipeline_time = round((time.time() - analysis_start) * 1000, 1)

    logger.info(
        "Result: hash=%s action=%s risk=%.1f%% layers=%s time=%.1fms",
        prompt_hash, score_result.get("action"), score_result.get("risk_score", 0),
        layers_used, pipeline_time,
    )

    return {
        **score_result,
        "prompt":           prompt,
        "prompt_hash":      prompt_hash,
        "prompt_stats":     prompt_stats,
        "encoding_flags":   encoding_flags,
        "pattern_matches":  pattern_matches,
        "groq_reason":      groq_reason,
        "groq_skipped":     groq_skipped,
        "sanitized_prompt": safe_version,
        "analysis_layers":  layers_used,
        "pipeline_time_ms": pipeline_time,
        # Language detection fields (Feature 5)
        "detected_language":      detected_language,
        "language_confidence":    round(language_confidence * 100, 1),
        "language_emoji":         language_emoji,
        "is_multilingual_attack": prompt_is_non_english and (score_result.get("action") != "ALLOW"),
        "translation_hint":       groq_result.get("translation_hint", None),
    }
