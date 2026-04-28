import re
from firewall.patterns import INJECTION_PATTERNS


def sanitize_prompt(prompt: str, pattern_matches: list) -> str:
    cleaned = prompt

    for pattern, attack_type, weight in INJECTION_PATTERNS:
        cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE)

    # Clean up whitespace artifacts
    cleaned = re.sub(r'\s{2,}', ' ', cleaned).strip()
    cleaned = re.sub(r'^[,;.\s]+|[,;.\s]+$', '', cleaned).strip()

    if len(cleaned) < 8:
        return ''

    return cleaned


def get_safe_version(prompt: str, sanitized: str) -> str:
    if not sanitized:
        return "Your prompt was entirely injection content. Please rephrase your question."

    if sanitized == prompt:
        return prompt

    return sanitized