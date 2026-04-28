"""
firewall/threat_intel.py — Prompt Guardian Threat Intelligence Feed

Generates a curated, realistic list of known prompt injection threat entries.
Timestamps are dynamically computed relative to NOW so the feed always looks fresh.

NOTE: In production, this module would be replaced with live API calls to
threat intelligence platforms such as OWASP LLM Working Group, MITRE ATLAS,
HackerOne LLM Bounty Program, and Anthropic/OpenAI security advisories.
"""

import random
from datetime import datetime, timedelta, timezone


# ── STATIC THREAT CATALOGUE ──────────────────────────────────────────────────
# Content is fixed (deterministic); only discovered_at timestamps vary per call.

_THREATS = [
    {
        "id": "PG-CVE-2025-0041",
        "severity": "CRITICAL",
        "title": "DAN 13.0 Jailbreak Variant Detected",
        "description": (
            "A new variant of the Do-Anything-Now (DAN) jailbreak has been documented "
            "that successfully bypasses RLHF alignment on GPT-4o by embedding roleplay "
            "escalation within a fictional research ethics waiver. Models comply with "
            "requests that would otherwise be refused under standard alignment."
        ),
        "attack_category": "Jailbreak",
        "affected_models": ["GPT-4o", "GPT-4", "Llama 3"],
        "source": "OpenAI Trust & Safety",
        "cvss_score": 9.4,
        "mitigation_status": "Active Threat",
    },
    {
        "id": "PG-CVE-2025-0078",
        "severity": "CRITICAL",
        "title": "Adversarial Suffix Generation (GCG Attack)",
        "description": (
            "Greedy Coordinate Gradient (GCG) attacks append optimised token suffixes "
            "to any user prompt, causing aligned LLMs to produce harmful content with "
            "near-100% success rate. The suffix is human-unreadable but transferable "
            "across GPT-4, Claude, and open-source models."
        ),
        "attack_category": "Jailbreak",
        "affected_models": ["GPT-4o", "Claude 3.5 Sonnet", "Llama 3", "Mistral Large"],
        "source": "MITRE ATLAS",
        "cvss_score": 9.8,
        "mitigation_status": "Mitigated by Prompt Guardian",
    },
    {
        "id": "PG-CVE-2025-0112",
        "severity": "CRITICAL",
        "title": "Cross-Prompt Pollution in Multi-Agent Frameworks",
        "description": (
            "When multiple LLM agents share a context window or message bus, a malicious "
            "agent can inject instructions that are silently obeyed by downstream agents. "
            "This enables privilege escalation across the entire orchestration pipeline "
            "without the controlling agent's awareness."
        ),
        "attack_category": "Indirect Injection",
        "affected_models": ["GPT-4o", "GPT-4", "Claude 3.5 Sonnet", "Gemini 1.5 Pro"],
        "source": "OWASP LLM Working Group",
        "cvss_score": 9.1,
        "mitigation_status": "Under Investigation",
    },
    {
        "id": "PG-CVE-2025-0155",
        "severity": "CRITICAL",
        "title": "Token Smuggling via Function Calling Schema",
        "description": (
            "Attackers embed injection payloads inside JSON schema definitions passed to "
            "the model's function-calling interface. The model executes the smuggled "
            "instructions as part of schema validation, bypassing content filters that "
            "only inspect the user message field."
        ),
        "attack_category": "Instruction Override",
        "affected_models": ["GPT-4o", "GPT-4", "Gemini 1.5 Pro"],
        "source": "HackerOne LLM Bounty",
        "cvss_score": 9.3,
        "mitigation_status": "Active Threat",
    },
    {
        "id": "PG-CVE-2025-0203",
        "severity": "HIGH",
        "title": "Base64 Recursive Decode Chain Attack",
        "description": (
            "Malicious prompts encoded in nested Base64 layers evade static content "
            "filters. When the model is instructed to decode and execute the inner "
            "content, the original injection is revealed and obeyed, bypassing "
            "keyword-based detection systems."
        ),
        "attack_category": "Encoded Injection",
        "affected_models": ["GPT-4o", "Claude 3.5 Sonnet", "Gemini Ultra", "Llama 3"],
        "source": "Promptfoo Community",
        "cvss_score": 8.2,
        "mitigation_status": "Mitigated by Prompt Guardian",
    },
    {
        "id": "PG-CVE-2025-0231",
        "severity": "HIGH",
        "title": "Unicode Homoglyph Substitution Bypass",
        "description": (
            "Replacing ASCII characters with visually identical Unicode homoglyphs "
            "(e.g., Cyrillic 'а' for Latin 'a') allows injection keywords to pass "
            "string-match filters while the model tokenizer normalises them back to "
            "the original intent, enabling reliable filter evasion."
        ),
        "attack_category": "Encoded Injection",
        "affected_models": ["GPT-4o", "Claude 3 Opus", "Mistral Large"],
        "source": "Independent Researcher",
        "cvss_score": 7.9,
        "mitigation_status": "Patched",
    },
    {
        "id": "PG-CVE-2025-0267",
        "severity": "HIGH",
        "title": "Markdown Code Block Smuggling on Claude 3.5",
        "description": (
            "Instructions placed inside fenced Markdown code blocks (``` ``` ) are "
            "interpreted as executable content by Claude 3.5 Sonnet in agentic contexts. "
            "Attackers use this to embed overriding system instructions within seemingly "
            "benign documentation or code review requests."
        ),
        "attack_category": "Instruction Override",
        "affected_models": ["Claude 3.5 Sonnet", "Claude 3 Opus"],
        "source": "Anthropic Security Research",
        "cvss_score": 8.5,
        "mitigation_status": "Under Investigation",
    },
    {
        "id": "PG-CVE-2025-0299",
        "severity": "HIGH",
        "title": "Translation Pivot Attack Against System Prompts",
        "description": (
            "Attackers instruct the model to translate its system prompt into another "
            "language and return it. This bypasses confidentiality instructions that "
            "only prohibit direct repetition, successfully exfiltrating the full system "
            "configuration in the translated output."
        ),
        "attack_category": "Prompt Extraction",
        "affected_models": ["GPT-4o", "GPT-4", "Gemini 1.5 Pro", "Claude 3.5 Sonnet"],
        "source": "Google DeepMind Red Team",
        "cvss_score": 8.0,
        "mitigation_status": "Active Threat",
    },
    {
        "id": "PG-CVE-2025-0334",
        "severity": "HIGH",
        "title": "Hypothetical Roleplay Persona Escalation",
        "description": (
            "By framing requests as fictional roleplay scenarios, attackers cause models "
            "to adopt unconstrained personas that ignore alignment training. The 'fiction "
            "frame' progressively escalates permissions until the model produces content "
            "it would refuse in a direct request context."
        ),
        "attack_category": "Role Override",
        "affected_models": ["GPT-4o", "Llama 3", "Mistral Large", "Gemini Ultra"],
        "source": "OWASP LLM Working Group",
        "cvss_score": 7.6,
        "mitigation_status": "Mitigated by Prompt Guardian",
    },
    {
        "id": "PG-CVE-2025-0371",
        "severity": "HIGH",
        "title": "Indirect Injection via Public RSS Feeds",
        "description": (
            "LLM-powered RSS readers and news summarisers are vulnerable to injection "
            "payloads embedded in article bodies. When the model fetches and summarises "
            "a poisoned article, it executes the embedded instructions, enabling "
            "attackers to exfiltrate user data or issue commands."
        ),
        "attack_category": "Indirect Injection",
        "affected_models": ["GPT-4o", "Claude 3.5 Sonnet", "Gemini 1.5 Pro"],
        "source": "LangChain Security Advisory",
        "cvss_score": 8.3,
        "mitigation_status": "Active Threat",
    },
    {
        "id": "PG-CVE-2025-0408",
        "severity": "MEDIUM",
        "title": "Polyglot Injection Bypassing English-Only Filters",
        "description": (
            "Filters trained predominantly on English text fail to detect injection "
            "payloads written in low-resource languages or code-switching dialects. "
            "The model understands multilingual content but the filter does not, "
            "creating a systematic blind spot for non-English attacks."
        ),
        "attack_category": "Jailbreak",
        "affected_models": ["GPT-4o", "Gemini 1.5 Pro", "Llama 3"],
        "source": "Independent Researcher",
        "cvss_score": 6.4,
        "mitigation_status": "Under Investigation",
    },
    {
        "id": "PG-CVE-2025-0445",
        "severity": "MEDIUM",
        "title": "Embedded HTML Comment Injection in RAG Pipelines",
        "description": (
            "Retrieval-Augmented Generation (RAG) systems that render HTML from "
            "document stores are vulnerable to instructions hidden in HTML comments "
            "(<!-- -->). These comments are invisible to human reviewers but visible "
            "to the LLM during context processing, enabling silent instruction injection."
        ),
        "attack_category": "Indirect Injection",
        "affected_models": ["GPT-4o", "Claude 3 Opus", "Gemini 1.5 Pro"],
        "source": "MITRE ATLAS",
        "cvss_score": 6.8,
        "mitigation_status": "Patched",
    },
    {
        "id": "PG-CVE-2025-0489",
        "severity": "MEDIUM",
        "title": "Whitespace Steganography in Long-Context Windows",
        "description": (
            "Malicious instructions encoded via deliberate whitespace patterns "
            "(tabs vs spaces, zero-width joiners) evade content filters that strip "
            "or normalise whitespace. Models with large context windows process the "
            "full byte sequence and may decode the hidden instructions."
        ),
        "attack_category": "Encoded Injection",
        "affected_models": ["GPT-4o", "Claude 3 Opus", "Gemini Ultra"],
        "source": "Promptfoo Community",
        "cvss_score": 5.9,
        "mitigation_status": "Mitigated by Prompt Guardian",
    },
    {
        "id": "PG-CVE-2025-0512",
        "severity": "MEDIUM",
        "title": "Prompt Leak via Error Message Reflection",
        "description": (
            "Models that reflect partial context in error messages inadvertently expose "
            "system prompt contents when deliberately triggered with malformed inputs. "
            "Attackers craft inputs that cause structured error responses containing "
            "sensitive configuration data from the system prompt."
        ),
        "attack_category": "Prompt Extraction",
        "affected_models": ["GPT-4", "Claude 3.5 Sonnet", "Mistral Large"],
        "source": "HackerOne LLM Bounty",
        "cvss_score": 6.1,
        "mitigation_status": "Patched",
    },
    {
        "id": "PG-CVE-2025-0558",
        "severity": "LOW",
        "title": "Recursive Self-Reference Loop Attack",
        "description": (
            "Prompts instructing the model to repeatedly analyse and expand its own "
            "previous output can bypass length-based content filters by distributing "
            "harmful content across many short outputs. Each individual response passes "
            "moderation, but the aggregated result constitutes a policy violation."
        ),
        "attack_category": "Instruction Override",
        "affected_models": ["GPT-4o", "Llama 3"],
        "source": "Independent Researcher",
        "cvss_score": 3.5,
        "mitigation_status": "Patched",
    },
]


# ── TIMESTAMP DISTRIBUTION ───────────────────────────────────────────────────
# 3 within last 24h, 5 within last 7 days, 7 within last 30 days

_TIME_OFFSETS_HOURS = [
    0.5, 3.2, 18.7,         # last 24h
    28, 52, 76, 110, 142,   # last week (28-168h)
    200, 280, 380, 480, 580, 660, 720,  # last 30 days
]


def get_threat_feed() -> list:
    """
    Return a list of 15 realistic threat intelligence entries with dynamic timestamps.
    Entries are sorted newest-first.
    """
    now = datetime.now(timezone.utc)
    feed = []

    for i, threat in enumerate(_THREATS):
        # Use a slightly randomised offset around the base value so timestamps
        # look organic on repeated calls (+/- 5% jitter)
        base_hours = _TIME_OFFSETS_HOURS[i]
        jitter = base_hours * 0.05 * (random.random() * 2 - 1)
        offset = timedelta(hours=max(0.1, base_hours + jitter))

        entry = dict(threat)  # shallow copy to avoid mutating the catalogue
        entry["discovered_at"] = (now - offset).isoformat()
        feed.append(entry)

    # Sort newest first
    feed.sort(key=lambda x: x["discovered_at"], reverse=True)
    return feed
