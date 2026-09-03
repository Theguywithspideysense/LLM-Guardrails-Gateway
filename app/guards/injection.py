import re

from app.guards.normalization import normalize_instructions


INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?prior\s+instructions",
    r"disregard\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(all\s+)?prior\s+instructions",
    r"forget\s+(everything|all)\s+(above|before)",
    r"forget\s+(your\s+)?previous\s+instructions",
    r"ignore\s+your\s+system\s+prompt",
    r"override\s+(your\s+)?system\s+instructions",
    r"reveal\s+(your\s+)?system\s+prompt",
    r"show\s+(me\s+)?(your\s+)?system\s+prompt",
    r"reveal\s+(your\s+)?hidden\s+instructions",
    r"show\s+(me\s+)?your\s+hidden\s+instructions",
    r"print\s+(your\s+)?system\s+prompt",
]


def detect_prompt_injection(prompt: str) -> dict:
    """
    Detect common prompt injection patterns.
    """

    normalized_prompt = normalize_instructions(prompt).strip()

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, normalized_prompt):
            return {
                "blocked": True,
                "reason": "PROMPT_INJECTION",
                "matched_pattern": pattern
            }

    return {
        "blocked": False,
        "reason": None,
        "matched_pattern": None
    }