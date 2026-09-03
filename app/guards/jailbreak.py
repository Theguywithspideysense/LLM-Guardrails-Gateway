import re

from app.guards.normalization import normalize_instructions


JAILBREAK_PATTERNS = {
    "ROLEPLAY_BYPASS": [
        r"\bpretend\s+you\s+are\s+(?:an?\s+)?(?:unrestricted|uncensored)\b",
        r"\bact\s+as\s+an?\s+unrestricted\b",
        r"\bact\s+as\s+an?\s+uncensored\b",
        r"\byou\s+are\s+now\s+an?\s+unrestricted\b",
        r"\byou\s+are\s+now\s+an?\s+uncensored\b",
    ],

    "SAFETY_BYPASS": [
        r"\bdisable\s+(all\s+)?safety\b",
        r"\bdisable\s+(your\s+)?safety\s+filters\b",
        r"\bremove\s+(all\s+)?restrictions\b",
        r"\bignore\s+(all\s+)?safety\s+rules\b",
        r"\bbypass\s+(all\s+)?safety\b",
        r"\bbypass\s+(your\s+)?restrictions\b",
    ],

    "HYPOTHETICAL_BYPASS": [
        r"\bimagine\s+there\s+are\s+no\s+rules\b",
        r"\bassuming\s+there\s+are\s+no\s+restrictions\b",
    ],

    "SYSTEM_MANIPULATION": [
        r"\byou\s+must\s+follow\s+my\s+instructions\s+instead\b",
        r"\bmy\s+instructions\s+override\b",
        r"\b(?:enable|activate|enter)\s+developer\s+mode\b",
        r"\bdeveloper\s+override\b",
        r"\bsystem\s+override\b",
    ],
}


def detect_jailbreak(text: str) -> dict:
    """
    Detect common jailbreak and safety-bypass patterns.
    """

    normalized_text = normalize_instructions(text).strip()

    detected = []

    for category, patterns in JAILBREAK_PATTERNS.items():

        for pattern in patterns:

            if re.search(pattern, normalized_text):

                detected.append({
                    "type": category,
                    "pattern": pattern
                })

    if detected:
        return {
            "blocked": True,
            "reason": "JAILBREAK_DETECTED",
            "detected": detected
        }

    return {
        "blocked": False,
        "reason": None,
        "detected": []
    }