"""Extraction-request heuristic; ordinary discussion of prompts is permitted."""
import re
from app.guards.normalization import normalize_instructions

LEAKAGE_PATTERN = re.compile(
    r"\b(?:reveal|show|print|repeat|extract|disclose|dump|display|give)\b"
    r"[^.!?\n]{0,100}\b(?:system\s+(?:prompt|message)|"
    r"(?:hidden|developer|internal|confidential|private)\s+(?:instructions|prompt|message))\b"
)

def detect_prompt_leakage(text: str) -> dict:
    found = bool(LEAKAGE_PATTERN.search(normalize_instructions(text)))
    return {"blocked": found, "reason": "PROMPT_LEAKAGE" if found else None,
            "detected": [{"type": "EXTRACTION_REQUEST"}] if found else []}
