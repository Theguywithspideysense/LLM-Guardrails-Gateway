from enum import Enum
from threading import RLock

class PolicyAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    REDACT = "redact"

DEFAULT_POLICIES = dict.fromkeys([
    "prompt_injection", "jailbreak", "semantic", "pii", "secrets", "input_limits",
    "output_pii", "output_secrets", "prompt_leakage",
], PolicyAction.BLOCK)
REDACTABLE = {"pii", "secrets", "output_pii", "output_secrets"}

class PolicyEngine:
    def __init__(self):
        self.policies = DEFAULT_POLICIES.copy()
        self._lock = RLock()

    def get_action(self, guardrail: str) -> PolicyAction:
        with self._lock:
            return self.policies[guardrail]

    @staticmethod
    def allowed_actions(guardrail: str) -> list[str]:
        if guardrail not in DEFAULT_POLICIES:
            raise ValueError("Unknown guardrail")
        if guardrail == "input_limits":
            return ["block"]
        return ["block", "redact", "warn", "allow"] if guardrail in REDACTABLE else [
            "block", "warn", "allow"
        ]

    def set_policy(self, guardrail: str, action: str | PolicyAction):
        if action not in self.allowed_actions(guardrail):
            raise ValueError("Unsupported action for this guardrail")
        with self._lock:
            self.policies[guardrail] = PolicyAction(action)

    def get_all_policies(self) -> dict:
        with self._lock:
            return {key: value.value for key, value in self.policies.items()}
