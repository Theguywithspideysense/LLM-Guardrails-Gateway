"""Request-local pipeline with explicit gates before and after model execution."""
import time
from datetime import datetime, timezone
from uuid import uuid4
import httpx
import ollama
from app.config import settings
from app.guards.output_guard import check_output
from app.guards.semantic_guard import semantic_check
from app.guards.sensitive_data import find_sensitive_data
from app.policies.policy_engine import DEFAULT_POLICIES, PolicyEngine
from app.services.audit_logger import log_audit_event
from app.services.guardrail_engine import GuardrailEngine
from app.services.ollama_client import generate_response
from app.services.redaction_service import redact_sensitive_data
from app.services.risk_engine import calculate_risk, should_block
from app.services.runtime_state import RuntimeState
from app.services.security_logger import log_security_event

class Gateway:
    def __init__(self):
        self.guards = GuardrailEngine()
        self.policies = PolicyEngine()
        self.state = RuntimeState()

    def process(self, original_prompt: str) -> tuple[dict, int]:
        start = time.perf_counter()
        policies = self.policies.get_all_policies()  # One consistent policy snapshot per request.
        checks = {name: {"guardrail": name,
                         "stage": "output" if name.startswith("output_") else "input",
                         "status": "skipped", "blocked": False}
                  for name in DEFAULT_POLICIES}
        checks["semantic"]["stage"] = "semantic"
        if not settings.semantic_enabled:
            checks["semantic"]["status"] = "disabled"
        violations, warnings = [], []
        input_redacted = output_redacted = False
        prompt = original_prompt
        # Avoid scanning oversized input, and redact BEFORE truncating ordinary previews.
        preview = "[Input exceeds limit]" if len(prompt) > settings.max_input_length else (
            redact_sensitive_data(prompt).replace("\n", " ").replace("\r", " ")[:200]
        )

        def finish(action: str, stage: str, reason: str, response=None, status=200):
            result = {
                "request_id": str(uuid4()), "timestamp": datetime.now(timezone.utc).isoformat(),
                "success": action not in {"block", "error"}, "blocked": action == "block",
                "action": action, "stage": stage, "reason": reason, "model": settings.model,
                "risk": calculate_risk(violations), "violation_count": len(violations),
                "violations": violations, "checks": list(checks.values()),
                "redacted": input_redacted or output_redacted,
                "input_redacted": input_redacted, "output_redacted": output_redacted,
                "warnings": warnings, "prompt_preview": preview, "response": response,
                "latency_ms": round((time.perf_counter() - start) * 1000, 2),
            }
            self.state.record(result)
            # No user/model text, provider exceptions, or classifier explanations go to disk.
            event = {key: result[key] for key in ("request_id", "action", "stage", "reason",
                                                  "risk", "redacted", "latency_ms")}
            event["message_length"] = len(original_prompt)
            event["guardrails"] = sorted({v["guardrail"] for v in violations})
            log_audit_event("REQUEST_COMPLETED", event)
            if violations or action == "error":
                log_security_event("SECURITY_DECISION", event)
            return result, status

        def blocked_reason(stage_violations):
            if should_block(calculate_risk(violations)):
                return "CRITICAL_RISK"
            for violation in stage_violations:
                if policies[violation["guardrail"]] == "block":
                    return violation["reason"]
            return None

        def apply_policies(text, stage_violations):
            groups = set()
            for violation in stage_violations:
                name = violation["guardrail"]
                action = policies[name]
                if action == "redact":
                    groups.add(name.removeprefix("output_"))
                elif action == "warn":
                    warnings.append({"guardrail": name, "reason": violation["reason"]})
            if groups:
                text = redact_sensitive_data(text, groups)
                if find_sensitive_data(text, groups):
                    raise ValueError("REDACTION_FAILED")
            return text, bool(groups)

        inputs = self.guards.check_input(prompt)
        checks.update({check["guardrail"]: check for check in inputs["checks"]})
        violations.extend(inputs["violations"])
        reason = blocked_reason(inputs["violations"])
        if reason:
            return finish("block", "input", reason)
        try:
            prompt, input_redacted = apply_policies(prompt, inputs["violations"])
        except ValueError:
            return finish("block", "input", "REDACTION_FAILED")

        if settings.semantic_enabled:
            semantic = semantic_check(prompt)
            checks["semantic"].update(
                status="error" if semantic["error"] else (
                    "triggered" if semantic["blocked"] else "passed"),
                blocked=semantic["blocked"] and not semantic["error"],
            )
            if semantic["error"]:
                return finish("error", "semantic", "SEMANTIC_CHECK_FAILED", status=503)
            if semantic["blocked"]:
                violation = {"guardrail": "semantic", "stage": "semantic",
                             "reason": semantic["reason"], "details": {
                                 "category": semantic["category"],
                                 "confidence": semantic["confidence"]}}
                violations.append(violation)
                reason = blocked_reason([violation])
                if reason:
                    return finish("block", "semantic", reason)
                if policies["semantic"] == "warn":
                    warnings.append({"guardrail": "semantic", "reason": semantic["reason"]})
        else:
            warnings.append({"guardrail": "semantic", "reason": "SEMANTIC_DISABLED"})

        try:
            response = generate_response(prompt)
        except httpx.TimeoutException:
            return finish("error", "generation", "OLLAMA_TIMEOUT", status=504)
        except (httpx.HTTPError, ollama.ResponseError, ConnectionError, ValueError):
            return finish("error", "generation", "OLLAMA_REQUEST_FAILED", status=503)
        if not isinstance(response, str) or not response.strip():
            return finish("error", "generation", "EMPTY_MODEL_RESPONSE", status=502)
        if len(response) > settings.max_output_length:
            return finish("block", "output", "OUTPUT_TOO_LONG")

        output = check_output(response)
        checks.update({check["guardrail"]: check for check in output["checks"]})
        violations.extend(output["violations"])
        reason = blocked_reason(output["violations"])
        if reason:
            return finish("block", "output", reason)
        try:
            response, output_redacted = apply_policies(response, output["violations"])
        except ValueError:
            return finish("block", "output", "REDACTION_FAILED")
        if input_redacted or output_redacted:
            return finish("redact", "complete", "SENSITIVE_DATA_REDACTED", response)
        if warnings:
            return finish("warn", "complete", "ALLOWED_WITH_WARNING", response)
        return finish("allow", "complete", "CHECKS_PASSED", response)
