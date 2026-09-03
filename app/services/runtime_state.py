from collections import deque
from copy import deepcopy
from threading import RLock

class RuntimeState:
    """Single-process demo state; snapshots are independent of concurrent requests."""
    def __init__(self):
        self._lock = RLock()
        self.reset()

    def reset(self):
        with self._lock:
            self._stats = {"total_requests": 0, "blocked_requests": 0, "failed_requests": 0,
                           "risk_score": 0, "risk_level": "LOW", "latency_ms": 0}
            self._history = deque(maxlen=100)

    def record(self, result: dict):
        with self._lock:
            self._stats["total_requests"] += 1
            self._stats["blocked_requests"] += int(result["blocked"])
            self._stats["failed_requests"] += int(result["action"] == "error")
            self._stats.update(risk_score=result["risk"]["score"],
                               risk_level=result["risk"]["level"],
                               latency_ms=result["latency_ms"])
            self._history.appendleft({
                key: deepcopy(result[key]) for key in (
                    "request_id", "timestamp", "prompt_preview", "action", "blocked",
                    "risk", "violations", "latency_ms", "stage", "reason"
                )
            })

    def stats(self):
        with self._lock:
            return self._stats.copy()

    def history(self):
        with self._lock:
            return deepcopy(list(self._history))
