"""Local FastAPI gateway. Run one worker; see README for deployment limits."""
from secrets import compare_digest
from threading import BoundedSemaphore
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.trustedhost import TrustedHostMiddleware
from app.config import PROJECT_ROOT, settings
from app.middleware import BodyLimitMiddleware
from app.schemas import ChatRequest, ChatResponse, PolicyRequest
from app.services.audit_logger import log_audit_event
from app.services.gateway import Gateway
from app.services.ollama_client import get_ollama_status
from app.services.security_logger import get_recent_events

app = FastAPI(title="LLM Guardrails Gateway", version="1.1.0",
              description="Local Ollama gateway with input/output inspection and explicit policy decisions.")
limiter = Limiter(key_func=get_remote_address, headers_enabled=True)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)
app.add_middleware(CORSMiddleware,
                   allow_origins=["http://localhost:5500", "http://127.0.0.1:5500"],
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type", "X-Admin-Key"],
                   allow_credentials=False)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"])
gateway = Gateway()
slots = BoundedSemaphore(settings.max_concurrent_requests)
admin_header = APIKeyHeader(name="X-Admin-Key", auto_error=False)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    if request.url.path.startswith("/dashboard"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'"
        )
    return response

@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={
        "success": False, "blocked": False, "action": "error", "reason": "INVALID_REQUEST",
        "detail": [{"loc": error["loc"], "type": error["type"]} for error in exc.errors()],
    })

@app.get("/", tags=["Status"])
def root():
    return {"message": "LLM Guardrails Gateway is running", "model": settings.model,
            "dashboard": "/dashboard/", "docs": "/docs"}

@app.get("/health", tags=["Status"])
def health():
    status = get_ollama_status()
    ready = status["ollama"] == "available" and status["model_available"]
    return JSONResponse({"status": "healthy" if ready else "degraded", "model": settings.model,
                         "semantic_enabled": settings.semantic_enabled, **status},
                        status_code=200 if ready else 503)

@app.post("/chat", response_model=ChatResponse, tags=["Gateway"])
@limiter.limit(settings.rate_limit)
def chat(request: Request, chat_request: ChatRequest):
    if not slots.acquire(blocking=False):
        return JSONResponse({"success": False, "blocked": False, "action": "error",
                             "reason": "GATEWAY_BUSY"}, status_code=503,
                            headers={"Retry-After": "2"})
    try:
        result, status = gateway.process(chat_request.message)
        return JSONResponse(result, status_code=status)
    finally:
        slots.release()

@app.get("/stats", tags=["Dashboard"])
def stats():
    return gateway.state.stats()

@app.get("/history", tags=["Dashboard"])
def history():
    return {"history": gateway.state.history()}

@app.get("/security-events", tags=["Dashboard"])
def security_events(limit: int = Query(10, ge=1, le=100)):
    return {"events": get_recent_events(limit)}

@app.get("/risk-config", tags=["Policies"])
def risk_config():
    return {"levels": {"LOW": "0–29", "MEDIUM": "30–59", "HIGH": "60–79", "CRITICAL": "80–100"},
            "block_threshold": 80, "max_input_length": settings.max_input_length,
            "max_line_count": settings.max_line_count, "rate_limit": settings.rate_limit}

@app.get("/policies", tags=["Policies"])
def get_policies():
    policies = gateway.policies.get_all_policies()
    return {"policies": policies,
            "allowed_actions": {name: gateway.policies.allowed_actions(name) for name in policies},
            "updates_enabled": bool(settings.admin_key), "persistent": False}

def require_admin(key: str | None = Depends(admin_header)):
    if not settings.admin_key:
        raise HTTPException(403, "Policy updates are disabled. Configure GATEWAY_ADMIN_KEY.")
    if key is None or not compare_digest(key.encode(), settings.admin_key.encode()):
        raise HTTPException(401, "Invalid admin key")

@app.post("/policies", dependencies=[Depends(require_admin)], tags=["Policies"])
def update_policy(policy: PolicyRequest):
    try:
        gateway.policies.set_policy(policy.guardrail, policy.action)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    log_audit_event("POLICY_UPDATED", {"guardrail": policy.guardrail, "action": policy.action})
    return {"success": True, "guardrail": policy.guardrail, "action": policy.action}

@app.get("/dashboard", include_in_schema=False)
def dashboard_redirect():
    return RedirectResponse("/dashboard/")

@app.get("/dashboard/", include_in_schema=False)
def dashboard():
    return FileResponse(PROJECT_ROOT / "dashboard" / "index.html")

app.mount("/dashboard/assets", StaticFiles(directory=PROJECT_ROOT / "dashboard" / "assets"), name="assets")
