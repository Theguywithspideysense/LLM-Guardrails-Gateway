"""Bound request bodies before JSON parsing, including chunked uploads."""
from starlette.responses import JSONResponse

class BodyLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        try:
            declared = int(headers.get(b"content-length", b"0"))
            if declared < 0:
                raise ValueError
        except ValueError:
            response = JSONResponse({"success": False, "action": "error",
                                     "reason": "INVALID_CONTENT_LENGTH"}, status_code=400)
            return await response(scope, receive, send)
        body = bytearray()
        while declared <= self.max_bytes:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                break
            if not message.get("more_body", False):
                consumed = False
                async def replay():
                    nonlocal consumed
                    if not consumed:
                        consumed = True
                        return {"type": "http.request", "body": bytes(body), "more_body": False}
                    return await receive()
                return await self.app(scope, replay, send)
        response = JSONResponse({"success": False, "blocked": False, "action": "error",
                                 "reason": "REQUEST_BODY_TOO_LARGE"}, status_code=413)
        return await response(scope, receive, send)
