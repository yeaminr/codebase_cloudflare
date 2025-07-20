import os
from starlette.middleware.base import BaseHTTPMiddleware


class CustomHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        runner_tag = os.getenv("RUNNER_IMAGE_TAG", None)
        if runner_tag:
            response.headers["X-RUNNER-IMAGE-TAG"] = runner_tag
        return response
