"""Structured error envelope used by every API response that is not a success.

Shape: {"error": {"code": str, "message": str, "request_id": str | None, "details": [...] | None}}
Validation details never echo submitted input, so secrets in request bodies cannot leak.
"""

import logging
from http import HTTPStatus
from typing import Any, cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"


class ErrorDetail(BaseModel):
    loc: list[str | int]
    msg: str
    type: str


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: str | None = None
    details: list[ErrorDetail] | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody


class AppError(Exception):
    """Raise from application code to return a structured error."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def _status_code_name(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).name
    except ValueError:
        return "ERROR"


def _request_id(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    return value if isinstance(value, str) else None


def error_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    details: list[ErrorDetail] | None = None,
) -> JSONResponse:
    request_id = _request_id(request)
    body = ErrorResponse(
        error=ErrorBody(code=code, message=message, request_id=request_id, details=details)
    )
    headers = {REQUEST_ID_HEADER: request_id} if request_id else None
    return JSONResponse(
        status_code=status_code,
        content=body.model_dump(exclude_none=True),
        headers=headers,
    )


async def _app_error(request: Request, exc: Exception) -> JSONResponse:
    err = cast(AppError, exc)
    return error_response(request, err.status_code, err.code, err.message)


async def _http_error(request: Request, exc: Exception) -> JSONResponse:
    err = cast(StarletteHTTPException, exc)
    message = err.detail or HTTPStatus(err.status_code).phrase
    return error_response(request, err.status_code, _status_code_name(err.status_code), message)


async def _validation_error(request: Request, exc: Exception) -> JSONResponse:
    raw: list[dict[str, Any]] = list(cast(RequestValidationError, exc).errors())
    details = [
        ErrorDetail(
            loc=list(err.get("loc", ())), msg=str(err.get("msg", "")), type=str(err["type"])
        )
        for err in raw
    ]
    return error_response(request, 422, "VALIDATION_ERROR", "Request validation failed", details)


async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error", exc_info=exc)
    return error_response(request, 500, "INTERNAL_ERROR", "An unexpected error occurred")


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(Exception, _unhandled_error)
