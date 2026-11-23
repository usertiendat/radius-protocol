"""
Global Exception Handlers cho FastAPI Application (Phase 0B - Step 3.3.3).
Chịu trách nhiệm:
1. Ánh xạ toàn bộ BaseBusinessException thành HTTP JSON response chuẩn hóa:
   {
       "error": {
           "code": "<ERROR_CODE>",
           "message": "<ERROR_MESSAGE>"
       }
   }
2. Bảo vệ an ninh: Không để lộ stack trace, thông tin CSDL, credentials hoặc bí mật hệ thống.
3. Xử lý TransactionAlreadyActiveError như một lỗi nội bộ an toàn (HTTP 500) mà không lộ ranh giới giao dịch nội bộ.
4. Xử lý ngoại lệ không xác định (Unhandled Exception) thành HTTP 500 an toàn.
5. Giữ nguyên cơ chế xử lý mặc định của FastAPI đối với HTTPException và RequestValidationError.
"""

import logging
from typing import Union
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.exceptions import (
    BaseBusinessException,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ServiceUnavailableError,
    UnauthorizedError,
    ValidationError,
)
from app.services.transaction import TransactionAlreadyActiveError

logger = logging.getLogger(__name__)


def business_exception_handler(request: Request, exc: BaseBusinessException) -> JSONResponse:
    """
    Xử lý tập trung toàn bộ Business Exceptions (NotFoundError, ConflictError, UnauthorizedError,
    ForbiddenError, ServiceUnavailableError, ValidationError,...).

    Chuẩn hóa JSON Response:
    {
        "error": {
            "code": exc.code,
            "message": exc.message
        }
    }
    """
    logger.info(
        "Business exception tại endpoint %s: [%s] %s",
        getattr(request, "url", None) and getattr(request.url, "path", None) or "unknown",
        exc.code,
        exc.message,
    )
    return JSONResponse(
        status_code=exc.http_status,
        content={
            "error": {
                "code": exc.code,
                "message": exc.message,
            }
        },
    )


def transaction_already_active_handler(request: Request, exc: TransactionAlreadyActiveError) -> JSONResponse:
    """
    Xử lý ngoại lệ vi phạm ranh giới transaction (TransactionAlreadyActiveError).
    Đây là lỗi lập trình / thiết kế kiến trúc nội bộ, tuyệt đối không trả chi tiết cho client.
    Trả về HTTP 500 an toàn và ghi log cảnh báo hệ thống.
    """
    logger.error(
        "Vi phạm ranh giới giao dịch (Transaction Invariant Violation) tại %s: %s",
        getattr(request, "url", None) and getattr(request.url, "path", None) or "unknown",
        exc,
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "Đã xảy ra sự cố nội bộ trong quá trình xử lý giao dịch.",
            }
        },
    )


def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Xử lý các ngoại lệ không xác định (Unhandled/General Exceptions).
    Ngăn chặn hoàn toàn việc rò rỉ stack trace, URL CSDL, credentials hay SQL query ra ngoài client.
    Trả về HTTP 500 với cấu trúc JSON chuẩn hóa.
    """
    # Nếu là HTTPException hoặc RequestValidationError, giữ nguyên cơ chế xử lý mặc định của FastAPI
    if isinstance(exc, (HTTPException, StarletteHTTPException, RequestValidationError)):
        raise exc

    logger.error(
        "Ngoại lệ hệ thống chưa được phân loại tại %s: %s",
        getattr(request, "url", None) and getattr(request.url, "path", None) or "unknown",
        exc,
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "Đã xảy ra lỗi máy chủ nội bộ. Vui lòng thử lại sau.",
            }
        },
    )


def register_exception_handlers(app: FastAPI) -> None:
    """
    Đăng ký toàn bộ exception handlers tập trung vào FastAPI application instance.
    """
    # 1. Đăng ký cho BaseBusinessException và toàn bộ lớp con
    for exc_cls in (
        BaseBusinessException,
        NotFoundError,
        ConflictError,
        UnauthorizedError,
        ForbiddenError,
        ServiceUnavailableError,
        ValidationError,
    ):
        app.add_exception_handler(exc_cls, business_exception_handler)

    # 2. Đăng ký cho TransactionAlreadyActiveError (Lỗi vi phạm ranh giới giao dịch)
    app.add_exception_handler(TransactionAlreadyActiveError, transaction_already_active_handler)

    # 3. Đăng ký cho Exception tổng quát (Unhandled exceptions)
    app.add_exception_handler(Exception, unhandled_exception_handler)
