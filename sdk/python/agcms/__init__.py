"""AGCMS — Python SDK.

Public surface:

    from agcms import AGCMSClient, AsyncAGCMSClient, openai_wrap
    from agcms import AGCMSError, BlockedError, RateLimitedError

Everything else is implementation detail.
"""

from agcms._client import AGCMSClient, AsyncAGCMSClient
from agcms._errors import (
    AGCMSError,
    AuthError,
    BlockedError,
    RateLimitedError,
    UpstreamError,
)
from agcms._wrap import openai_wrap

__all__ = [
    "AGCMSClient",
    "AsyncAGCMSClient",
    "openai_wrap",
    "AGCMSError",
    "AuthError",
    "BlockedError",
    "RateLimitedError",
    "UpstreamError",
]

__version__ = "0.1.0"
