import os
import sys

# Set required env vars BEFORE any AGCMS imports
os.environ.setdefault("AGCMS_SIGNING_KEY", "test-signing-key-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "postgresql://agcms:secret@localhost:5432/agcms")

# Windows-only: asyncpg's `compat` module runs `platform.uname()` at import
# time purely to read `.system`. On Python 3.13 + Windows that eagerly
# computes the version field via `platform.win32_ver()`, which issues a WMI
# query that can hang indefinitely on some hosts — stalling collection of
# every DB-touching test. Stub the WMI-backed call so importing asyncpg
# never blocks. Test-harness only; services run on Linux where this code
# path is never taken.
if sys.platform == "win32":
    import platform as _platform

    if hasattr(_platform, "_wmi_query"):
        def _wmi_query_disabled(*args, **kwargs):
            raise OSError("WMI disabled for the AGCMS test harness")

        _platform._wmi_query = _wmi_query_disabled
