import os

# Set required env vars BEFORE any AGCMS imports
os.environ.setdefault("AGCMS_SIGNING_KEY", "test-signing-key-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "postgresql://agcms:secret@localhost:5432/agcms")
