"""S3 Object Lock uploader for anchor manifests.

Only imported when ``AGCMS_ANCHOR_S3_BUCKET`` is set. Keeps boto3 out of
the core path so dev deployments and unit tests don't need AWS creds.

Bucket requirements:
  * Versioning enabled.
  * Object Lock enabled in Compliance mode (set at bucket creation; not
    reversible).
  * IAM identity has ``s3:PutObject`` + ``s3:PutObjectRetention``.

Layout: ``s3://<bucket>/<tenant_id>/<yyyy-mm-dd>.json``
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import Optional


class S3AnchorUploader:
    """Async-compatible wrapper over a sync boto3 S3 client."""

    def __init__(self, bucket: str, region: Optional[str] = None):
        try:
            import boto3  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "boto3 is required for S3 anchor uploads. "
                "Install it or unset AGCMS_ANCHOR_S3_BUCKET to disable S3."
            ) from exc
        self._bucket = bucket
        self._s3 = boto3.client("s3", region_name=region or os.environ.get("AWS_REGION"))

    async def __call__(self, manifest: dict, retention_until: datetime) -> dict:
        tenant = manifest["tenant_id"]
        day = manifest["period_start"][:10]  # YYYY-MM-DD
        key = f"{tenant}/{day}.json"
        body = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._s3.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=retention_until,
            ),
        )
        return {
            "url": f"s3://{self._bucket}/{key}",
            "version_id": response.get("VersionId"),
        }


def build_uploader_from_env() -> Optional[S3AnchorUploader]:
    bucket = os.environ.get("AGCMS_ANCHOR_S3_BUCKET")
    if not bucket:
        return None
    return S3AnchorUploader(bucket=bucket)
