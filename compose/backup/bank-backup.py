#!/usr/bin/env python3
"""Back the Hindsight bank up to an S3-compatible bucket, and restore it from there.

Why a bank export and not a database dump: `export-bank` writes a portable archive that
carries the documents, facts, bank config, mental models and directives but *no embeddings* --
those are regenerated on import. That makes the file small, independent of the embedding model
and of the Hindsight version, and restorable into an instance configured differently. A dump
of PostgreSQL would be larger, version-coupled, and would carry vectors that are meaningless
to a different model.

boto3 is already inside the official Hindsight image, which is why this runs there instead of
in a sidecar that would need its own S3 client: no extra image, no extra binary, and the
archive is produced by the same tool that the restore path consumes.

Modes
    once      export, upload, prune, exit -- for a cron-like external trigger
    loop      the same, every BACKUP_INTERVAL seconds (the service's default)
    list      show what is in the bucket, newest last
    restore   download an archive and import it into this instance

Nothing here prints a credential. Endpoint, bucket and key names are configuration, not
secrets, and only those appear in the output.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

ADMIN = os.environ.get("HINDSIGHT_ADMIN", "/app/api/.venv/bin/hindsight-admin")

BANK = os.environ.get("BANK", "hermes")
BUCKET = os.environ.get("BUCKET_NAME", "")
PREFIX = os.environ.get("BUCKET_PREFIX", "hindsight").strip("/")
ENDPOINT = os.environ.get("BUCKET_ENDPOINT", "").strip() or None
REGION = os.environ.get("BUCKET_REGION", "us-east-1")
KEEP = int(os.environ.get("BACKUP_KEEP", "7") or 7)
INTERVAL = int(os.environ.get("BACKUP_INTERVAL", "86400") or 86400)


def log(message: str) -> None:
    print(f"[backup] {message}", flush=True)


def fail(message: str) -> None:
    print(f"[backup] error: {message}", file=sys.stderr, flush=True)
    sys.exit(1)


def client():
    if not BUCKET:
        fail("BUCKET_NAME is empty: set it in compose/.env (see the bucket block there)")
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        fail("boto3 is missing; this script expects the official Hindsight image")

    for name in ("BUCKET_ACCESS_KEY", "BUCKET_SECRET_KEY"):
        if not os.environ.get(name):
            fail(f"{name} is empty: the bucket needs credentials from compose/.env")

    # Path-style addressing is what MinIO and most self-hosted S3 gateways require; virtual
    # host style is what AWS and Cloudflare R2 prefer. Both are supported by one flag.
    addressing = "path" if os.environ.get("BUCKET_PATH_STYLE", "auto") == "path" else "auto"
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id=os.environ["BUCKET_ACCESS_KEY"],
        aws_secret_access_key=os.environ["BUCKET_SECRET_KEY"],
        config=Config(s3={"addressing_style": addressing}, retries={"max_attempts": 3}),
    )


def key_for(moment: datetime) -> str:
    # ISO-8601 in UTC, so sorting the keys sorts them chronologically.
    stamp = moment.strftime("%Y%m%dT%H%M%SZ")
    return f"{PREFIX}/{BANK}/bank-{stamp}.zip" if PREFIX else f"{BANK}/bank-{stamp}.zip"


def existing(s3) -> list[dict]:
    prefix = f"{PREFIX}/{BANK}/" if PREFIX else f"{BANK}/"
    out: list[dict] = []
    token = None
    while True:
        kwargs = {"Bucket": BUCKET, "Prefix": prefix}
        if token:
            kwargs["ContinuationToken"] = token
        page = s3.list_objects_v2(**kwargs)
        out.extend(page.get("Contents") or [])
        if not page.get("IsTruncated"):
            break
        token = page.get("NextContinuationToken")
    return sorted(out, key=lambda o: o["Key"])


def ensure_bucket(s3) -> None:
    """Create the bucket if it is not there yet, so a fresh test endpoint works out of the box."""
    try:
        s3.head_bucket(Bucket=BUCKET)
    except Exception:
        try:
            s3.create_bucket(Bucket=BUCKET)
            log(f"created bucket '{BUCKET}'")
        except Exception as exc:  # noqa: BLE001 -- report why, do not guess
            fail(f"bucket '{BUCKET}' is not reachable and could not be created: {exc}")


def export(bank: str, destination: str) -> None:
    cmd = [ADMIN, "export-bank", "--bank", bank, "--output", destination]
    log(f"exporting bank '{bank}'")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip().splitlines()[-3:]
        fail("export-bank failed: " + " / ".join(tail))
    if not os.path.exists(destination) or os.path.getsize(destination) == 0:
        fail("export-bank reported success but produced no archive")


def prune(s3, keep: int) -> None:
    objects = existing(s3)
    surplus = objects[:-keep] if keep > 0 and len(objects) > keep else []
    for obj in surplus:
        s3.delete_object(Bucket=BUCKET, Key=obj["Key"])
        log(f"pruned {obj['Key']}")
    if surplus:
        log(f"kept the newest {keep}")


def do_backup(s3) -> None:
    ensure_bucket(s3)
    with tempfile.TemporaryDirectory() as workdir:
        archive = os.path.join(workdir, f"bank-{BANK}.zip")
        export(BANK, archive)
        size = os.path.getsize(archive)
        key = key_for(datetime.now(timezone.utc))
        log(f"uploading {size / 1024 / 1024:.1f} MiB to s3://{BUCKET}/{key}")
        s3.upload_file(archive, BUCKET, key)
    prune(s3, KEEP)
    log(f"done; {len(existing(s3))} archive(s) in the bucket")


def cmd_once() -> None:
    do_backup(client())


def cmd_loop() -> None:
    log(f"bank '{BANK}' -> s3://{BUCKET}/{PREFIX or ''} every {INTERVAL}s, keeping {KEEP}")
    s3 = client()
    while True:
        try:
            do_backup(s3)
        except SystemExit:
            raise
        except Exception as exc:  # noqa: BLE001 -- a backup loop must survive one bad night
            log(f"backup failed, will retry next interval: {exc}")
        time.sleep(INTERVAL)


def cmd_list() -> None:
    s3 = client()
    ensure_bucket(s3)
    objects = existing(s3)
    if not objects:
        log(f"no archives for bank '{BANK}' in s3://{BUCKET}")
        return
    for obj in objects:
        stamp = obj["LastModified"].strftime("%Y-%m-%d %H:%M:%SZ")
        log(f"{stamp}  {obj['Size'] / 1024 / 1024:7.1f} MiB  {obj['Key']}")


def cmd_restore(key: str | None, target_bank: str) -> None:
    s3 = client()
    objects = existing(s3)
    if not objects:
        fail(f"no archives for bank '{BANK}' in s3://{BUCKET}: nothing to restore")
    chosen = next((o for o in objects if o["Key"] == key), None) if key else objects[-1]
    if chosen is None:
        fail(f"no archive with key '{key}'")

    log(f"downloading {chosen['Key']} ({chosen['Size'] / 1024 / 1024:.1f} MiB)")
    with tempfile.TemporaryDirectory() as workdir:
        archive = os.path.join(workdir, "restore.zip")
        s3.download_file(BUCKET, chosen["Key"], archive)
        log(f"importing into bank '{target_bank}' (this re-embeds every memory: it takes minutes)")
        result = subprocess.run(
            [ADMIN, "import-bank", "--archive", archive, "--target-bank", target_bank],
            capture_output=True,
            text=True,
        )
        print(result.stdout, end="")
        if result.returncode != 0:
            tail = (result.stderr or "").strip().splitlines()[-5:]
            print("\n".join(tail), file=sys.stderr)
            if any("already exist" in line.lower() for line in tail):
                fail(
                    f"bank '{target_bank}' already exists, so nothing was imported. That is the "
                    "tool refusing to overwrite a live bank -- drop it first if you really mean to."
                )
            fail("import-bank failed")
    log(f"restored into bank '{target_bank}'")


def main() -> None:
    parser = argparse.ArgumentParser(description="Back up and restore a Hindsight bank via S3")
    parser.add_argument("mode", choices=["once", "loop", "list", "restore"], nargs="?", default="loop")
    parser.add_argument("--key", help="restore: exact object key instead of the newest")
    parser.add_argument("--target-bank", help="restore: bank to import into (default: BUCKET's bank)")
    args = parser.parse_args()

    if args.mode == "once":
        cmd_once()
    elif args.mode == "list":
        cmd_list()
    elif args.mode == "restore":
        cmd_restore(args.key, args.target_bank or BANK)
    else:
        cmd_loop()


if __name__ == "__main__":
    main()
