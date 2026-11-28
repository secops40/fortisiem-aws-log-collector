#!/usr/bin/env python3

import argparse
import gzip
import hashlib
import io
import json
import logging
import os
import re
import signal
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path, PurePosixPath
from urllib.parse import unquote_plus, urlparse
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError


LOG = logging.getLogger("aws-log-collector")
STOP = threading.Event()

BASE_DIR = "/usr/local/fortisiem-aws-log-collector"
DEFAULT_RAW_DIR = f"{BASE_DIR}/logs/raw"
DEFAULT_OUTPUT_DIR = f"{BASE_DIR}/logs/processed"
DEFAULT_STATE_DB = f"{BASE_DIR}/logs/state.db"
DEFAULT_VISIBILITY_TIMEOUT = 300
DEFAULT_VISIBILITY_HEARTBEAT = 120
DEFAULT_WAIT_TIME = 20
DEFAULT_MAX_MESSAGES = 5
DEFAULT_WORKERS = 1
MAX_WORKERS = 32
DEFAULT_RETENTION_DAYS = 7
COPY_CHUNK_SIZE = 1024 * 1024
_CLEANUP_INTERVAL = 3600
SECURITY_HUB_LOG_KEYWORD = "AWS_SECURITY_HUB_EVENT_DATA"
# log_keyword values starting with this prefix enable CloudTrail Records splitting.
CLOUDTRAIL_LOG_KEYWORD_PREFIX = "AWS_S3_LOG_CLOUDTRAIL"
# process_mode: full = prefix/split + gzip (default); raw = download as-is;
# raw_gz = download as-is but guarantee gzip (plain text is compressed whole).
PROCESS_MODES = ("full", "raw", "raw_gz")
DEFAULT_PROCESS_MODE = "full"


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(threadName)s] %(message)s",
    )


def _validate_workers(value: object, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_WORKERS:
        raise ValueError(f"{name} must be an integer between 1 and {MAX_WORKERS}")


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    if isinstance(cfg, list):
        cfg = {"collectors": cfg}

    collectors = cfg.get("collectors")
    if not isinstance(collectors, list) or not collectors:
        raise ValueError("config must contain a non-empty 'collectors' list")

    for i, item in enumerate(collectors):
        # v7 renamed "logmark" to "log_keyword". Keep the old field as a
        # compatibility fallback so an existing v6 config does not break during
        # upgrade. New configurations should use only "log_keyword".
        if not item.get("log_keyword") and item.get("logmark"):
            item["log_keyword"] = item["logmark"]

        mode = item.get("process_mode", cfg.get("process_mode", DEFAULT_PROCESS_MODE))
        if mode not in PROCESS_MODES:
            raise ValueError(
                f"collectors[{i}].process_mode must be one of {list(PROCESS_MODES)}"
            )

        # The FortiSIEM prefix fields are only used in full mode.
        required = ["log", "sqs"]
        if mode == "full":
            required += ["log_keyword", "phCustId", "reptDevIpAddr", "reptDevName"]
        for key in required:
            if item.get(key) is None or str(item.get(key)).strip() == "":
                raise ValueError(f"collectors[{i}] missing required field: {key}")

        if "preserve_s3_path" in item and not isinstance(item["preserve_s3_path"], bool):
            raise ValueError(
                f"collectors[{i}].preserve_s3_path must be true or false"
            )

        if "write_raw_logs" in item and not isinstance(item["write_raw_logs"], bool):
            raise ValueError(
                f"collectors[{i}].write_raw_logs must be true or false"
            )

        if "s3_key_include_regex" in item:
            pattern = item["s3_key_include_regex"]
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError(
                    f"collectors[{i}].s3_key_include_regex must be a non-empty string"
                )
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(
                    f"collectors[{i}].s3_key_include_regex is not a valid regex: {exc}"
                )

        if "workers" in item:
            _validate_workers(item["workers"], f"collectors[{i}].workers")

        access_key = item.get("aws_access_key_id")
        secret_key = item.get("aws_secret_access_key")
        if bool(access_key) != bool(secret_key):
            raise ValueError(
                f"collectors[{i}] must provide both aws_access_key_id "
                "and aws_secret_access_key, or neither"
            )

    if "workers" in cfg:
        _validate_workers(cfg["workers"], "workers")
    if cfg.get("process_mode", DEFAULT_PROCESS_MODE) not in PROCESS_MODES:
        raise ValueError(f"process_mode must be one of {list(PROCESS_MODES)}")
    if "write_raw_logs" in cfg and not isinstance(cfg["write_raw_logs"], bool):
        raise ValueError("write_raw_logs must be true or false")
    if "preserve_s3_path" in cfg and not isinstance(cfg["preserve_s3_path"], bool):
        raise ValueError("preserve_s3_path must be true or false")

    return cfg


def build_aws_session(collector_cfg: dict) -> boto3.Session:
    """Create an AWS session for one collector.

    Credentials are intentionally scoped per collector so different log sources
    may use different AWS accounts. If no explicit key is configured, boto3's
    normal credential provider chain is used.
    """
    access_key = collector_cfg.get("aws_access_key_id")
    secret_key = collector_cfg.get("aws_secret_access_key")
    session_token = collector_cfg.get("aws_session_token")

    if access_key and secret_key:
        return boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token or None,
        )

    return boto3.Session()


def derive_region_from_queue_url(queue_url: str) -> Optional[str]:
    host = urlparse(queue_url).hostname or ""

    # Current format: sqs.ap-northeast-1.amazonaws.com
    m = re.match(r"^sqs[.-]([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$", host)
    if m:
        return m.group(1)

    # Legacy format: ap-northeast-1.queue.amazonaws.com
    m = re.match(r"^([a-z0-9-]+)\.queue\.amazonaws\.com(?:\.cn)?$", host)
    if m:
        return m.group(1)

    return None


def safe_object_path(output_root: Path, log_name: str, bucket: str, key: str) -> Path:
    # S3 object keys are not filesystem paths. Reject path traversal.
    p = PurePosixPath(key)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError(f"unsafe S3 object key: {key!r}")

    return output_root / log_name / bucket / Path(*p.parts)


def sanitize_filename_component(value: str) -> str:
    """Make a short config value safe for use as one filename component."""
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    value = value.strip("._")
    return value or "log"


def flattened_output_path(
    output_root: Path,
    log_name: str,
    key: str,
    bucket: str,
    db: sqlite3.Connection,
) -> Path:
    """Return <output_root>/<log>_<source-basename> for flat mode.

    If this (bucket, object_key) was processed before, the stored output_path
    is returned so the result is idempotent across re-deliveries with different
    event metadata (e.g. different sequencer values).
    """
    basename = PurePosixPath(key).name
    if not basename:
        raise ValueError(f"S3 object key has no filename: {key!r}")

    row = db.execute(
        "SELECT output_path FROM processed_objects WHERE bucket = ? AND object_key = ? LIMIT 1",
        (bucket, key),
    ).fetchone()

    if row is not None:
        return Path(row[0])

    prefix = sanitize_filename_component(log_name)
    return output_root / f"{prefix}_{basename}"


def init_db(db_path: str) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(path, timeout=30) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS processed_objects (
                event_id TEXT PRIMARY KEY,
                log_name TEXT NOT NULL,
                bucket TEXT NOT NULL,
                object_key TEXT NOT NULL,
                version_id TEXT,
                etag TEXT,
                sequencer TEXT,
                output_path TEXT NOT NULL,
                processed_at INTEGER NOT NULL
            )
            """
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_bucket_key ON processed_objects (bucket, object_key)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_processed_at ON processed_objects (processed_at)"
        )
        db.commit()


def make_event_id(log_name: str, queue_url: str, bucket: str, key: str,
                  version_id: Optional[str], etag: Optional[str],
                  sequencer: Optional[str],
                  event_name: Optional[str] = None) -> str:
    # event_id 綁定 collector 身分（log_name + queue_url），避免同一 S3 物件
    # 扇出到多條 collector 時，因共用 state_db 而互相 dedup 誤判 skip。
    raw = "\x1f".join([
        log_name,
        queue_url,
        bucket,
        key,
        version_id or "",
        etag or "",
        sequencer or "",
        event_name or "",
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def is_processed(db: sqlite3.Connection, event_id: str) -> bool:
    row = db.execute(
        "SELECT 1 FROM processed_objects WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    return row is not None


def mark_processed(
    db: sqlite3.Connection,
    event_id: str,
    log_name: str,
    bucket: str,
    key: str,
    version_id: Optional[str],
    etag: Optional[str],
    sequencer: Optional[str],
    output_path: str,
) -> None:
    db.execute(
        """
        INSERT OR IGNORE INTO processed_objects
        (event_id, log_name, bucket, object_key, version_id, etag, sequencer,
         output_path, processed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            log_name,
            bucket,
            key,
            version_id,
            etag,
            sequencer,
            output_path,
            int(time.time()),
        ),
    )
    db.commit()


def cleanup_old_records(db_path: str, retention_days: int) -> None:
    cutoff = int(time.time()) - retention_days * 86400
    with sqlite3.connect(db_path, timeout=30) as db:
        db.execute(
            "DELETE FROM processed_objects WHERE processed_at < ?",
            (cutoff,),
        )
        db.commit()


def _is_s3_event_payload(payload: object) -> bool:
    """Return True for an S3 event notification payload or S3 test event."""
    if not isinstance(payload, dict):
        return False

    if payload.get("Event") == "s3:TestEvent":
        return True

    records = payload.get("Records")
    if not isinstance(records, list):
        return False

    # Empty Records is still structurally an S3 event payload.  For non-empty
    # messages, require at least one aws:s3 record so arbitrary JSON containing
    # a Records field is not accidentally accepted.
    if not records:
        return True

    return any(
        isinstance(record, dict) and record.get("eventSource") == "aws:s3"
        for record in records
    )


def unwrap_sqs_body(body: str) -> Tuple[dict, str]:
    """Detect and unwrap supported SQS message formats.

    Returns (s3_payload, detected_format).

    Supported formats:
      * S3 -> SQS
      * S3 -> SNS -> SQS
      * S3 -> SNS (Raw Message Delivery) -> SQS (same body shape as S3 -> SQS)
    """
    outer = json.loads(body)
    if not isinstance(outer, dict):
        raise ValueError("SQS body is not a JSON object")

    # Direct S3 notification, or SNS Raw Message Delivery where the SNS
    # envelope has already been stripped before SQS receives the message.
    if _is_s3_event_payload(outer):
        return outer, "S3 -> SQS (or SNS Raw Message Delivery)"

    # Normal SNS subscription delivery.  Require the SNS notification shape
    # instead of accepting any arbitrary JSON object with a Message field.
    if outer.get("Type") == "Notification" and "Message" in outer:
        msg = outer["Message"]
        if isinstance(msg, str):
            inner = json.loads(msg)
        elif isinstance(msg, dict):
            inner = msg
        else:
            raise ValueError("SNS Notification Message is not JSON text/object")

        if not _is_s3_event_payload(inner):
            raise ValueError("SNS Notification does not contain an S3 event payload")

        return inner, "S3 -> SNS -> SQS"

    raise ValueError(
        "unsupported SQS body format: expected direct S3 event or SNS Notification containing S3 event"
    )


def extract_s3_records(payload: dict) -> List[dict]:
    # S3 sends a special test event during some notification setups.
    if payload.get("Event") == "s3:TestEvent":
        return []

    records = payload.get("Records")
    if not isinstance(records, list):
        raise ValueError("message does not contain S3 Records")

    result = []
    for record in records:
        if not isinstance(record, dict):
            continue

        event_source = record.get("eventSource")
        event_name = record.get("eventName", "")
        if event_source != "aws:s3" or not event_name.startswith("ObjectCreated:"):
            LOG.info("Ignoring non-ObjectCreated S3 event: %s", event_name)
            continue

        s3 = record.get("s3") or {}
        bucket = (s3.get("bucket") or {}).get("name")
        obj = s3.get("object") or {}
        encoded_key = obj.get("key")

        if not bucket or encoded_key is None:
            raise ValueError("S3 record missing bucket or object key")

        result.append({
            "bucket": bucket,
            "key": unquote_plus(encoded_key),
            "version_id": obj.get("versionId"),
            "etag": obj.get("eTag"),
            "sequencer": obj.get("sequencer"),
            "region": record.get("awsRegion"),
            "event_name": event_name,
        })

    return result


class VisibilityExtender:
    def __init__(
        self,
        sqs,
        queue_url: str,
        receipt_handle: str,
        visibility_timeout: int,
        heartbeat: int,
    ):
        self.sqs = sqs
        self.queue_url = queue_url
        self.receipt_handle = receipt_handle
        self.visibility_timeout = visibility_timeout
        self.heartbeat = heartbeat
        self._stop = threading.Event()
        self._thread = None

    def __enter__(self):
        if self.heartbeat > 0:
            self._thread = threading.Thread(
                target=self._run,
                name="visibility-extender",
                daemon=True,
            )
            self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self):
        while not self._stop.wait(self.heartbeat):
            try:
                self.sqs.change_message_visibility(
                    QueueUrl=self.queue_url,
                    ReceiptHandle=self.receipt_handle,
                    VisibilityTimeout=self.visibility_timeout,
                )
                LOG.debug("Extended SQS visibility timeout")
            except Exception:
                LOG.exception("Failed to extend SQS visibility timeout")


def download_s3_object(
    s3_client,
    bucket: str,
    key: str,
    version_id: Optional[str],
    raw_path: Path,
) -> None:
    """Download the original S3 object to raw_path using an atomic rename."""
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=f".{raw_path.name}.",
        suffix=".tmp",
        dir=str(raw_path.parent),
    )
    os.close(tmp_fd)

    get_args = {"Bucket": bucket, "Key": key}
    if version_id:
        get_args["VersionId"] = version_id

    try:
        response = s3_client.get_object(**get_args)
        body = response["Body"]
        with body, open(tmp_name, "wb") as dst:
            while True:
                chunk = body.read(COPY_CHUNK_SIZE)
                if not chunk:
                    break
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(tmp_name, raw_path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def download_s3_object_gz(
    s3_client,
    bucket: str,
    key: str,
    version_id: Optional[str],
    output_path: Path,
) -> None:
    """Download an S3 object unchanged, guaranteeing gzip output.

    gzip input is stored byte-for-byte; anything else is compressed whole.
    Content is never modified. Uses an atomic rename.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=str(output_path.parent),
    )
    os.close(tmp_fd)

    get_args = {"Bucket": bucket, "Key": key}
    if version_id:
        get_args["VersionId"] = version_id

    body = None
    try:
        body = s3_client.get_object(**get_args)["Body"]
        src = io.BufferedReader(_RawReader(body))
        already_gzip = src.peek(2)[:2] == GZIP_MAGIC
        with open(tmp_name, "wb") as dst:
            out = dst if already_gzip else gzip.GzipFile(fileobj=dst, mode="wb")
            try:
                while True:
                    chunk = src.read(COPY_CHUNK_SIZE)
                    if not chunk:
                        break
                    out.write(chunk)
            finally:
                if not already_gzip:
                    out.close()
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(tmp_name, output_path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
    finally:
        if body is not None:
            body.close()


def build_log_prefix(
    log_keyword: str,
    ph_cust_id: str,
    rept_dev_ip_addr: str,
    rept_dev_name: str,
) -> bytes:
    """Build the FortiSIEM prefix prepended to every source log line."""
    return (
        f"{log_keyword}:"
        f"phCustId={ph_cust_id},"
        f"reptDevIpAddr={rept_dev_ip_addr},"
        f"reptDevName={rept_dev_name},"
        "msg="
    ).encode("utf-8")


GZIP_MAGIC = b"\x1f\x8b"


class _RawReader(io.RawIOBase):
    """Adapt any object with read(n) (e.g. botocore StreamingBody) to a raw
    stream so it can be wrapped in io.BufferedReader (which gives us peek())."""

    def __init__(self, src):
        self._src = src

    def readable(self):
        return True

    def readinto(self, b):
        data = self._src.read(len(b))
        n = len(data)
        b[:n] = data
        return n


def open_maybe_gzip(binary_stream):
    """Return a binary stream, transparently gunzipping when needed.

    Compression is detected from the gzip magic bytes, NOT from the file name,
    because Firehose -> S3 objects usually have no extension at all
    (e.g. <delivery-stream-name>-1-YYYY-MM-DD-HH-MM-SS-<uuid>) and may be plain
    text, JSON, or gzip. Lines can be iterated directly from the returned stream.
    """
    buffered = io.BufferedReader(_RawReader(binary_stream))
    if buffered.peek(2)[:2] == GZIP_MAGIC:
        return gzip.GzipFile(fileobj=buffered, mode="rb")
    return buffered


def open_securityhub_text(binary_stream):
    """Return a UTF-8 text stream for a Security Hub object (plain or gzip)."""
    return io.TextIOWrapper(
        open_maybe_gzip(binary_stream), encoding="utf-8", errors="strict"
    )


def write_transformed_gzip(
    source_lines,
    prefix: bytes,
    output_path: Path,
) -> None:
    """Write prefixed source lines to output_path as gzip using atomic rename."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=str(output_path.parent),
    )
    os.close(tmp_fd)

    try:
        with open(tmp_name, "wb") as raw_out:
            with gzip.GzipFile(fileobj=raw_out, mode="wb") as gz_out:
                for line in source_lines:
                    # Normalise CRLF (Windows) / missing final newline, and
                    # never emit a prefix-only event for blank lines.
                    line = line.rstrip(b"\r\n")
                    if not line:
                        continue
                    gz_out.write(prefix)
                    gz_out.write(line)
                    gz_out.write(b"\n")
            raw_out.flush()
            os.fsync(raw_out.fileno())
        os.replace(tmp_name, output_path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def iter_cloudtrail_lines(gz_in):
    """Yield one compact JSON line (bytes) per entry of CloudTrail "Records"."""
    try:
        doc = json.load(io.TextIOWrapper(gz_in, encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"CloudTrail object is not valid JSON: {exc}") from exc

    if not isinstance(doc, dict) or not isinstance(doc.get("Records"), list):
        raise ValueError("CloudTrail object has no 'Records' array")

    records = doc["Records"]
    LOG.info("CloudTrail: splitting %d record(s)", len(records))
    for record in records:
        yield (
            json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")


def source_lines_for(gz_in, log_keyword: str):
    """Return the line iterator to prefix: split Records for CloudTrail, else raw lines."""
    if log_keyword.startswith(CLOUDTRAIL_LOG_KEYWORD_PREFIX):
        return iter_cloudtrail_lines(gz_in)
    return gz_in


def transform_gzip_file(
    raw_path: Path,
    log_keyword: str,
    ph_cust_id: str,
    rept_dev_ip_addr: str,
    rept_dev_name: str,
    output_path: Path,
) -> None:
    """Transform a persisted raw .gz file into a FortiSIEM-ready .gz file."""
    prefix = build_log_prefix(
        log_keyword=log_keyword,
        ph_cust_id=ph_cust_id,
        rept_dev_ip_addr=rept_dev_ip_addr,
        rept_dev_name=rept_dev_name,
    )

    with open(raw_path, "rb") as raw_in:
        src = open_maybe_gzip(raw_in)
        write_transformed_gzip(
            source_lines_for(src, log_keyword), prefix, output_path
        )


def transform_s3_gzip_object(
    s3_client,
    bucket: str,
    key: str,
    version_id: Optional[str],
    log_keyword: str,
    ph_cust_id: str,
    rept_dev_ip_addr: str,
    rept_dev_name: str,
    output_path: Path,
) -> None:
    """Stream a gzip or plain-text object from S3 directly into the processed gzip output.

    This path is used when write_raw_logs=false. The original S3 object is not
    persisted under logs/raw; only the processed output is written locally.
    """
    get_args = {"Bucket": bucket, "Key": key}
    if version_id:
        get_args["VersionId"] = version_id

    prefix = build_log_prefix(
        log_keyword=log_keyword,
        ph_cust_id=ph_cust_id,
        rept_dev_ip_addr=rept_dev_ip_addr,
        rept_dev_name=rept_dev_name,
    )

    response = s3_client.get_object(**get_args)
    body = response["Body"]
    try:
        src = open_maybe_gzip(body)
        write_transformed_gzip(
            source_lines_for(src, log_keyword), prefix, output_path
        )
    finally:
        body.close()


def iter_json_objects(text_stream):
    """Yield concatenated JSON objects from a text stream.

    Supports input such as:
        {"event1"}{"event2"}{"event3"}

    Whitespace/newlines between JSON objects are allowed. The stream is read
    incrementally so the whole S3 object does not need to be loaded into memory.
    """
    decoder = json.JSONDecoder()
    buffer = ""
    eof = False

    while True:
        if not eof:
            chunk = text_stream.read(COPY_CHUNK_SIZE)
            if chunk:
                buffer += chunk
            else:
                eof = True

        consumed_any = False
        pos = 0
        while pos < len(buffer):
            # Skip inter-object whitespace.
            while pos < len(buffer) and buffer[pos].isspace():
                pos += 1
            if pos >= len(buffer):
                break

            try:
                obj, end = decoder.raw_decode(buffer, pos)
            except json.JSONDecodeError as exc:
                if not eof:
                    # The JSON object may be split across the next chunk;
                    # carry the unconsumed remainder (from pos) forward.
                    break
                raise ValueError(
                    f"Invalid concatenated JSON at stream offset: {exc}"
                ) from exc

            yield obj
            pos = end
            consumed_any = True

        # Drop the consumed prefix once per chunk (integer cursor) instead of
        # re-slicing the buffer after every decoded object (was O(n^2)).
        buffer = buffer[pos:]

        if eof:
            if buffer.strip():
                raise ValueError("Unexpected trailing data after JSON objects")
            break

        # If the current buffer did not contain a complete JSON object, read
        # another chunk. If it did, the inner loop already consumed it.
        if not consumed_any and not buffer:
            continue


def iter_securityhub_findings(text_stream):
    """Yield one Security Hub finding dict per event.findings entry."""
    event_count = 0
    finding_count = 0

    for event_count, event in enumerate(iter_json_objects(text_stream), start=1):
        if not isinstance(event, dict):
            raise ValueError(
                f"Security Hub event {event_count} is not a JSON object"
            )

        detail = event.get("detail") or {}
        if not isinstance(detail, dict):
            raise ValueError(
                f"Security Hub event {event_count} has invalid detail object"
            )

        findings = detail.get("findings", [])
        if findings is None:
            findings = []
        if not isinstance(findings, list):
            raise ValueError(
                f"Security Hub event {event_count} has invalid detail.findings"
            )

        LOG.info(
            "Security Hub event %d: found %d finding(s)",
            event_count,
            len(findings),
        )

        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError(
                    f"Security Hub event {event_count} contains a non-object finding"
                )
            finding_count += 1
            yield finding

    LOG.info(
        "Security Hub JSON processing completed: events=%d findings=%d",
        event_count,
        finding_count,
    )


def write_securityhub_gzip(
    text_stream,
    output_path: Path,
) -> int:
    """Extract Security Hub findings and write one finding per gzip line."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=str(output_path.parent),
    )
    os.close(tmp_fd)

    finding_count = 0
    try:
        with open(tmp_name, "wb") as raw_out:
            with gzip.GzipFile(fileobj=raw_out, mode="wb") as gz_out:
                for finding in iter_securityhub_findings(text_stream):
                    line = (
                        "[AWS_SECURITY_HUB_EVENT_DATA] = "
                        + json.dumps(finding, ensure_ascii=False)
                        + "\n"
                    ).encode("utf-8")
                    gz_out.write(line)
                    finding_count += 1
            raw_out.flush()
            os.fsync(raw_out.fileno())
        os.replace(tmp_name, output_path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise

    return finding_count


def transform_securityhub_file(
    raw_path: Path,
    output_path: Path,
) -> int:
    """Process a persisted Security Hub raw file (plain or gzip JSON, any name)."""
    with open(raw_path, "rb") as binary_stream:
        text_stream = open_securityhub_text(binary_stream)
        return write_securityhub_gzip(text_stream, output_path)


def transform_s3_securityhub_object(
    s3_client,
    bucket: str,
    key: str,
    version_id: Optional[str],
    output_path: Path,
) -> int:
    """Stream a Security Hub object (plain or gzip JSON, any name) from S3."""
    get_args = {"Bucket": bucket, "Key": key}
    if version_id:
        get_args["VersionId"] = version_id

    response = s3_client.get_object(**get_args)
    body = response["Body"]
    try:
        text_stream = open_securityhub_text(body)
        return write_securityhub_gzip(text_stream, output_path)
    finally:
        body.close()


def gzip_output_key(key: str) -> str:
    """Return an output filename key whose content is always gzip-compressed.

    Output is always gzip. Keys already ending in .gz are kept; anything else
    (.json, or no extension at all as with Firehose) gets ".gz" appended.
    """
    if key.lower().endswith(".gz"):
        return key
    return key + ".gz"


# Backward-compatible name.
securityhub_output_key = gzip_output_key


def process_message(
    collector_cfg: dict,
    global_cfg: dict,
    aws_session: boto3.Session,
    message: dict,
    db: sqlite3.Connection,
) -> bool:
    """Process one SQS message; on failure log which S3 object was being handled."""
    progress: Dict[str, Any] = {}
    try:
        return _process_records(
            collector_cfg, global_cfg, aws_session, message, db, progress
        )
    except Exception as exc:
        LOG.error(
            "Processing failed: log=%s object=%s error=%s: %s",
            collector_cfg.get("log"),
            progress.get("uri", "<unknown: failed before S3 record was parsed>"),
            type(exc).__name__,
            exc,
        )
        raise


def _process_records(
    collector_cfg: dict,
    global_cfg: dict,
    aws_session: boto3.Session,
    message: dict,
    db: sqlite3.Connection,
    progress: Dict[str, Any],
) -> bool:
    log_name = collector_cfg["log"]
    queue_url = collector_cfg["sqs"]
    process_mode = collector_cfg.get(
        "process_mode", global_cfg.get("process_mode", DEFAULT_PROCESS_MODE)
    )
    # Prefix fields are not required (and may be absent) in raw/raw_gz mode.
    log_keyword = str(collector_cfg.get("log_keyword", ""))
    ph_cust_id = str(collector_cfg.get("phCustId", ""))
    rept_dev_ip_addr = str(collector_cfg.get("reptDevIpAddr", ""))
    rept_dev_name = str(collector_cfg.get("reptDevName", ""))
    preserve_s3_path = bool(
        collector_cfg.get(
            "preserve_s3_path",
            global_cfg.get("preserve_s3_path", False),
        )
    )

    write_raw_logs = bool(
        collector_cfg.get(
            "write_raw_logs",
            global_cfg.get("write_raw_logs", False),
        )
    )

    raw_root = Path(
        collector_cfg.get(
            "raw_dir",
            global_cfg.get("raw_dir", DEFAULT_RAW_DIR),
        )
    )
    output_root = Path(
        collector_cfg.get(
            "output_dir",
            global_cfg.get("output_dir", DEFAULT_OUTPUT_DIR),
        )
    )
    key_include_regex = collector_cfg.get("s3_key_include_regex")
    key_include = re.compile(key_include_regex) if key_include_regex else None
    try:
        payload, detected_format = unwrap_sqs_body(message["Body"])
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"cannot parse SQS body ({exc}); body[:300]={str(message.get('Body'))[:300]!r}"
        ) from exc
    LOG.info("Detected message format: %s", detected_format)
    records = extract_s3_records(payload)

    if not records:
        LOG.info("No processable S3 ObjectCreated records; message considered handled")
        return True

    s3_clients: Dict[Optional[str], Any] = {}

    for rec in records:
        bucket = rec["bucket"]
        key = rec["key"]
        version_id = rec["version_id"]
        etag = rec["etag"]
        sequencer = rec["sequencer"]
        event_region = rec["region"]
        event_name = rec.get("event_name")
        progress["uri"] = f"s3://{bucket}/{key}"

        # Optional allow-list: objects whose key does not match are skipped and
        # treated as handled (no error, so the SQS message is deleted).
        if key_include is not None and not key_include.search(key):
            LOG.info(
                "Skipped (no match s3_key_include_regex=%r): s3://%s/%s",
                key_include_regex,
                bucket,
                key,
            )
            continue

        event_id = make_event_id(
            log_name, queue_url, bucket, key, version_id, etag, sequencer,
            event_name=event_name,
        )

        if is_processed(db, event_id):
            LOG.info("Duplicate ignored: s3://%s/%s", bucket, key)
            continue

        # Raw files are optional. When enabled they always preserve the original
        # S3 hierarchy. When disabled, the source gzip is streamed from S3
        # directly into the processed output and no raw copy is persisted.
        raw_path = (
            safe_object_path(raw_root, log_name, bucket, key)
            if write_raw_logs and process_mode == "full"
            else None
        )

        is_securityhub = log_keyword == SECURITY_HUB_LOG_KEYWORD

        # Processed output is always gzip. Input may be gzip, plain text or JSON
        # with any (or no) extension, so append .gz unless already present.
        # raw mode keeps the original name untouched.
        output_key = key if process_mode == "raw" else gzip_output_key(key)

        # Processed output may either preserve the S3 hierarchy or be forced
        # into a single flat directory. Flat mode uses <log>_<basename>.
        if preserve_s3_path:
            output_path = safe_object_path(output_root, log_name, bucket, output_key)
        else:
            output_path = flattened_output_path(
                db=db,
                output_root=output_root,
                log_name=log_name,
                key=output_key,
                bucket=bucket,
            )

        client_region = event_region or collector_cfg.get("s3_region")
        if client_region not in s3_clients:
            s3_clients[client_region] = aws_session.client(
                "s3",
                region_name=client_region,
            )
        s3 = s3_clients[client_region]

        if process_mode == "raw":
            LOG.info("Downloading as-is s3://%s/%s -> %s", bucket, key, output_path)
            download_s3_object(
                s3_client=s3,
                bucket=bucket,
                key=key,
                version_id=version_id,
                raw_path=output_path,
            )
        elif process_mode == "raw_gz":
            LOG.info("Downloading as gzip s3://%s/%s -> %s", bucket, key, output_path)
            download_s3_object_gz(
                s3_client=s3,
                bucket=bucket,
                key=key,
                version_id=version_id,
                output_path=output_path,
            )
        elif write_raw_logs:
            LOG.info(
                "Downloading raw s3://%s/%s -> %s",
                bucket,
                key,
                raw_path,
            )
            download_s3_object(
                s3_client=s3,
                bucket=bucket,
                key=key,
                version_id=version_id,
                raw_path=raw_path,
            )

            LOG.info(
                "Transforming raw %s -> %s [log_keyword=%r preserve_s3_path=%s]",
                raw_path,
                output_path,
                log_keyword,
                preserve_s3_path,
            )
            if is_securityhub:
                finding_count = transform_securityhub_file(
                    raw_path=raw_path,
                    output_path=output_path,
                )
                LOG.info("Security Hub output generated: findings=%d", finding_count)
            else:
                transform_gzip_file(
                    raw_path=raw_path,
                    log_keyword=log_keyword,
                    ph_cust_id=ph_cust_id,
                    rept_dev_ip_addr=rept_dev_ip_addr,
                    rept_dev_name=rept_dev_name,
                    output_path=output_path,
                )
        else:
            LOG.info(
                "Processing s3://%s/%s -> %s [raw copy disabled log_keyword=%r preserve_s3_path=%s]",
                bucket,
                key,
                output_path,
                log_keyword,
                preserve_s3_path,
            )
            if is_securityhub:
                finding_count = transform_s3_securityhub_object(
                    s3_client=s3,
                    bucket=bucket,
                    key=key,
                    version_id=version_id,
                    output_path=output_path,
                )
                LOG.info("Security Hub output generated: findings=%d", finding_count)
            else:
                transform_s3_gzip_object(
                    s3_client=s3,
                    bucket=bucket,
                    key=key,
                    version_id=version_id,
                    log_keyword=log_keyword,
                    ph_cust_id=ph_cust_id,
                    rept_dev_ip_addr=rept_dev_ip_addr,
                    rept_dev_name=rept_dev_name,
                    output_path=output_path,
                )

        mark_processed(
            db=db,
            event_id=event_id,
            log_name=log_name,
            bucket=bucket,
            key=output_key,
            version_id=version_id,
            etag=etag,
            sequencer=sequencer,
            output_path=str(output_path),
        )

        LOG.info("Completed: %s", output_path)

    return True


def queue_worker(collector_cfg: dict, global_cfg: dict, worker_idx: int = 0) -> None:
    """Poll one SQS queue. Several of these may run in parallel for the same
    queue (collector "workers"); SQS visibility timeout guarantees each message
    is handed to only one of them at a time. Each thread owns its own boto3
    session/client and SQLite connection. Only worker 0 runs state cleanup."""
    log_name = collector_cfg["log"]
    queue_url = collector_cfg["sqs"]

    region = (
        collector_cfg.get("region")
        or derive_region_from_queue_url(queue_url)
        or global_cfg.get("region")
    )

    aws_session = build_aws_session(collector_cfg)
    sqs = aws_session.client("sqs", region_name=region)

    visibility_timeout = int(
        collector_cfg.get(
            "visibility_timeout",
            global_cfg.get("visibility_timeout", DEFAULT_VISIBILITY_TIMEOUT),
        )
    )
    heartbeat = int(
        collector_cfg.get(
            "visibility_heartbeat",
            global_cfg.get("visibility_heartbeat", DEFAULT_VISIBILITY_HEARTBEAT),
        )
    )
    wait_time = int(
        collector_cfg.get(
            "wait_time_seconds",
            global_cfg.get("wait_time_seconds", DEFAULT_WAIT_TIME),
        )
    )
    max_messages = int(
        collector_cfg.get(
            "max_messages",
            global_cfg.get("max_messages", DEFAULT_MAX_MESSAGES),
        )
    )

    if not 1 <= max_messages <= 10:
        raise ValueError("max_messages must be between 1 and 10")
    if not 0 <= wait_time <= 20:
        raise ValueError("wait_time_seconds must be between 0 and 20")
    if heartbeat >= visibility_timeout:
        raise ValueError("visibility_heartbeat must be less than visibility_timeout")

    db_path = global_cfg.get("state_db", DEFAULT_STATE_DB)
    retention_days = int(global_cfg.get("retention_days", DEFAULT_RETENTION_DAYS))
    last_cleanup = 0.0

    # One connection per worker thread, reused for every record's dedup lookup
    # and mark. Used only within this thread, so check_same_thread is satisfied.
    db = sqlite3.connect(db_path, timeout=30)
    # WAL + synchronous=NORMAL: still crash-safe for the DB file, but avoids an
    # fsync on every per-object commit (dedup state is re-derivable anyway).
    db.execute("PRAGMA synchronous=NORMAL")

    credential_mode = (
        "config" if collector_cfg.get("aws_access_key_id") else "default-chain"
    )
    LOG.info(
        "Starting collector=%s region=%s credentials=%s queue=%s",
        log_name,
        region or "default",
        credential_mode,
        queue_url,
    )

    try:
        while not STOP.is_set():
            now = time.time()
            if worker_idx == 0 and now - last_cleanup >= _CLEANUP_INTERVAL:
                try:
                    cleanup_old_records(db_path, retention_days)
                    LOG.debug("Cleaned up records older than %d days", retention_days)
                except Exception:
                    LOG.exception("Failed to clean up old state records")
                last_cleanup = now

            try:
                response = sqs.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=max_messages,
                    WaitTimeSeconds=wait_time,
                    VisibilityTimeout=visibility_timeout,
                    AttributeNames=["ApproximateReceiveCount"],
                )
            except (BotoCoreError, ClientError):
                LOG.exception("SQS receive failed for %s", log_name)
                STOP.wait(5)
                continue

            messages = response.get("Messages", [])
            if not messages:
                continue

            for message in messages:
                if STOP.is_set():
                    break

                receipt = message["ReceiptHandle"]
                receive_count = (
                    (message.get("Attributes") or {}).get("ApproximateReceiveCount", "?")
                )
                LOG.debug(
                    "Received SQS message id=%s receive_count=%s",
                    message.get("MessageId"),
                    receive_count,
                )

                try:
                    with VisibilityExtender(
                        sqs=sqs,
                        queue_url=queue_url,
                        receipt_handle=receipt,
                        visibility_timeout=visibility_timeout,
                        heartbeat=heartbeat,
                    ):
                        handled = process_message(
                            collector_cfg=collector_cfg,
                            global_cfg=global_cfg,
                            aws_session=aws_session,
                            message=message,
                            db=db,
                        )

                    if handled:
                        sqs.delete_message(
                            QueueUrl=queue_url,
                            ReceiptHandle=receipt,
                        )
                        LOG.debug("Deleted SQS message id=%s", message.get("MessageId"))

                except Exception:
                    # Do not delete. SQS will make the message visible again after
                    # the visibility timeout, or send it to DLQ according to its policy.
                    LOG.exception(
                        "Message processing failed log=%s id=%s receive_count=%s; leaving it in SQS",
                        log_name,
                        message.get("MessageId"),
                        receive_count,
                    )
    finally:
        db.close()


def handle_signal(signum, frame):
    LOG.info("Received signal %s; stopping", signum)
    STOP.set()


def main() -> int:
    parser = argparse.ArgumentParser(description="FortiSIEM AWS S3/SNS/SQS gzip log collector")
    parser.add_argument(
        "-c",
        "--config",
        default=f"{BASE_DIR}/config.json",
        help="config JSON path",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate config and exit",
    )
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
        setup_logging(cfg.get("log_level", "INFO"))

        if args.check_config:
            LOG.info("Configuration OK: %s", args.config)
            return 0

        init_db(cfg.get("state_db", DEFAULT_STATE_DB))

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)

        threads = []
        for collector_cfg in cfg["collectors"]:
            n_workers = int(
                collector_cfg.get("workers", cfg.get("workers", DEFAULT_WORKERS))
            )
            for idx in range(n_workers):
                t = threading.Thread(
                    target=queue_worker,
                    args=(collector_cfg, cfg, idx),
                    name=f"queue-{collector_cfg['log']}-{idx}",
                    daemon=True,
                )
                t.start()
                threads.append(t)

        workers_failed = False
        while not STOP.is_set():
            alive = [t for t in threads if t.is_alive()]
            if len(alive) != len(threads):
                LOG.error("One or more queue workers stopped unexpectedly")
                workers_failed = True
                STOP.set()
                break
            STOP.wait(1)

        for t in threads:
            t.join(timeout=25)

        if workers_failed:
            # Exit non-zero so systemd Restart=on-failure restarts the service
            # instead of treating an unexpected worker death as a clean shutdown.
            LOG.error("Collector stopped due to worker failure")
            return 1

        LOG.info("Collector stopped")
        return 0

    except Exception as exc:
        logging.basicConfig(level=logging.INFO)
        LOG.exception("Fatal error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
