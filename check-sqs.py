#!/usr/bin/env python3
"""Read config.json and print the SQS queue depth of every collector as a table."""

import json
import os
import re
import sys
from urllib.parse import urlparse

import boto3
from botocore.exceptions import BotoCoreError, ClientError

DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


def derive_region(queue_url):
    host = urlparse(queue_url).hostname or ""
    m = re.fullmatch(r"sqs[.-]([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?", host)
    if m:
        return m.group(1)
    m = re.fullmatch(r"([a-z0-9-]+)\.queue\.amazonaws\.com(?:\.cn)?", host)
    if m:
        return m.group(1)
    return None


def build_session(collector):
    """Per-collector credentials; fall back to boto3's default chain."""
    key = collector.get("aws_access_key_id")
    secret = collector.get("aws_secret_access_key")
    if key and secret:
        return boto3.Session(
            aws_access_key_id=key,
            aws_secret_access_key=secret,
            aws_session_token=collector.get("aws_session_token") or None,
        )
    return boto3.Session()


def print_table(headers, rows, right_cols=()):
    widths = [max(len(str(r[i])) for r in [headers] + rows) for i in range(len(headers))]
    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"

    def fmt(row):
        cells = []
        for i, v in enumerate(row):
            align = ">" if i in right_cols else "<"
            cells.append("{:{}{}}".format(str(v), align, widths[i]))
        return "| " + " | ".join(cells) + " |"

    print(sep)
    print(fmt(headers))
    print(sep)
    for r in rows:
        print(fmt(r))
    print(sep)


def main():
    if len(sys.argv) > 2:
        print("Usage: python3 check-sqs.py [config.json]")
        sys.exit(1)

    config_path = sys.argv[1] if len(sys.argv) == 2 else DEFAULT_CONFIG

    try:
        with open(config_path, "r") as f:
            cfg = json.load(f)
    except (IOError, ValueError) as e:
        print("Failed to read config: {}".format(e))
        sys.exit(1)

    collectors = cfg.get("collectors")
    if not isinstance(collectors, list) or not collectors:
        print("config must contain a non-empty 'collectors' list")
        sys.exit(1)

    rows = []
    for i, c in enumerate(collectors):
        log = c.get("log", "collector[{}]".format(i))
        queue_url = c.get("sqs", "")
        queue_name = queue_url.rstrip("/").split("/")[-1] if queue_url else "-"
        region = c.get("region") or cfg.get("region") or derive_region(queue_url) or "-"

        try:
            if not queue_url:
                raise ValueError("missing 'sqs' URL")
            if region == "-":
                raise ValueError("cannot determine region")
            sqs = build_session(c).client("sqs", region_name=region)
            attrs = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=[
                    "ApproximateNumberOfMessages",
                    "ApproximateNumberOfMessagesNotVisible",
                ],
            )["Attributes"]
            available = attrs["ApproximateNumberOfMessages"]
            in_flight = attrs["ApproximateNumberOfMessagesNotVisible"]
        except (ClientError, BotoCoreError, ValueError, KeyError) as e:
            available = in_flight = "ERROR"
            print("[ERROR] {}: {}".format(log, e), file=sys.stderr)

        rows.append((log, queue_name, region, available, in_flight))

    print_table(
        ("Log", "Queue Name", "Region", "Messages available", "In flight"),
        rows,
        right_cols=(3, 4),
    )


if __name__ == "__main__":
    main()
