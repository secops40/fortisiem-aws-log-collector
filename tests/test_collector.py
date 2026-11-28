#!/usr/bin/env python3
"""Unit tests for collector.py"""

import gzip
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

import collector
from collector import (
    SECURITY_HUB_LOG_KEYWORD,
    build_log_prefix,
    flattened_output_path,
    init_db,
    is_processed,
    iter_json_objects,
    iter_securityhub_findings,
    make_event_id,
    mark_processed,
    securityhub_output_key,
    write_securityhub_gzip,
    write_transformed_gzip,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _text_stream(data: bytes) -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")


def _sh_event(findings: list) -> bytes:
    """Minimal EventBridge Security Hub event."""
    event = {
        "version": "0",
        "detail-type": "Security Hub Findings - Imported",
        "source": "aws.securityhub",
        "detail": {"findings": findings},
    }
    return json.dumps(event).encode("utf-8")


def _finding(id_suffix: str = "1") -> dict:
    return {
        "SchemaVersion": "2018-10-08",
        "Id": f"arn:aws:securityhub:ap-southeast-1:123456789012:finding/{id_suffix}",
    }


# ---------------------------------------------------------------------------
# TestIterJsonObjects
# ---------------------------------------------------------------------------

class TestIterJsonObjects(unittest.TestCase):

    def _run(self, data: bytes) -> list:
        return list(iter_json_objects(_text_stream(data)))

    def test_single(self):
        obj = {"a": 1}
        self.assertEqual(self._run(json.dumps(obj).encode()), [obj])

    def test_multiple_no_sep(self):
        objs = [{"a": 1}, {"b": 2}, {"c": 3}]
        data = b"".join(json.dumps(o).encode() for o in objs)
        self.assertEqual(self._run(data), objs)

    def test_whitespace_between(self):
        data = b'{"a":1}\n\n{"b":2}\n{"c":3}'
        self.assertEqual(len(self._run(data)), 3)

    def test_empty_stream(self):
        self.assertEqual(self._run(b""), [])

    def test_split_at_chunk_boundary(self):
        obj = {"key": "value_that_is_long_enough_to_span_10_byte_chunks_easily"}
        data = json.dumps(obj).encode()
        original = collector.COPY_CHUNK_SIZE
        try:
            collector.COPY_CHUNK_SIZE = 10
            result = list(iter_json_objects(_text_stream(data)))
        finally:
            collector.COPY_CHUNK_SIZE = original
        self.assertEqual(result, [obj])

    def test_invalid_json_raises(self):
        with self.assertRaises(ValueError):
            self._run(b"not valid json at all !!!")

    def test_trailing_garbage_raises(self):
        with self.assertRaises(ValueError):
            self._run(b'{"a":1}GARBAGE')

    def test_many_small_objects_single_chunk(self):
        """Integer-cursor path: many objects that all land in one chunk."""
        objs = [{"i": n} for n in range(1000)]
        data = b"".join(json.dumps(o).encode() for o in objs)
        original = collector.COPY_CHUNK_SIZE
        try:
            # Bigger than the whole payload so everything is one chunk.
            collector.COPY_CHUNK_SIZE = len(data) + 1
            result = list(iter_json_objects(_text_stream(data)))
        finally:
            collector.COPY_CHUNK_SIZE = original
        self.assertEqual(result, objs)

    def test_object_boundaries_across_chunk_sizes(self):
        """Every chunk size must recover the same object sequence regardless of
        where the split falls inside an object."""
        objs = [{"i": n, "pad": "x" * (n % 7)} for n in range(30)]
        data = b"".join(json.dumps(o).encode() for o in objs)
        original = collector.COPY_CHUNK_SIZE
        try:
            for size in range(1, 41):
                collector.COPY_CHUNK_SIZE = size
                result = list(iter_json_objects(_text_stream(data)))
                self.assertEqual(result, objs, f"mismatch at chunk size {size}")
        finally:
            collector.COPY_CHUNK_SIZE = original


# ---------------------------------------------------------------------------
# TestIterSecurityhubFindings
# ---------------------------------------------------------------------------

class TestIterSecurityhubFindings(unittest.TestCase):

    def _run(self, data: bytes) -> list:
        return list(iter_securityhub_findings(_text_stream(data)))

    def test_single_event_single_finding(self):
        result = self._run(_sh_event([_finding("1")]))
        self.assertEqual(len(result), 1)
        self.assertIn("Id", result[0])

    def test_single_event_multi_findings(self):
        result = self._run(_sh_event([_finding("1"), _finding("2"), _finding("3")]))
        self.assertEqual(len(result), 3)

    def test_multi_events(self):
        data = _sh_event([_finding("1")]) + _sh_event([_finding("2")]) + _sh_event([_finding("3")])
        self.assertEqual(len(self._run(data)), 3)

    def test_empty_findings_array(self):
        self.assertEqual(self._run(_sh_event([])), [])

    def test_empty_stream(self):
        self.assertEqual(self._run(b""), [])

    def test_invalid_findings_type_raises(self):
        event = {
            "detail-type": "Security Hub Findings - Imported",
            "detail": {"findings": "not-a-list"},
        }
        with self.assertRaises(ValueError):
            self._run(json.dumps(event).encode())


# ---------------------------------------------------------------------------
# TestWriteSecurityhubGzip
# ---------------------------------------------------------------------------

class TestWriteSecurityhubGzip(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _stream(self, n: int = 3) -> io.TextIOWrapper:
        return _text_stream(_sh_event([_finding(str(i)) for i in range(n)]))

    def _out(self, name: str = "out.json.gz") -> Path:
        return Path(self.tmpdir) / name

    def test_output_format(self):
        out = self._out()
        write_securityhub_gzip(self._stream(), out)
        with gzip.open(out, "rt", encoding="utf-8") as f:
            for line in f:
                self.assertTrue(
                    line.startswith("[AWS_SECURITY_HUB_EVENT_DATA] = "),
                    f"Bad prefix: {line[:60]!r}",
                )

    def test_returns_correct_count(self):
        out = self._out()
        self.assertEqual(write_securityhub_gzip(self._stream(5), out), 5)

    def test_output_is_valid_gzip(self):
        out = self._out()
        write_securityhub_gzip(self._stream(), out)
        with gzip.open(out, "rb") as f:
            self.assertGreater(len(f.read()), 0)

    def test_finding_is_parseable_json(self):
        out = self._out()
        write_securityhub_gzip(self._stream(1), out)
        prefix = "[AWS_SECURITY_HUB_EVENT_DATA] = "
        with gzip.open(out, "rt", encoding="utf-8") as f:
            for line in f:
                parsed = json.loads(line[len(prefix):].strip())
                self.assertIn("Id", parsed)

    def test_tmp_cleaned_on_failure(self):
        class BrokenStream:
            def read(self, n=-1):
                raise RuntimeError("forced read failure")

        out = self._out()
        with self.assertRaises(Exception):
            write_securityhub_gzip(BrokenStream(), out)

        orphans = list(Path(self.tmpdir).glob("*.tmp"))
        self.assertEqual(orphans, [], f"Orphaned tmp files: {orphans}")


# ---------------------------------------------------------------------------
# TestSecurityhubOutputKey
# ---------------------------------------------------------------------------

class TestSecurityhubOutputKey(unittest.TestCase):

    def test_json_gets_gz_suffix(self):
        self.assertEqual(securityhub_output_key("findings.json"), "findings.json.gz")

    def test_json_gz_unchanged(self):
        self.assertEqual(securityhub_output_key("findings.json.gz"), "findings.json.gz")

    def test_case_insensitive_json(self):
        self.assertEqual(securityhub_output_key("findings.JSON"), "findings.JSON.gz")

    def test_case_insensitive_json_gz(self):
        self.assertEqual(securityhub_output_key("findings.JSON.GZ"), "findings.JSON.GZ")

    def test_preserves_path(self):
        key = "AWSLogs/111122223333/SecurityHub/ap-southeast-1/2026-09-15.json"
        self.assertEqual(securityhub_output_key(key), key + ".gz")

    def test_gz_extension_kept(self):
        self.assertEqual(securityhub_output_key("findings.gz"), "findings.gz")

    def test_no_extension_gets_gz_suffix(self):
        key = "YYYY/MM/DD/HH/my-delivery-stream-1-2026-01-01-00-00-00-0000aaaa"
        self.assertEqual(securityhub_output_key(key), key + ".gz")

    def test_txt_extension_gets_gz_suffix(self):
        self.assertEqual(securityhub_output_key("findings.txt"), "findings.txt.gz")


# ---------------------------------------------------------------------------
# TestNormalLogIsolation
# ---------------------------------------------------------------------------

class TestNormalLogIsolation(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "state.db")
        init_db(self.db_path)
        self.db = sqlite3.connect(self.db_path, timeout=30)
        self.output_root = Path(self.tmpdir) / "processed"
        self.output_root.mkdir()

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # --- FortiSIEM prefix format ---

    def test_build_log_prefix_format(self):
        prefix = build_log_prefix("VPCFlow", "1001", "10.0.0.1", "myhost")
        self.assertIsInstance(prefix, bytes)
        self.assertTrue(prefix.startswith(b"VPCFlow:"))
        self.assertIn(b"phCustId=1001", prefix)
        self.assertIn(b"reptDevIpAddr=10.0.0.1", prefix)
        self.assertIn(b"reptDevName=myhost", prefix)
        self.assertTrue(prefix.endswith(b"msg="))

    def test_write_transformed_gzip_every_line_has_prefix(self):
        prefix = b"VPCFlow:phCustId=1,reptDevIpAddr=10.0.0.1,reptDevName=host,msg="
        source = [b"line1\n", b"line2\n", b"line3\n"]
        out = self.output_root / "vpcflow_test.log.gz"
        write_transformed_gzip(iter(source), prefix, out)

        with gzip.open(out, "rb") as f:
            for line in f:
                self.assertTrue(line.startswith(prefix), f"Missing prefix: {line[:80]!r}")

    # --- Flat output naming ---

    def test_vpcflow_prefix_in_flat_output(self):
        path = flattened_output_path(
            output_root=self.output_root,
            log_name="vpcflow",
            key="AWSLogs/123/vpcflow/us-west-2/2026/01/01/mylog.log.gz",
            bucket="my-bucket",
            db=self.db,
        )
        self.assertTrue(path.name.startswith("vpcflow_"), path.name)

    def test_guardduty_prefix_in_flat_output(self):
        path = flattened_output_path(
            output_root=self.output_root,
            log_name="guardduty",
            key="AWSLogs/123/guardduty/us-east-1/2026/01/01/findings.jsonl.gz",
            bucket="my-bucket",
            db=self.db,
        )
        self.assertTrue(path.name.startswith("guardduty_"), path.name)

    def test_vpcflow_and_guardduty_paths_do_not_collide(self):
        """Same S3 key + different log names → different output paths."""
        same_key = "AWSLogs/123/logs/2026/01/01/data.log.gz"
        vpcflow_path = flattened_output_path(
            output_root=self.output_root,
            log_name="vpcflow",
            key=same_key,
            bucket="my-bucket",
            db=self.db,
        )
        guardduty_path = flattened_output_path(
            output_root=self.output_root,
            log_name="guardduty",
            key=same_key,
            bucket="my-bucket",
            db=self.db,
        )
        self.assertNotEqual(vpcflow_path, guardduty_path)
        self.assertTrue(vpcflow_path.name.startswith("vpcflow_"))
        self.assertTrue(guardduty_path.name.startswith("guardduty_"))

    def test_securityhub_prefix_in_flat_output(self):
        path = flattened_output_path(
            output_root=self.output_root,
            log_name="securityhub",
            key="findings/2026/01/01/x.json.gz",
            bucket="my-bucket",
            db=self.db,
        )
        self.assertTrue(path.name.startswith("securityhub_"), path.name)

    def test_all_three_log_names_do_not_collide(self):
        """三方對稱：同 S3 key 給三種 log_name 產出必須各自獨立前綴、路徑不衝突。"""
        same_key = "shared/2026/01/01/data.log.gz"
        paths = {
            name: flattened_output_path(
                output_root=self.output_root,
                log_name=name,
                key=same_key,
                bucket="my-bucket",
                db=self.db,
            )
            for name in ("vpcflow", "guardduty", "securityhub")
        }
        # 三個路徑兩兩不同
        distinct = {str(p) for p in paths.values()}
        self.assertEqual(len(distinct), 3,
                         f"三個 log_name 產出相同路徑: {paths}")
        # 各自前綴正確
        for name, p in paths.items():
            self.assertTrue(p.name.startswith(f"{name}_"),
                            f"{name} 產出非 {name}_ 前綴: {p.name}")

    # --- Pipeline 端到端契約鎖：log_name → 輸出前綴 ---

    def _run_process_message_with_key(self, log_name: str, log_keyword: str,
                                       key: str) -> None:
        """Helper：跑一次 process_message，攔截兩種 transform，讓其寫最小 gzip
        到 output_path。呼叫端跑完後檢查 output_root。"""
        cfg = {
            "log": log_name,
            "sqs": f"https://sqs.us-west-2.amazonaws.com/1/fsm-{log_name}",
            "log_keyword": log_keyword,
            "phCustId": "1",
            "reptDevIpAddr": "10.0.0.1",
            "reptDevName": "amazon.com",
            "output_dir": str(self.output_root),
            "raw_dir": str(Path(self.tmpdir) / "raw"),
            "write_raw_logs": False,
            "preserve_s3_path": False,
        }
        s3_event = {
            "Records": [{
                "eventSource": "aws:s3",
                "eventName": "ObjectCreated:Put",
                "awsRegion": "us-west-2",
                "s3": {
                    "bucket": {"name": "my-bucket"},
                    "object": {"key": key, "eTag": "e", "sequencer": "s"},
                },
            }]
        }
        message = {"Body": json.dumps(s3_event), "ReceiptHandle": "rh"}
        aws_session = MagicMock()
        aws_session.client.return_value = MagicMock()

        def stub(**kwargs):
            out = Path(kwargs["output_path"])
            out.parent.mkdir(parents=True, exist_ok=True)
            with gzip.open(out, "wb") as f:
                f.write(b"stub\n")

        with patch.object(collector, "transform_s3_gzip_object", side_effect=stub), \
             patch.object(collector, "transform_s3_securityhub_object", side_effect=stub):
            collector.process_message(
                collector_cfg=cfg,
                global_cfg={},
                aws_session=aws_session,
                message=message,
                db=self.db,
            )

    def _assert_output_prefix_isolation(self, expected_prefix: str,
                                        forbidden_prefixes: tuple) -> None:
        outputs = list(self.output_root.rglob("*.gz"))
        self.assertTrue(outputs, "collector 應該至少產出一個檔")
        for p in outputs:
            self.assertTrue(
                p.name.startswith(expected_prefix),
                f"產出檔名非預期前綴 {expected_prefix!r}: {p.name}"
            )
        for other in forbidden_prefixes:
            offenders = [p.name for p in outputs if p.name.startswith(other)]
            self.assertEqual(
                offenders, [],
                f"collector 產出了禁用前綴 {other!r} 檔: {offenders}"
            )

    def test_vpcflow_sqs_produces_vpcflow_output_only(self):
        """契約：vpcflow collector 走完 process_message，產出檔名必為 vpcflow_ 前綴，
        絕不會出現 guardduty_ 或 securityhub_ 前綴檔。"""
        self._run_process_message_with_key(
            log_name="vpcflow",
            log_keyword="AWS_S3_LOG_VPCFLOW-us-west-2",
            key="AWSLogs/1/vpcflowlogs/us-west-2/2026/01/01/data.log.gz",
        )
        self._assert_output_prefix_isolation(
            expected_prefix="vpcflow_",
            forbidden_prefixes=("guardduty_", "securityhub_"),
        )

    def test_guardduty_sqs_produces_guardduty_output_only(self):
        """對稱契約：guardduty collector 產出必為 guardduty_ 前綴。"""
        self._run_process_message_with_key(
            log_name="guardduty",
            log_keyword="AWS_S3_LOG_GUARDDUTY",
            key="AWSLogs/1/GuardDuty/us-west-2/2026/01/01/findings.jsonl.gz",
        )
        self._assert_output_prefix_isolation(
            expected_prefix="guardduty_",
            forbidden_prefixes=("vpcflow_", "securityhub_"),
        )

    def test_securityhub_sqs_produces_securityhub_output_only(self):
        """對稱契約：securityhub collector 產出必為 securityhub_ 前綴。
        SecurityHub 走 transform_s3_securityhub_object 分支，key 需 .json 或 .json.gz。"""
        self._run_process_message_with_key(
            log_name="securityhub",
            log_keyword=SECURITY_HUB_LOG_KEYWORD,
            key="findings/2026/01/01/imported.json.gz",
        )
        self._assert_output_prefix_isolation(
            expected_prefix="securityhub_",
            forbidden_prefixes=("vpcflow_", "guardduty_"),
        )

    # --- Cross-collector dedup isolation ---

    def test_same_object_two_collectors_independent_dedup(self):
        """同一 S3 物件扇出到兩條 collector，dedup 身分必須各自獨立：
        一條標記為已處理，不可害另一條被 skip。
        現行 make_event_id 只用物件身分 → 兩條算出同一 event_id，第二條被誤判已處理。"""
        common = dict(bucket="b", key="AWSLogs/1/GuardDuty/x.jsonl.gz",
                      version_id=None, etag="e", sequencer="s")
        # 修好後：make_event_id 綁定 collector 身分，兩條對同物件算出不同 id
        eid_vpcflow = make_event_id(log_name="vpcflow", queue_url="q-vpc", **common)
        eid_guardduty = make_event_id(log_name="guardduty", queue_url="q-gd", **common)
        # vpcflow 先處理並標記：
        mark_processed(db=self.db, event_id=eid_vpcflow, log_name="vpcflow",
                       bucket=common["bucket"], key=common["key"], version_id=None,
                       etag="e", sequencer="s", output_path="/tmp/vpcflow_x.gz")
        # guardduty 對「自己的物件」必須仍視為未處理：
        self.assertFalse(is_processed(self.db, eid_guardduty),
                         "guardduty 被 vpcflow 的標記誤判為已處理（global event_id 共用）")

    # --- Security Hub isolation ---

    def test_securityhub_output_has_no_fortisiem_prefix(self):
        stream = _text_stream(_sh_event([_finding("1")]))
        out = self.output_root / "securityhub_test.json.gz"
        write_securityhub_gzip(stream, out)

        with gzip.open(out, "rt", encoding="utf-8") as f:
            for line in f:
                self.assertNotIn("phCustId=", line)
                self.assertNotIn("reptDevIpAddr=", line)
                self.assertTrue(line.startswith("[AWS_SECURITY_HUB_EVENT_DATA] = "))

    def test_open_securityhub_text_detects_plain_and_gzip(self):
        import gzip as _gz, io as _io
        from collector import open_securityhub_text
        data = b'{"detail":{"findings":[{"Id":"a"}]}}'
        for raw in (data, _gz.compress(data)):
            self.assertEqual(open_securityhub_text(_io.BytesIO(raw)).read().encode(), data)

    def test_plain_text_and_gzip_objects_get_prefixed_gzip_output(self):
        """Extension-less Firehose objects (plain text, CRLF, blank lines, or gzip)
        are all converted to prefixed gzip lines."""
        import gzip as _gz, io as _io
        from collector import transform_s3_gzip_object

        text = b"line one\r\n\r\nline two\r\nlast line no newline"

        class Body:
            def __init__(self, b): self.b = _io.BytesIO(b)
            def read(self, n=-1): return self.b.read(n)
            def close(self): pass

        class Client:
            def __init__(self, b): self.b = b
            def get_object(self, **k): return {"Body": Body(self.b)}

        for raw in (text, _gz.compress(text)):
            out = self.output_root / "win_test.gz"
            transform_s3_gzip_object(
                Client(raw), "b", "windows/2026/11/23/07/my-delivery-stream-1-x",
                None, "AWS_S3_EC2_WINDOWS", "1", "10.0.0.1", "dev", out,
            )
            with _gz.open(out, "rb") as f:
                lines = f.read().split(b"\n")
            prefix = b"AWS_S3_EC2_WINDOWS:phCustId=1,reptDevIpAddr=10.0.0.1,reptDevName=dev,msg="
            self.assertEqual(
                lines,
                [prefix + b"line one", prefix + b"line two", prefix + b"last line no newline", b""],
            )

    def _run_raw_mode(self, mode: str, payload: bytes, key: str):
        import io as _io
        cfg = {
            "log": "win",
            "sqs": "https://sqs.us-west-2.amazonaws.com/1/fsm-win",
            "process_mode": mode,  # no log_keyword / phCust* fields needed
            "output_dir": str(self.output_root),
            "preserve_s3_path": False,
        }
        event = {"Records": [{
            "eventSource": "aws:s3", "eventName": "ObjectCreated:Put",
            "awsRegion": "us-west-2",
            "s3": {"bucket": {"name": "my-bucket"},
                   "object": {"key": key, "eTag": "e", "sequencer": "s"}},
        }]}

        class Body:
            def __init__(self): self.b = _io.BytesIO(payload)
            def read(self, n=-1): return self.b.read(n)
            def close(self): pass
            def __enter__(self): return self
            def __exit__(self, *a): return False

        s3 = MagicMock()
        s3.get_object.side_effect = lambda **k: {"Body": Body()}
        sess = MagicMock()
        sess.client.return_value = s3
        collector.process_message(
            collector_cfg=cfg, global_cfg={}, aws_session=sess,
            message={"Body": json.dumps(event), "ReceiptHandle": "rh"}, db=self.db,
        )

    def test_raw_mode_keeps_content_and_name(self):
        payload = b"plain\r\ntext\r\n"
        self._run_raw_mode("raw", payload, "windows/2026/11/23/07/my-stream-1-x")
        out = self.output_root / "win_my-stream-1-x"
        self.assertEqual(out.read_bytes(), payload)

    def test_raw_gz_mode_compresses_plain_text_unchanged(self):
        payload = b"plain\r\ntext\r\n"
        self._run_raw_mode("raw_gz", payload, "windows/my-stream-1-x")
        out = self.output_root / "win_my-stream-1-x.gz"
        self.assertEqual(gzip.decompress(out.read_bytes()), payload)

    def test_raw_gz_mode_keeps_gzip_bytes(self):
        payload = gzip.compress(b"hello\n")
        self._run_raw_mode("raw_gz", payload, "windows/my-stream-1-x")
        out = self.output_root / "win_my-stream-1-x.gz"
        self.assertEqual(out.read_bytes(), payload)

    def test_load_config_process_mode(self):
        base = {"log": "a", "sqs": "q"}
        def load(cfg):
            path = Path(self.tmpdir) / "c.json"
            path.write_text(json.dumps(cfg))
            return collector.load_config(str(path))
        load({"collectors": [dict(base, process_mode="raw")]})      # prefix fields not required
        load({"collectors": [dict(base, process_mode="raw_gz")]})
        with self.assertRaises(ValueError):
            load({"collectors": [dict(base)]})                       # full needs prefix fields
        with self.assertRaises(ValueError):
            load({"collectors": [dict(base, process_mode="bogus")]})

    def test_securityhub_constant_value(self):
        self.assertEqual(SECURITY_HUB_LOG_KEYWORD, "AWS_SECURITY_HUB_EVENT_DATA")


if __name__ == "__main__":
    unittest.main()
