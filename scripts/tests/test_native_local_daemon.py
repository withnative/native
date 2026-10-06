import asyncio
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest


SCRIPT = Path(__file__).parents[1] / "native-local-daemon.py"
spec = importlib.util.spec_from_file_location("native_local_daemon", SCRIPT)
daemon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(daemon)


class FakeWriter:
    def __init__(self, reader):
        self.reader = reader

    def write(self, line):
        message = json.loads(line)
        if "id" not in message:
            return
        tag = message.get("params", {}).get("tag", 0)
        result = {"tools": []} if message.get("method") == "tools/list" else tag
        response = json.dumps({"id": message["id"], "result": result}).encode() + b"\n"
        asyncio.get_running_loop().call_later(
            (20 - tag) / 2000, self.reader.feed_data, response)

    async def drain(self):
        await asyncio.sleep(0)


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.reader = asyncio.StreamReader()
        self.writer = FakeWriter(self.reader)
        self.engine = daemon.Engine(SimpleNamespace(
            stdin=self.writer, stdout=self.reader))

    async def test_clients_with_same_request_id_receive_their_own_responses(self):
        async def client(tag):
            frame = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                "params": {"tag": tag}}).encode() + b"\n"
            return json.loads(await self.engine.exchange(frame))["result"]
        self.assertEqual(await asyncio.gather(*(client(tag) for tag in range(20))),
                         list(range(20)))

    async def test_notification_does_not_consume_the_next_response(self):
        self.assertIsNone(await self.engine.exchange(
            b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'))
        response = await self.engine.exchange(
            b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
        self.assertEqual(json.loads(response)["id"], 1)

    async def test_engine_eof_refuses_future_requests(self):
        self.reader.feed_eof()
        with self.assertRaises(RuntimeError):
            await self.engine.exchange(b'{"id":1,"method":"tools/list"}\n')
        self.assertTrue(self.engine.broken)
        with self.assertRaises(RuntimeError):
            await self.engine.exchange(b'{"id":2,"method":"tools/list"}\n')

    async def test_wrong_response_id_stops_engine(self):
        self.reader.feed_data(b'{"id":999,"result":{}}\n')
        with self.assertRaisesRegex(RuntimeError, "framing mismatch"):
            await self.engine.exchange(b'{"id":1,"method":"tools/list"}\n')
        self.assertTrue(self.engine.broken)

    async def test_malformed_discovery_stops_engine_cleanly(self):
        self.reader.feed_data(b'{"id":1,"result":17}\n')
        with self.assertRaisesRegex(RuntimeError, "discovery result shape mismatch"):
            await self.engine.exchange(b'{"id":1,"method":"tools/list"}\n')
        self.assertTrue(self.engine.broken)


class ContextWriter:
    def __init__(self, reader, context):
        self.reader, self.context, self.requests = reader, context, []
        self.error = False
        self.status_only = False
        self.records = [{"id": "native:root", "status": "found"}]
        self.executor_meta = {"schema": "native.mcp-executor.v1",
            "surface": "standby-read-only", "manifestSha256": "a" * 64,
            "descriptorBytes": 1000}

    def write(self, line):
        request = json.loads(line)
        self.requests.append(request)
        if request["method"] == "tools/list":
            result = {"tools": [{"name": name, "description": "official"} for name
                in ("bootstrap", "records_read", "records_write", "system_read", "standby_status")]}
            result["nextCursor"] = "preserved-cursor"
            result["_meta"] = {"nativeExecutor": self.executor_meta.copy()}
            result["tools"][3]["inputSchema"] = {"properties": {
                "operation": {"enum": ["ping", "engine_info", "describe_operation"]}}}
        elif request["method"] == "initialize":
            result = {"instructions": "canonical bootstrap mints a run key", "protocolVersion": "2025-11-25"}
        else:
            result = {"structuredContent": {"standby_context": self.context, "records": self.records}, "isError": self.error}
        if self.status_only and request["method"] == "tools/call":
            result = {"structuredContent": {"standby_context": self.context,
                "error_code": "STANDBY_STATUS_ONLY", "run_context": None}, "isError": True}
        self.last_response = daemon.frame({"jsonrpc": "2.0", "id": request["id"], "result": result})
        self.reader.feed_data(self.last_response)

    async def drain(self):
        pass


class MetadataTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.context = {"status_scope": "serving_generation_freshness_only", "mode": "standby",
            "read_only": True, "writes_supported": False, "canonical_authority": "hosted",
            "serving_generation_id": "immutable-generation", "freshness": {
                "state": "beyond_rpo", "age_seconds": 15000}, "freshness_degraded": True}
        reader = asyncio.StreamReader()
        self.writer = ContextWriter(reader, self.context)
        self.engine = daemon.Engine(SimpleNamespace(stdin=self.writer, stdout=reader))

    async def call(self, name, arguments=None):
        request = {"jsonrpc": "2.0", "id": "client", "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}}}
        return json.loads(await self.engine.exchange(daemon.frame(request)))

    async def test_readiness_and_metadata_follow_status_only_then_two_generations(self):
        self.writer.status_only = True
        self.writer.context = dict(self.context, mode="status_only", serving_generation_id=None,
            freshness={"state": "unavailable", "age_seconds": None})
        self.assertEqual(await daemon.readiness(self.engine), "status_only")
        cached = json.loads(await self.engine.exchange(daemon.frame({"jsonrpc":"2.0", "id":7, "method":"tools/list", "params":{}})))["result"]["tools"]
        self.assertIn("records_read", {tool["name"] for tool in cached})
        unavailable = await self.call("bootstrap")
        self.assertFalse(unavailable["result"]["isError"])
        self.assertFalse(unavailable["result"]["structuredContent"]["workspace_reads_available"])
        self.assertEqual(unavailable["result"]["structuredContent"]["standby_context"]["mode"], "status_only")
        refused = await self.call("records_write", {"operation": "create_record"})
        self.assertTrue(refused["result"]["isError"])
        self.assertEqual(refused["result"]["structuredContent"]["error_code"], "STANDBY_STATUS_ONLY")
        self.writer.status_only = False
        for generation in ("accepted-one", "accepted-two"):
            self.writer.context = dict(self.context, serving_generation_id=generation)
            self.assertEqual(await daemon.readiness(self.engine), "standby")
            metadata = (await self.call("bootstrap"))["result"]["structuredContent"]
            self.assertTrue(metadata["workspace_reads_available"])
            self.assertEqual(metadata["standby_context"]["serving_generation_id"], generation)
            read = await self.call("records_read", {"operation":"get_record", "arguments":{"ids":["native:root"]}})
            self.assertFalse(read["result"]["isError"])
            self.assertEqual(read["result"]["structuredContent"]["standby_context"]["serving_generation_id"], generation)
        self.assertFalse(self.engine.broken)

    async def test_status_only_readiness_rejects_untyped_or_false_availability(self):
        self.writer.status_only = True
        for context in (dict(self.context, mode="status_only"),
            dict(self.context, mode="status_only", serving_generation_id=None,
                 freshness={"state":"fresh", "age_seconds": 0})):
            self.writer.context = context
            with self.assertRaisesRegex(RuntimeError, "context unavailable"):
                await daemon.readiness(self.engine)

    async def test_bootstrap_refuses_not_found_kernel_root_even_with_matching_id(self):
        self.writer.records = [{"id": "native:root", "status": "not_found"}]
        refused = await self.call("bootstrap")
        self.assertTrue(refused["result"]["isError"])
        self.assertEqual(refused["result"]["structuredContent"]["error_code"], "LOCAL_CONTEXT_UNAVAILABLE")

    async def test_bootstrap_preserves_kernel_context_and_explicitly_limits_scope(self):
        reply = await self.call("bootstrap", {"format": "json"})
        result = reply["result"]["structuredContent"]
        self.assertEqual(reply["id"], "client")
        self.assertEqual(result["standby_context"], self.context)
        self.assertEqual(result["bootstrap_scope"], "local_serving_metadata_only")
        self.assertFalse(result["full_audit_available_on_this_connection"])
        self.assertNotIn("run_key", result)
        self.assertEqual(self.writer.requests[0]["params"], {"name": "records_read",
            "arguments": {"operation": "get_record", "arguments": {"ids": ["native:root"]}, "format": "json"}})

    async def test_bootstrap_accepts_optional_context_without_creating_a_run(self):
        reply = await self.call("bootstrap", {"run_key": "existing-run", "parent_key": "parent", "format": "json"})
        self.assertFalse(reply["result"]["isError"])
        self.assertNotIn("run_key", reply["result"]["structuredContent"])
        self.assertNotIn("run_key", self.writer.requests[-1]["params"]["arguments"])

    async def test_missing_or_status_only_context_cannot_claim_read_recovery(self):
        for context in (None, {}, dict(self.context, mode="status_only"),
                        dict(self.context, read_only=False), dict(self.context, freshness=None)):
            self.writer.context = context
            reply = await self.call("bootstrap")
            self.assertTrue(reply["result"]["isError"])
            self.assertEqual(reply["result"]["structuredContent"]["error_code"], "LOCAL_CONTEXT_UNAVAILABLE")

    async def test_authorization_error_cannot_become_successful_bootstrap(self):
        self.writer.error = True
        self.assertTrue((await self.call("bootstrap"))["result"]["isError"])

    async def test_invisible_root_cannot_become_successful_bootstrap(self):
        self.writer.records = []
        self.assertTrue((await self.call("bootstrap"))["result"]["isError"])

    async def test_metadata_notifications_do_not_invoke_full_audits(self):
        for name in ("bootstrap", "standby_status", "engine_info"):
            request = daemon.frame({"method": "tools/call", "params": {"name": name}})
            self.assertIsNone(await self.engine.exchange(request))
        self.assertEqual(self.writer.requests, [])

    async def test_reads_and_writes_are_forwarded_unchanged(self):
        for name in ("records_read", "records_write", "system_read"):
            arguments = {"operation": "original", "arguments": {"value": 4}, "run_key": "caller"}
            request = daemon.frame({"id": 4, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
            self.assertEqual(await self.engine.exchange(request), self.writer.last_response)
            self.assertEqual(self.writer.requests[-1]["params"], {"name": name, "arguments": arguments})

    async def test_ping_keeps_official_handling(self):
        await self.call("system_read", {"operation": "ping"})
        self.assertEqual(self.writer.requests[-1]["params"]["arguments"], {"operation": "ping"})

    async def test_initialize_discloses_metadata_only_scope(self):
        response = json.loads(await self.engine.exchange(daemon.frame({"id": 1, "method": "initialize"})))
        self.assertIn("NOT canonical Native bootstrap", response["result"]["instructions"])
        self.assertEqual(response["result"]["protocolVersion"], "2025-11-25")

    async def test_full_audits_refused_without_touching_consumer(self):
        for name, arguments in (("engine_info", {}), ("system_read", {"operation": "engine_info"})):
            reply = await self.call(name, arguments)
            self.assertTrue(reply["result"]["isError"])
            self.assertEqual(reply["result"]["structuredContent"]["error_code"], "LOCAL_FULL_AUDIT_SEPARATE")
        self.assertEqual(self.writer.requests, [])

    async def test_discovery_labels_local_bootstrap_and_omits_full_audit(self):
        response = json.loads(await self.engine.exchange(daemon.frame({"id": 1, "method": "tools/list"})))
        self.assertNotIn("nativeExecutor", response["result"]["_meta"])
        self.assertEqual(response["result"]["_meta"]["nativeLocalRelay"], {
            "catalogueScope": "local_projection", "upstreamNativeExecutor": self.writer.executor_meta})
        tools = {tool["name"]: tool for tool in response["result"]["tools"]}
        self.assertIn("standby_status", tools)
        self.assertIn("metadata only", tools["standby_status"]["description"])
        self.assertIn("NOT canonical Native bootstrap", tools["bootstrap"]["description"])
        self.assertEqual(tools["records_write"]["description"], "official")
        self.assertEqual(tools["system_read"]["inputSchema"]["properties"]["operation"]["enum"], ["ping", "describe_operation"])
        self.assertEqual(response["result"]["nextCursor"], "preserved-cursor")

    async def test_unsupported_bootstrap_arguments_fail_before_kernel_read(self):
        self.assertTrue((await self.call("bootstrap", {"format": "app"}))["result"]["isError"])
        self.assertTrue((await self.call("bootstrap", {"run_key": 123}))["result"]["isError"])
        self.assertEqual(self.writer.requests, [])

    async def test_bootstrap_and_status_preserve_age_and_failed_attempt_after_success(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory) / "refresh.json"
            status.write_text(json.dumps({"state": "succeeded",
                "last_failed_attempt_at": "2026-10-04T10:00:00Z",
                "last_successful_attempt_at": "2026-10-04T16:00:00Z",
                "download_bytes": 12345,
                "credential": "must never be returned"}))
            status.chmod(0o600)
            self.engine.refresh_status = str(status)
            for name in ("bootstrap", "standby_status"):
                result = (await self.call(name))["result"]["structuredContent"]
                self.assertEqual(result["standby_context"]["freshness"]["age_seconds"], 15000)
                self.assertEqual(result["refresh"]["last_failed_attempt_at"], "2026-10-04T10:00:00Z")
                self.assertNotIn("credential", result["refresh"])
                self.assertEqual(result["refresh"]["download_bytes"], 12345)
                self.assertEqual(self.writer.requests[-1]["params"]["name"], "records_read")

    async def test_broken_refresh_status_cannot_hide_old_reader_age(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory) / "refresh.json"
            self.engine.refresh_status = str(status)
            for payload, mode in (("not json", 0o600), ("{}", 0o644)):
                status.write_text(payload)
                status.chmod(mode)
                result = (await self.call("standby_status"))["result"]["structuredContent"]
                self.assertEqual(result["standby_context"]["freshness"]["age_seconds"], 15000)
                self.assertFalse(result["refresh"]["status_available"])


class PoolEngine:
    def __init__(self, generation, write_refused=True):
        self.generation = generation
        self.write_refused = write_refused
        self.release = asyncio.Event()
        self.release.set()
        self.started = asyncio.Event()
        self.exited = asyncio.Event()
        self.close_count = 0
        self.process = SimpleNamespace(returncode=None, stdin=SimpleNamespace(close=self.close),
                                       wait=self.wait)

    def close(self):
        self.close_count += 1
        self.process.returncode = 0
        self.exited.set()

    async def wait(self):
        await self.exited.wait()
        return 0

    async def exchange(self, line, timeout=120):
        request = json.loads(line)
        name = request.get("params", {}).get("name")
        if request.get("method") == "tools/list":
            result = {"tools": [{"name": name} for name in ("bootstrap", "records_read")]}
        elif name == "bootstrap":
            result = {"structuredContent": {"bootstrap_scope": "local_serving_metadata_only",
                "standby_context": {"mode": "standby", "serving_generation_id": self.generation}}}
        elif name == "records_write":
            result = {"isError": self.write_refused,
                "structuredContent": {"error_code": "STANDBY_READ_ONLY" if self.write_refused else None}}
        else:
            self.started.set()
            await self.release.wait()
            result = {"generation": self.generation}
        return daemon.frame({"id": request.get("id"), "result": result})


class ReaderPoolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.old = PoolEngine("a" * 64)
        self.new = PoolEngine("b" * 64)
        self.start_allowed = asyncio.Event()
        self.start_allowed.set()
        self.start_called = asyncio.Event()

        async def start():
            self.start_called.set()
            await self.start_allowed.wait()
            return self.new
        self.pool = daemon.ReaderPool(self.old, start)

    async def asyncTearDown(self):
        await self.pool.close()

    async def test_old_reader_serves_during_candidate_startup(self):
        self.start_allowed.clear()
        activation = asyncio.create_task(self.pool.activate("b" * 64))
        await self.start_called.wait()
        response = json.loads(await self.pool.exchange(daemon.frame({"id": 1, "method": "read"})))
        self.assertEqual(response["result"]["generation"], "a" * 64)
        self.start_allowed.set()
        self.assertTrue((await activation)["activated"])
        response = json.loads(await self.pool.exchange(daemon.frame({"id": 1, "method": "read"})))
        self.assertEqual(response["result"]["generation"], "b" * 64)

    async def test_generation_mismatch_keeps_old_reader(self):
        with self.assertRaisesRegex(RuntimeError, "generation mismatch"):
            await self.pool.activate("c" * 64)
        self.assertIs(self.pool.current, self.old)
        self.assertEqual(self.old.close_count, 0)
        self.assertEqual(self.new.close_count, 1)

    async def test_write_refusal_is_required_before_swap(self):
        self.new.write_refused = False
        with self.assertRaisesRegex(RuntimeError, "refuse writes"):
            await self.pool.activate("b" * 64)
        self.assertIs(self.pool.current, self.old)
        self.assertEqual(self.old.close_count, 0)

    async def test_failed_start_keeps_old_reader(self):
        async def fail():
            raise RuntimeError("startup refused")
        self.pool.start_engine = fail
        with self.assertRaisesRegex(RuntimeError, "startup refused"):
            await self.pool.activate("b" * 64)
        self.assertIs(self.pool.current, self.old)
        self.assertEqual(self.old.close_count, 0)

    async def test_activation_waits_for_existing_exchange_before_retiring(self):
        self.old.release.clear()
        read = asyncio.create_task(self.pool.exchange(daemon.frame({"id": 1, "method": "read"})))
        await self.old.started.wait()
        activation = asyncio.create_task(self.pool.activate("b" * 64))
        await self.start_called.wait()
        await asyncio.sleep(0)
        self.assertEqual(self.old.close_count, 0)
        self.old.release.set()
        self.assertEqual(json.loads(await read)["result"]["generation"], "a" * 64)
        await activation
        await asyncio.sleep(0)
        self.assertEqual(self.old.close_count, 1)

    async def test_second_activation_is_refused_without_starting_another_candidate(self):
        self.start_allowed.clear()
        activation = asyncio.create_task(self.pool.activate("b" * 64))
        await self.start_called.wait()
        with self.assertRaisesRegex(RuntimeError, "already running"):
            await self.pool.activate("b" * 64)
        self.start_allowed.set()
        await activation

    async def test_invalid_generation_refused_before_start(self):
        with self.assertRaises(ValueError):
            await self.pool.activate("not a generation")
        self.assertFalse(self.start_called.is_set())

    async def test_disconnected_activation_cancels_work_and_keeps_old_reader(self):
        self.new.release.clear()
        candidate_started = asyncio.Event()
        original_exchange = self.new.exchange

        async def stalled(line, timeout=120):
            candidate_started.set()
            await self.new.release.wait()
            return await original_exchange(line, timeout)
        self.new.exchange = stalled
        reader = asyncio.StreamReader()
        activation = asyncio.create_task(daemon.activate_request(self.pool, reader, "b" * 64, 10))
        await candidate_started.wait()
        reader.feed_eof()
        with self.assertRaisesRegex(RuntimeError, "disconnected"):
            await activation
        self.assertIs(self.pool.current, self.old)
        self.assertEqual(self.new.close_count, 1)
        self.assertEqual(self.old.close_count, 0)

    async def test_server_activation_deadline_cancels_work(self):
        async def stalled(line, timeout=120):
            await asyncio.Event().wait()
        self.new.exchange = stalled
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            await daemon.activate_request(self.pool, asyncio.StreamReader(), "b" * 64, 0.02)
        self.assertIs(self.pool.current, self.old)
        self.assertEqual(self.new.close_count, 1)


@unittest.skipUnless(sys.platform == "linux", "Linux owner-only relay")
class LocalBoundaryTests(unittest.TestCase):
    def test_seeded_relay_activates_without_dropping_an_existing_client(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("old", "live", "scratch"):
                (root / name).mkdir(mode=0o700)
            config = root / "runtime.json"
            config.write_text(json.dumps({"generation": "a" * 64}))
            consumer = root / "consumer"
            consumer.write_text('''#!/usr/bin/python3
import json, sys
generation = json.load(open(sys.argv[-1]))["generation"]
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    if message["method"] == "tools/list":
        result = {"tools": [{"name": name} for name in
            ("bootstrap", "records_read", "records_write", "standby_status")]}
    elif message.get("params", {}).get("name") == "records_write":
        result = {"isError": True, "structuredContent": {"error_code": "STANDBY_READ_ONLY"}}
    else:
        result = {"structuredContent": {"standby_context": {
            "status_scope": "serving_generation_freshness_only", "mode": "standby",
            "read_only": True, "writes_supported": False, "canonical_authority": "hosted",
            "serving_generation_id": generation, "freshness": {"age_seconds": 12000}},
            "records": [{"id": "native:root", "status": "found"}]}}
    print(json.dumps({"id": message["id"], "result": result}), flush=True)
''')
            consumer.chmod(0o700)
            old_socket, live_socket = root / "old/data.sock", root / "live/data.sock"
            control = root / "live/control.sock"
            processes = []

            def start(endpoint, extra=()):
                process = subprocess.Popen([sys.executable, str(SCRIPT), "serve",
                    "--socket", str(endpoint), "--consumer", str(consumer), "--config", str(config),
                    "--scratch", str(root / "scratch"), "--account", "owner", *extra],
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                processes.append(process)
                deadline = time.monotonic() + 10
                while not endpoint.exists():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        self.fail("relay did not start")
                    time.sleep(0.02)
                return process

            try:
                start(old_socket)
                config.write_text(json.dumps({"generation": "b" * 64}))
                start(live_socket, ("--seed-socket", str(old_socket), "--control-socket", str(control)))
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(10)
                    client.connect(str(live_socket))
                    with client.makefile("rb") as responses:
                        def bootstrap():
                            client.sendall(daemon.frame({"id": 7, "method": "tools/call",
                                "params": {"name": "bootstrap", "arguments": {}}}))
                            return json.loads(responses.readline())["result"]["structuredContent"]
                        self.assertEqual(bootstrap()["standby_context"]["serving_generation_id"], "a" * 64)
                        activated = subprocess.run([sys.executable, str(SCRIPT), "activate",
                            "--socket", str(control), "--expected-generation", "b" * 64],
                            capture_output=True, text=True, timeout=10)
                        self.assertEqual(activated.returncode, 0, activated.stderr)
                        self.assertEqual(bootstrap()["standby_context"]["serving_generation_id"], "b" * 64)
                        self.assertEqual(processes[0].poll(), None)
            finally:
                for process in reversed(processes):
                    process.terminate()
                    try:
                        process.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()

    def test_fresh_stdio_normalizes_bootstrap_for_older_warm_daemon_only(self):
        with tempfile.TemporaryDirectory() as directory:
            endpoint = str(Path(directory) / "standby.sock")
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(endpoint)
            listener.listen(1)
            listener.settimeout(10)
            requests = []

            def server():
                connection, _ = listener.accept()
                with connection, connection.makefile("rwb") as stream:
                    for line in stream:
                        requests.append(json.loads(line))
                        stream.write(daemon.frame({"id": requests[-1]["id"], "result": {"accepted": True}}))
                        stream.flush()

            worker = threading.Thread(target=server, daemon=True)
            worker.start()
            bootstrap = {"id": 1, "method": "tools/call", "params": {"name": "bootstrap",
                "arguments": {"format": "json", "run_key": "caller", "parent_key": "parent"}}}
            read = {"id": 1, "method": "tools/call", "params": {"name": "records_read",
                "arguments": {"operation": "get_record", "run_key": "caller", "parent_key": "parent"}}}
            try:
                result = subprocess.run([sys.executable, str(SCRIPT), "stdio", "--socket", endpoint],
                    input=daemon.frame(bootstrap)+daemon.frame(read), capture_output=True, timeout=10)
                worker.join(timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(worker.is_alive())
                self.assertEqual(len(result.stdout.splitlines()), 2)
                self.assertEqual(requests[0]["params"]["arguments"], {"format": "json"})
                self.assertEqual(requests[1], read)
                invalid = daemon.frame({"id": 1, "method": "tools/call", "params": {"name": "bootstrap", "arguments": {"run_key": 7}}})
                self.assertEqual(daemon.normalize_local_bootstrap(invalid), invalid)
            finally:
                listener.close()

    def test_account_selection_is_required_before_consumer_start(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "serve", "--socket", "/abs/socket",
            "--consumer", "/nonexistent/consumer", "--config", "/abs/config", "--scratch", "/abs/scratch"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--account", result.stderr)

    def test_selected_account_reaches_official_consumer_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            consumer = Path(directory) / "consumer"
            consumer.write_text(f"#!{sys.executable}\nimport sys,json\nprint(json.dumps(sys.argv[1:]))\n")
            consumer.chmod(0o700)
            account = "acct_" + "0" * 32
            result = subprocess.run([sys.executable, str(SCRIPT), "engine", "--consumer", str(consumer),
                "--config", "/abs/runtime.json", "--account", account],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), ["--standby", "--account", account, "/abs/runtime.json"])

    def test_seccomp_denies_socket_creation(self):
        code = ("import runpy,socket; "
                f"m=runpy.run_path({str(SCRIPT)!r}); m['deny_network'](); "
                "socket.socket(socket.AF_INET)")
        result = subprocess.run([sys.executable, "-c", code],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("[Errno 101]", result.stderr)

    def test_lock_cannot_be_shared_or_redirected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fd = daemon.owner_lock(root)
            try:
                with self.assertRaises(BlockingIOError):
                    daemon.owner_lock(root)
            finally:
                os.close(fd)
            (root / "daemon.lock").unlink()
            target = root / "target"
            target.write_text("unchanged")
            (root / "daemon.lock").symlink_to(target)
            with self.assertRaises(OSError):
                daemon.owner_lock(root)
            self.assertEqual(target.read_text(), "unchanged")


if __name__ == "__main__":
    unittest.main()
