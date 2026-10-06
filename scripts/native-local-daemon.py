#!/usr/bin/env python3
"""Linux owner-only stdio relay to one warmed, network-denied HQ standby.

The official consumer performs complete startup admission. Data operations go
unchanged to it. Local bootstrap reports only its authenticated serving context;
expensive full status audits use a separate official process. No data is cached,
authorization changed, or traffic proxied to hosted Native.
"""

import argparse
import asyncio
import ctypes
import errno
import fcntl
import json
import math
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import threading

MAX_LINE = 8 * 1024 * 1024
LOCAL_BOOTSTRAP_DESCRIPTION = (
    "Local standby metadata only: authorised kernel read returns serving generation "
    "mode, read-only availability and snapshot age. This is NOT canonical Native "
    "bootstrap: it creates no run key, intent or workspace orientation and performs "
    "no full current-pointer audit. Hosted Native remains canonical. Full status "
    "audits require a separate official consumer, not this fast read connection.")
FULL_STATUS_ROUTE = (
    "The kernel context's full_status_tool refers to the official consumer, not "
    "this relay. Run the installed consumer separately with --standby --account "
    "<owner-account> <runtime-config>, then call standby_status. Startup and the "
    "full audit both revalidate history and may take tens of minutes.")


def refresh_metadata(path):
    """Advisory refresh state cannot grant readiness or replace kernel age."""
    if path is None:
        return {"configured": False, "status_available": False}
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536:
                raise ValueError("invalid refresh status file")
            value = json.load(source)
        if not isinstance(value, dict):
            raise ValueError("invalid refresh status")
        keys = ("state", "cadence_seconds", "last_attempt_at", "last_failed_attempt_at",
                "last_successful_attempt_at", "last_failure_phase", "last_error_code",
                "last_failure_error_code", "phase", "completed_phase", "finished_at",
                "durations_seconds", "download_bytes", "generation_id", "next_due_at")
        return dict({"configured": True, "status_available": True},
                    **{key: value[key] for key in keys if key in value})
    except (OSError, ValueError):
        return {"configured": True, "status_available": False}


def frame(value):
    return (json.dumps(value) + "\n").encode()


def tool_result(request, value, error=False):
    return frame({"jsonrpc": "2.0", "id": request["id"], "result": {
        "content": [{"type": "text", "text": json.dumps(value)}],
        "structuredContent": value, "isError": error}})


def normalize_local_bootstrap(line):
    """Fresh stdio clients may reuse a warm daemon predating context-key support.

    Local metadata creates no run/parent context. Discard only valid optional
    correlation keys; all data operations and invalid envelopes stay unchanged.
    """
    try:
        message = json.loads(line)
    except (ValueError, UnicodeError):
        return line
    if not isinstance(message, dict) or message.get("method") != "tools/call":
        return line
    params = message.get("params")
    if not isinstance(params, dict) or params.get("name") != "bootstrap":
        return line
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        return line
    keys = set(arguments) & {"run_key", "parent_key"}
    if not keys or any(not isinstance(arguments[key], str) for key in keys):
        return line
    for key in keys:
        del arguments[key]
    return frame(message)


def deny_network():
    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                    ctypes.c_int, ctypes.c_uint]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    context = lib.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError("network denial initialization failed")
    try:
        for name in (b"socket", b"connect"):
            number = lib.seccomp_syscall_resolve_name(name)
            if number < 0 or lib.seccomp_rule_add(
                    context, 0x00050000 | errno.ENETUNREACH, number, 0):
                raise RuntimeError("network denial rule failed")
        if lib.seccomp_load(context):
            raise RuntimeError("network denial could not be enforced")
    finally:
        lib.seccomp_release(context)


class Engine:
    def __init__(self, process, refresh_status=None):
        self.process = process
        self.refresh_status = refresh_status
        self.lock = asyncio.Lock()
        self.broken = False

    async def exchange(self, line, timeout=120):
        try:
            message = json.loads(line)
        except (ValueError, UnicodeError):
            message = None  # the kernel returns its parse-error response
        if isinstance(message, dict) and "method" not in message:
            return None  # stray JSON-RPC responses are not requests
        notification = isinstance(message, dict) and "id" not in message
        # Keep the full-audit entry points off the shared, serialised read path.
        # Each one re-verifies all retained history in the released consumer.
        params = message.get("params", {}) if isinstance(message, dict) else {}
        name = params.get("name") if isinstance(params, dict) else None
        arguments = params.get("arguments", {}) if isinstance(params, dict) else {}
        tool_call = isinstance(message, dict) and message.get("method") == "tools/call"
        if tool_call:
            if name == "engine_info" or (name == "system_read"
                    and isinstance(arguments, dict) and arguments.get("operation") == "engine_info"):
                if notification:
                    return None
                return tool_result(message, {"error_code": "LOCAL_FULL_AUDIT_SEPARATE",
                    "message": "Full status audits revalidate all history. Use a separate official consumer; local bootstrap provides serving freshness only."}, True)
            if name in ("bootstrap", "standby_status"):
                if notification:
                    return None
                if not isinstance(arguments, dict) or set(arguments) - {"format", "run_key", "parent_key"} \
                        or any(key in arguments and not isinstance(arguments[key], str)
                               for key in ("run_key", "parent_key")) \
                        or arguments.get("format", "json") not in ("json", "text"):
                    return tool_result(message, {"error_code": "LOCAL_BOOTSTRAP_ARGUMENTS",
                        "message": "Local metadata bootstrap accepts format=json or text and optional string run_key/parent_key (ignored; no local run is created)."}, True)
                # Do not inspect SQLite, synthesize freshness or invoke full bootstrap.
                # This authenticated ordinary read supplies the kernel's bounded
                # context for the immutable generation it actually serves.
                request = {"jsonrpc": "2.0", "id": message["id"], "method": "tools/call",
                    "params": {"name": "records_read", "arguments": {
                        "operation": "get_record", "arguments": {"ids": ["native:root"]},
                        "format": "json"}}}
                response = json.loads(await self.exchange(frame(request), timeout))
                result = response.get("result", {})
                value = result.get("structuredContent", {}) if isinstance(result, dict) else {}
                context = value.get("standby_context") if isinstance(value, dict) else None
                records = value.get("records", []) if isinstance(value, dict) else []
                common = (not response.get("error") and isinstance(result, dict)
                    and isinstance(context, dict) and context.get("read_only") is True
                    and context.get("writes_supported") is False
                    and context.get("canonical_authority") == "hosted"
                    and context.get("status_scope") == "serving_generation_freshness_only"
                    and isinstance(context.get("freshness"), dict))
                serving = (common and not result.get("isError")
                    and isinstance(records, list) and any(isinstance(record, dict)
                        and record.get("id") == "native:root" and record.get("status") == "found" for record in records)
                    and context.get("mode") == "standby"
                    and isinstance(context.get("serving_generation_id"), str)
                    and bool(context["serving_generation_id"]))
                status_only = (common and result.get("isError") is True
                    and value.get("error_code") == "STANDBY_STATUS_ONLY"
                    and context.get("mode") == "status_only"
                    and context.get("serving_generation_id") is None
                    and context["freshness"].get("state") == "unavailable"
                    and context["freshness"].get("age_seconds") is None)
                if not serving and not status_only:
                    return tool_result(message, {"error_code": "LOCAL_CONTEXT_UNAVAILABLE",
                        "message": "The authorised kernel read did not supply usable serving context; do not claim local context recovery."}, True)
                return tool_result(message, {"bootstrap_scope": "local_serving_metadata_only",
                    "description": LOCAL_BOOTSTRAP_DESCRIPTION, "standby_context": context,
                    "workspace_reads_available": serving,
                    "full_audit_available_on_this_connection": False,
                    "full_status_route": FULL_STATUS_ROUTE,
                    "refresh": refresh_metadata(self.refresh_status)})
        async with self.lock:
            if self.broken:
                raise RuntimeError("standby engine is unavailable")
            try:
                self.process.stdin.write(line)
                await self.process.stdin.drain()
                if notification:
                    return None
                response = await asyncio.wait_for(
                    self.process.stdout.readline(), timeout=timeout)
                if not response or not response.endswith(b"\n"):
                    raise RuntimeError("standby engine closed its response stream")
                decoded = json.loads(response)
                expected_id = message.get("id") if isinstance(message, dict) else None
                if not isinstance(decoded, dict) or decoded.get("id") != expected_id \
                        or not ("result" in decoded or "error" in decoded):
                    raise RuntimeError("standby engine response framing mismatch")
                if isinstance(message, dict) and message.get("method") == "tools/list":
                    result = decoded.get("result")
                    if "error" in decoded:
                        return response
                    if not isinstance(result, dict) or not isinstance(result.get("tools"), list) \
                            or not all(isinstance(tool, dict) for tool in result["tools"]):
                        raise RuntimeError("standby discovery result shape mismatch")
                    tools = result["tools"]
                    for tool in tools:
                        if tool.get("name") in ("bootstrap", "standby_status"):
                            tool["description"] = LOCAL_BOOTSTRAP_DESCRIPTION
                            tool["inputSchema"] = {"type": "object", "properties": {
                                "format": {"type": "string", "enum": ["json", "text"]},
                                "run_key": {"type": "string", "description": "Accepted but ignored by local metadata bootstrap."},
                                "parent_key": {"type": "string", "description": "Accepted but ignored by local metadata bootstrap."}},
                                "additionalProperties": False}
                            tool.pop("outputSchema", None)
                        elif tool.get("name") == "system_read":
                            tool["description"] = tool.get("description", "") + " On this local relay engine_info is disabled; use bootstrap for serving freshness."
                            operation = tool.get("inputSchema", {}).get("properties", {}).get("operation", {})
                            if "enum" in operation:
                                operation["enum"] = [name for name in operation["enum"] if name != "engine_info"]
                    result["tools"] = tools
                    # These are local bootstrap/audit projections, so the
                    # official child's manifest is upstream provenance only.
                    meta = result.setdefault("_meta", {})
                    if not isinstance(meta, dict):
                        raise RuntimeError("standby discovery metadata shape mismatch")
                    upstream = meta.pop("nativeExecutor", None)
                    meta["nativeLocalRelay"] = {"catalogueScope": "local_projection"}
                    if upstream is not None:
                        meta["nativeLocalRelay"]["upstreamNativeExecutor"] = upstream
                    return frame(decoded)
                if isinstance(message, dict) and message.get("method") == "initialize" \
                        and isinstance(decoded.get("result"), dict):
                    decoded["result"]["instructions"] = LOCAL_BOOTSTRAP_DESCRIPTION + " " + FULL_STATUS_ROUTE
                    return frame(decoded)
                return response
            except (OSError, ValueError, asyncio.TimeoutError, RuntimeError):
                # Never send a late response to the next client's request.
                self.broken = True
                raise


def private_directory(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("directory must be absolute and contain no symlinks")
    path.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() \
            or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("directory must be owned by this user with mode0700")
    return path


def owner_lock(directory):
    fd = os.open(directory / "daemon.lock",
                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("daemon lock must be an owner-only regular file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


async def readiness(engine):
    """Listening permits honest status-only metadata, never certifies a reader.

    Probe the real child: no cached discovery mode and no full bootstrap/audit.
    The same child can later advance to a ready reader on this connection.
    """
    for _ in range(2):
        response = await engine.exchange(
            b'{"jsonrpc":"2.0","id":0,"method":"tools/list","params":{}}\n', timeout=5400)
        decoded = json.loads(response)
        tools = decoded.get("result", {}).get("tools", [])
        names = {tool.get("name") for tool in tools}
        if decoded.get("error") or "bootstrap" not in names:
            raise RuntimeError("standby has no supported discovery surface")
        response = await engine.exchange(frame({"jsonrpc": "2.0", "id": 0,
            "method": "tools/call", "params": {"name": "bootstrap", "arguments": {"format": "json"}}}), timeout=5400)
        result = json.loads(response).get("result", {})
        value = result.get("structuredContent", {})
        if result.get("isError") or value.get("bootstrap_scope") != "local_serving_metadata_only":
            raise RuntimeError("standby kernel readiness context unavailable")
        mode = value["standby_context"]["mode"]
        if mode in ("standby", "status_only") and "records_read" in names:
            return mode
        # Connected standby discovery must already expose its stable read schema.
        # Reread once for compatibility with a child finishing catalogue setup.
    raise RuntimeError("standby discovery/readiness context mismatch")


async def close_engine(engine):
    process = engine.process
    if process.returncode is None:
        process.stdin.close()
        try:
            await asyncio.wait_for(process.wait(), timeout=30)
        except asyncio.TimeoutError:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()


class ReaderPool:
    """Serialize final exchanges and swap only a ready, confined reader."""
    def __init__(self, engine, start_engine):
        self.current = engine
        self.start_engine = start_engine
        self.lock = asyncio.Lock()
        self.activation_lock = asyncio.Lock()
        self.changed = asyncio.Event()
        self.retirements = set()

    async def exchange(self, line, timeout=120):
        async with self.lock:
            return await self.current.exchange(line, timeout)

    async def activate(self, expected_generation):
        if not isinstance(expected_generation, str) or len(expected_generation) != 64 \
                or any(char not in "0123456789abcdef" for char in expected_generation):
            raise ValueError("invalid expected generation")
        if self.activation_lock.locked():
            raise RuntimeError("reader activation already running")
        async with self.activation_lock:
            candidate = await self.start_engine()
            try:
                if await readiness(candidate) != "standby":
                    raise RuntimeError("candidate is status-only")
                response = json.loads(await candidate.exchange(frame({"id": 0,
                    "method": "tools/call", "params": {"name": "bootstrap",
                    "arguments": {}}})))
                context = response["result"]["structuredContent"]["standby_context"]
                if context.get("serving_generation_id") != expected_generation:
                    raise RuntimeError("candidate generation mismatch")
                response = json.loads(await candidate.exchange(frame({"id": 0,
                    "method": "tools/call", "params": {"name": "records_write",
                    "arguments": {"operation": "create_record", "arguments": {
                        "type": "Document", "name": "Standby write-refusal probe"}}}})))
                result = response.get("result", {})
                if not isinstance(result, dict) or result.get("isError") is not True \
                        or not isinstance(result.get("structuredContent"), dict) \
                        or result["structuredContent"].get(
                        "error_code") != "STANDBY_READ_ONLY":
                    raise RuntimeError("candidate did not refuse writes")
                async with self.lock:
                    previous = self.current
                    self.current = candidate
                    self.changed.set()
                    self.changed = asyncio.Event()
                # All exchanges using previous have completed. Existing client
                # sockets remain open and their next call uses the new reader.
                task = asyncio.create_task(self.retire(previous))
                self.retirements.add(task)
                task.add_done_callback(self.retirements.discard)
                return {"activated": True, "serving_generation_id": expected_generation}
            except BaseException:
                await close_engine(candidate)
                raise

    async def retire(self, engine):
        try:
            await close_engine(engine)
        except OSError:
            print("native-local-daemon: retired reader cleanup failed", file=sys.stderr)

    async def wait_exit(self):
        while True:
            engine, changed = self.current, self.changed
            exit_task = asyncio.create_task(engine.process.wait())
            change_task = asyncio.create_task(changed.wait())
            try:
                await asyncio.wait((exit_task, change_task), return_when=asyncio.FIRST_COMPLETED)
                if engine is self.current and exit_task.done():
                    return
            finally:
                for task in (exit_task, change_task):
                    if not task.done():
                        task.cancel()
                await asyncio.gather(exit_task, change_task, return_exceptions=True)

    async def close(self):
        async with self.activation_lock:
            await close_engine(self.current)
            await asyncio.gather(*self.retirements, return_exceptions=True)


def owner_peer(writer):
    peer = writer.get_extra_info("socket").getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    if struct.unpack("3i", peer)[1] != os.getuid():
        raise PermissionError("standby relay requires the owning user")


def remove_owner_socket(endpoint):
    if endpoint.exists():
        info = endpoint.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("refusing to remove non-owner or non-socket endpoint")
        endpoint.unlink()


def check_owner_socket(endpoint):
    endpoint = Path(endpoint)
    private_directory(endpoint.parent)
    info = endpoint.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() \
            or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("socket must be owner-only")
    return endpoint


async def activate_request(pool, reader, expected_generation, timeout):
    """A disconnected/timed-out requester cannot leave candidate work running."""
    activation = asyncio.create_task(pool.activate(expected_generation))
    disconnected = asyncio.create_task(reader.read(1))
    try:
        done, _ = await asyncio.wait((activation, disconnected), timeout=timeout,
                                    return_when=asyncio.FIRST_COMPLETED)
        if activation in done:
            return activation.result()
        raise RuntimeError("activation requester disconnected or deadline exceeded")
    finally:
        for task in (activation, disconnected):
            if not task.done():
                task.cancel()
        await asyncio.gather(activation, disconnected, return_exceptions=True)


async def serve(args):
    endpoint = Path(args.socket)
    directory = private_directory(endpoint.parent)
    scratch = private_directory(args.scratch)
    lock = owner_lock(directory)
    pool = None
    server = None
    control = None
    control_endpoint = Path(args.control_socket) if args.control_socket else None
    stopped = asyncio.Event()
    try:
        if control_endpoint is not None:
            private_directory(control_endpoint.parent)
            if control_endpoint == endpoint:
                raise ValueError("data and control sockets must differ")
        remove_owner_socket(endpoint)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("NATIVE_CE_")}
        environment["TMPDIR"] = str(scratch)
        async def start_engine():
            process = await asyncio.create_subprocess_exec(
                sys.executable, str(Path(__file__).resolve()), "engine",
                "--consumer", args.consumer, "--config", args.config, "--account", args.account,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                limit=MAX_LINE, env=environment)
            return Engine(process, args.refresh_status)

        if args.seed_socket:
            # Adopt only an existing owner-only, already confined relay. Its
            # actual authenticated context is checked below; no stored status
            # file is accepted as readiness evidence. This keeps installation
            # available without repeating the old generation's costly startup.
            seed = check_owner_socket(args.seed_socket)
            process = await asyncio.create_subprocess_exec(
                sys.executable, str(Path(__file__).resolve()), "stdio", "--socket", str(seed),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                limit=MAX_LINE, env=environment)
            engine = Engine(process, args.refresh_status)
        else:
            engine = await start_engine()
        pool = ReaderPool(engine, start_engine)
        # An owner connection can listen while the verified reader is absent.
        # Status-only bootstrap explicitly discloses unavailable workspace reads.
        mode = await readiness(engine)

        async def client(reader, writer):
            try:
                owner_peer(writer)
                while line := await reader.readline():
                    if not line.endswith(b"\n"):
                        raise ValueError("incomplete MCP frame")
                    if not line.strip():
                        continue
                    response = await pool.exchange(line)
                    if response is not None:
                        writer.write(response)
                        await asyncio.wait_for(writer.drain(), timeout=30)
            except (OSError, ValueError, RuntimeError, asyncio.TimeoutError):
                if pool.current.broken:
                    stopped.set()
            finally:
                writer.close()
                await writer.wait_closed()

        async def activate_client(reader, writer):
            try:
                owner_peer(writer)
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                request = json.loads(line)
                if not isinstance(request, dict) or set(request) != {"expected_generation"}:
                    raise ValueError("invalid activation request")
                result = await activate_request(pool, reader, request["expected_generation"],
                                                args.activation_timeout)
            except (OSError, ValueError, RuntimeError, KeyError, asyncio.TimeoutError):
                result = {"activated": False, "error_code": "LOCAL_ACTIVATION_REFUSED"}
            try:
                writer.write(frame(result))
                await asyncio.wait_for(writer.drain(), timeout=30)
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_unix_server(
            client, path=str(endpoint), limit=MAX_LINE)
        endpoint.chmod(0o600)
        if control_endpoint is not None:
            remove_owner_socket(control_endpoint)
            control = await asyncio.start_unix_server(
                activate_client, path=str(control_endpoint), limit=4096)
            control_endpoint.chmod(0o600)
        print(f"native-local-daemon: kernel connected mode={mode}", file=sys.stderr, flush=True)
        process_exit = asyncio.create_task(pool.wait_exit())
        failure = asyncio.create_task(stopped.wait())
        await asyncio.wait((process_exit, failure), return_when=asyncio.FIRST_COMPLETED)
        failure.cancel()
        process_exit.cancel()
        await asyncio.gather(process_exit, failure, return_exceptions=True)
        raise RuntimeError("standby engine exited or lost framing; relay stopped")
    finally:
        if control is not None:
            control.close()
            await control.wait_closed()
            control_endpoint.unlink(missing_ok=True)
        if server is not None:
            server.close()
            await server.wait_closed()
            endpoint.unlink(missing_ok=True)
        if pool is not None:
            await pool.close()
        os.close(lock)


def stdio(args):
    connection = socket.socket(socket.AF_UNIX)
    connection.connect(args.socket)
    failures = []

    def send():
        try:
            for line in sys.stdin.buffer:
                connection.sendall(normalize_local_bootstrap(line))
            connection.shutdown(socket.SHUT_WR)
        except OSError as error:
            failures.append(error)
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()

    threading.Thread(target=send, daemon=True).start()
    try:
        while data := connection.recv(65536):
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
    finally:
        connection.close()
    if failures:
        raise RuntimeError("standby relay connection failed")


def activate(args):
    endpoint = check_owner_socket(args.socket)
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(args.timeout)
        connection.connect(str(endpoint))
        connection.sendall(frame({"expected_generation": args.expected_generation}))
        with connection.makefile("rb") as reader:
            response = json.loads(reader.readline(4096))
    if response.get("activated") is not True \
            or response.get("serving_generation_id") != args.expected_generation:
        raise RuntimeError("reader activation refused")
    print(json.dumps(response))


def positive_seconds(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("deadline must be positive and finite")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    service = modes.add_parser("serve")
    service.add_argument("--socket", required=True)
    service.add_argument("--consumer", required=True)
    service.add_argument("--config", required=True)
    service.add_argument("--scratch", required=True)
    service.add_argument("--account", required=True)
    service.add_argument("--control-socket")
    service.add_argument("--refresh-status")
    service.add_argument("--seed-socket", help="Owner-only existing warm relay for initial continuity")
    service.add_argument("--activation-timeout", type=positive_seconds, default=9000,
                         help="Server-side candidate deadline, seconds (default 2.5 hours)")
    client = modes.add_parser("stdio")
    client.add_argument("--socket", required=True)
    activation = modes.add_parser("activate")
    activation.add_argument("--socket", required=True)
    activation.add_argument("--expected-generation", required=True)
    activation.add_argument("--timeout", type=positive_seconds, default=10800)
    child = modes.add_parser("engine")
    child.add_argument("--consumer", required=True)
    child.add_argument("--config", required=True)
    child.add_argument("--account", required=True)
    args = parser.parse_args()
    if args.mode == "engine":
        deny_network()
        os.execv(args.consumer, [args.consumer, "--standby", "--account", args.account, args.config])
    elif args.mode == "serve":
        asyncio.run(serve(args))
    elif args.mode == "activate":
        activate(args)
    else:
        stdio(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"native-local-daemon: {error}", file=sys.stderr)
        sys.exit(1)
