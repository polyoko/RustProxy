#!/usr/bin/env python3
"""Real-network probes for the T0 latency baseline. Run ``self-check`` first."""

import argparse
import csv
import math
import os
import select
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit


TIMEOUT_S = 15
RESULT_FIELDS = [
    "timestamp_utc",
    "kind",
    "run",
    "agent",
    "port",
    "mode",
    "phase",
    "idle_s",
    "client_tcp_connect_s",
    "time_appconnect_s",
    "time_starttransfer_s",
    "http_code",
    "num_connects",
    "curl_exit",
    "result",
    "re_register_ms",
    "first_success_ms",
    "throughput_mbps",
    "mobile_speedtest_mbps",
    "detail",
]


@dataclass(frozen=True)
class Binding:
    agent: str
    port: int


class ResultSink:
    def __init__(self, path: str):
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        is_new = not output.exists() or output.stat().st_size == 0
        self.file = output.open("a", newline="")
        self.writer = csv.DictWriter(self.file, fieldnames=RESULT_FIELDS)
        self.lock = threading.Lock()
        if is_new:
            self.writer.writeheader()
            self.file.flush()

    def write(self, **row: object) -> None:
        values = {field: "" for field in RESULT_FIELDS}
        values["timestamp_utc"] = datetime.now(UTC).isoformat(timespec="seconds")
        values.update({key: value for key, value in row.items() if value is not None})
        with self.lock:
            self.writer.writerow(values)
            self.file.flush()

    def close(self) -> None:
        self.file.close()


def parse_binding(value: str) -> Binding:
    agent, separator, port_text = value.rpartition(":")
    if not separator or not agent or any(char in agent for char in "\r\n,"):
        raise argparse.ArgumentTypeError("binding must be agent:port")
    try:
        port = int(port_text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("binding port must be a number") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("binding port must be between 1 and 65535")
    return Binding(agent, port)


def require_proxy(args: argparse.Namespace) -> tuple[str, str, str]:
    values = (args.host, args.user, args.password)
    if not all(values):
        raise ValueError("--host, --user, and --password are required (environment defaults: T0_SOCKS_*)")
    if any("\r" in value or "\n" in value for value in values):
        raise ValueError("proxy values must not contain a newline")
    return values


def curl_config(host: str, binding: Binding, user: str, password: str) -> str:
    return "\n".join(
        (
            'silent = ""',
            'show-error = ""',
            f'socks5-hostname = "{curl_quote(host)}:{binding.port}"',
            f'proxy-user = "{curl_quote(user)}:{curl_quote(password)}"',
            f"max-time = {TIMEOUT_S}",
            f"connect-timeout = {TIMEOUT_S}",
        )
    )


def curl_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def curl_rows(host: str, binding: Binding, user: str, password: str, url: str, count: int) -> tuple[list[dict[str, str]], int, str]:
    write_out = "%{time_connect},%{time_appconnect},%{time_starttransfer},%{http_code},%{num_connects}\\n"
    command = ["curl", "--config", "-", "--http1.1"]
    command.extend(item for _ in range(count) for item in ("--output", os.devnull))
    command.extend(("--write-out", write_out, *([url] * count)))
    completed = subprocess.run(command, input=curl_config(host, binding, user, password), text=True, capture_output=True, check=False)
    rows = []
    for line in completed.stdout.splitlines():
        values = line.split(",")
        if len(values) == 5:
            rows.append(dict(zip(("client_tcp_connect_s", "time_appconnect_s", "time_starttransfer_s", "http_code", "num_connects"), values)))
    while len(rows) < count:
        rows.append({})
    return rows[:count], completed.returncode, completed.stderr.strip().replace("\n", " ")


def write_sample(sink: ResultSink, host: str, binding: Binding, user: str, password: str, url: str, mode: str) -> bool:
    rows, exit_code, stderr = curl_rows(host, binding, user, password, url, 2)
    all_ok = True
    for index, metrics in enumerate(rows):
        phase = "new" if index == 0 else "reuse"
        reused = phase == "new" or metrics.get("num_connects") == "0"
        ok = exit_code == 0 and metrics.get("http_code", "000") != "000" and reused
        detail = stderr or ("connection_not_reused" if not reused else "")
        sink.write(
            kind="sample",
            agent=binding.agent,
            port=binding.port,
            mode=mode,
            phase=phase,
            curl_exit=exit_code,
            result="ok" if ok else "error",
            detail=detail,
            **metrics,
        )
        all_ok = all_ok and ok
    return all_ok


def sample_worker(args: argparse.Namespace, binding: Binding, sink: ResultSink, ends_at: float) -> None:
    host, user, password = require_proxy(args)
    next_sample = time.monotonic()
    last_finished: float | None = None
    cold_then_warm = False
    while next_sample < ends_at:
        time.sleep(max(0, next_sample - time.monotonic()))
        if time.monotonic() >= ends_at:
            break
        idle = float("inf") if last_finished is None else time.monotonic() - last_finished
        mode = "cold" if idle >= 60 else "warm"
        started = time.monotonic()
        write_sample(sink, host, binding, user, password, args.target_url, mode)
        last_finished = time.monotonic()
        if args.cold_idle and mode == "cold":
            cold_then_warm = True
            next_sample = started + args.interval
        elif args.cold_idle and cold_then_warm:
            cold_then_warm = False
            next_sample = last_finished + args.cold_idle
        else:
            next_sample = max(started + args.interval, last_finished)


def run_samples(args: argparse.Namespace) -> int:
    if args.duration <= 0 or args.interval <= 0:
        raise ValueError("--duration and --interval must be positive")
    if args.cold_idle and args.cold_idle < 60:
        raise ValueError("--cold-idle must be at least 60 seconds")
    require_proxy(args)
    sink = ResultSink(args.out)
    try:
        ends_at = time.monotonic() + args.duration
        with ThreadPoolExecutor(max_workers=len(args.binding)) as pool:
            futures = [pool.submit(sample_worker, args, binding, sink, ends_at) for binding in args.binding]
            for future in futures:
                future.result()
    finally:
        sink.close()
    return 0


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise OSError("unexpected EOF")
        chunks.extend(chunk)
    return bytes(chunks)


def socks_address(host: str, port: int) -> bytes:
    try:
        return b"\x01" + socket.inet_aton(host) + port.to_bytes(2, "big")
    except OSError:
        encoded = host.encode("idna")
        if not encoded or len(encoded) > 255:
            raise ValueError("target host must be 1-255 bytes")
        return b"\x03" + bytes((len(encoded),)) + encoded + port.to_bytes(2, "big")


def socks_reply(sock: socket.socket) -> tuple[str, int]:
    version, reply, _reserved, atyp = recv_exact(sock, 4)
    if version != 5 or reply != 0:
        raise OSError(f"SOCKS reply {reply}")
    if atyp == 1:
        host = socket.inet_ntoa(recv_exact(sock, 4))
    elif atyp == 3:
        host = recv_exact(sock, recv_exact(sock, 1)[0]).decode("idna")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        raise OSError(f"unknown SOCKS address type {atyp}")
    return host, int.from_bytes(recv_exact(sock, 2), "big")


def socks_open(host: str, binding: Binding, user: str, password: str, command: int, target_host: str, target_port: int) -> tuple[socket.socket, tuple[str, int]]:
    username = user.encode()
    secret = password.encode()
    if not username or len(username) > 255 or len(secret) > 255:
        raise ValueError("SOCKS username/password must be 1-255 bytes")
    sock = socket.create_connection((host, binding.port), TIMEOUT_S)
    sock.settimeout(TIMEOUT_S)
    try:
        sock.sendall(b"\x05\x01\x02")
        if recv_exact(sock, 2) != b"\x05\x02":
            raise OSError("SOCKS server did not select username/password authentication")
        sock.sendall(b"\x01" + bytes((len(username),)) + username + bytes((len(secret),)) + secret)
        if recv_exact(sock, 2) != b"\x01\x00":
            raise OSError("SOCKS authentication failed")
        sock.sendall(bytes((5, command, 0)) + socks_address(target_host, target_port))
        return sock, socks_reply(sock)
    except Exception:
        sock.close()
        raise


def target_request(url: str) -> tuple[str, int, str, bytes]:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("--target-url must be an http(s) URL without embedded credentials")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    request = f"GET {path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nConnection: close\r\n\r\n".encode()
    return parsed.hostname, port, parsed.scheme, request


def tcp_idle_probe(host: str, binding: Binding, user: str, password: str, target_url: str, idle_s: int) -> tuple[bool, str]:
    sock: socket.socket | ssl.SSLSocket | None = None
    try:
        target_host, target_port, scheme, request = target_request(target_url)
        sock, _ = socks_open(host, binding, user, password, 1, target_host, target_port)
        time.sleep(idle_s)
        if scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=target_host)
            sock.settimeout(TIMEOUT_S)
        sock.sendall(request)
        if not sock.recv(1):
            raise OSError("target closed after idle")
        return True, ""
    except Exception as error:
        return False, str(error)
    finally:
        if sock:
            sock.close()


def decode_udp_payload(packet: bytes) -> bytes:
    if len(packet) < 4 or packet[:3] != b"\x00\x00\x00":
        raise OSError("invalid SOCKS UDP frame")
    atyp = packet[3]
    if atyp == 1:
        offset = 10
    elif atyp == 3:
        if len(packet) < 5:
            raise OSError("short SOCKS UDP domain frame")
        offset = 5 + packet[4] + 2
    else:
        raise OSError(f"unsupported SOCKS UDP address type {atyp}")
    if len(packet) < offset:
        raise OSError("short SOCKS UDP frame")
    return packet[offset:]


def udp_roundtrip(client: socket.socket, relay: tuple[str, int], target_host: str, target_port: int, payload: bytes, wait_s: float) -> bool:
    client.sendto(b"\x00\x00\x00" + socks_address(target_host, target_port) + payload, relay)
    ready, _, _ = select.select((client,), (), (), wait_s)
    if not ready:
        return False
    response, _ = client.recvfrom(65535)
    return decode_udp_payload(response) == payload


def udp_idle_probe(host: str, binding: Binding, user: str, password: str, target_host: str, target_port: int, idle_s: int) -> tuple[bool, str]:
    control: socket.socket | None = None
    client: socket.socket | None = None
    try:
        control, relay = socks_open(host, binding, user, password, 3, "0.0.0.0", 0)
        if relay[0] in ("0.0.0.0", "::"):
            relay = (host, relay[1])
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("0.0.0.0", 0))
        client.setblocking(False)
        for _ in range(5):
            if udp_roundtrip(client, relay, target_host, target_port, b"t0-ready", 2):
                break
            time.sleep(1)
        else:
            raise OSError("UDP echo did not answer before idle")
        time.sleep(idle_s)
        if not udp_roundtrip(client, relay, target_host, target_port, b"t0-after-idle", TIMEOUT_S):
            raise OSError("UDP echo did not answer after idle")
        return True, ""
    except Exception as error:
        return False, str(error)
    finally:
        if client:
            client.close()
        if control:
            control.close()


def write_idle_result(sink: ResultSink, kind: str, binding: Binding, idle_s: int, result: tuple[bool, str]) -> bool:
    ok, detail = result
    sink.write(kind=kind, agent=binding.agent, port=binding.port, idle_s=idle_s, result="ok" if ok else "error", detail=detail)
    return ok


def run_nat(args: argparse.Namespace) -> int:
    host, user, password = require_proxy(args)
    if any(idle_s < 0 for idle_s in args.idle):
        raise ValueError("--idle must not be negative")
    if args.protocol == "udp" and not args.udp_target:
        raise ValueError("--udp-target host:port is required for UDP; it must be a UDP echo server")
    if args.protocol == "udp":
        udp_host, udp_port = parse_host_port(args.udp_target)
    sink = ResultSink(args.out)
    try:
        with ThreadPoolExecutor(max_workers=len(args.binding) * len(args.idle)) as pool:
            futures = []
            for binding in args.binding:
                for idle_s in args.idle:
                    if args.protocol == "tcp":
                        future = pool.submit(tcp_idle_probe, host, binding, user, password, args.target_url, idle_s)
                        kind = "nat_tcp"
                    else:
                        future = pool.submit(udp_idle_probe, host, binding, user, password, udp_host, udp_port, idle_s)
                        kind = "nat_udp"
                    futures.append((future, kind, binding, idle_s))
            passed = True
            for future, kind, binding, idle_s in futures:
                passed = write_idle_result(sink, kind, binding, idle_s, future.result()) and passed
    finally:
        sink.close()
    return 0 if passed else 1


def parse_host_port(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host:
        raise ValueError("target must be host:port")
    try:
        port = int(port_text)
    except ValueError as error:
        raise ValueError("target port must be a number") from error
    if not 1 <= port <= 65535:
        raise ValueError("target port must be between 1 and 65535")
    return host, port


class LogTail:
    def __init__(self, path: str | None):
        self.file = open(path) if path else None
        if self.file:
            self.file.seek(0, os.SEEK_END)

    def saw_reconnect(self, agent: str) -> bool:
        if not self.file:
            return False
        return any(f"Agent '{agent}' connected" in line for line in self.file.readlines())

    def close(self) -> None:
        if self.file:
            self.file.close()


def api_reset(api_url: str, password: str) -> tuple[int, str]:
    if "\r" in password or "\n" in password:
        raise ValueError("server password must not contain a newline")
    config = f'header = "X-Server-Password: {curl_quote(password)}"\n'
    completed = subprocess.run(
        ["curl", "--config", "-", "--request", "POST", "--output", os.devnull, "--write-out", "%{http_code}", api_url],
        input=config,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.returncode, completed.stdout.strip()


def run_rotation(args: argparse.Namespace) -> int:
    host, user, password = require_proxy(args)
    if not args.server_password:
        raise ValueError("--server-password or T0_SERVER_PASSWORD is required")
    if "{agent}" not in args.api_url:
        raise ValueError("--api-url must include {agent}")
    sink = ResultSink(args.out)
    passed = True
    try:
        if args.runs <= 0:
            raise ValueError("--runs must be positive")
        for binding in args.binding:
            for run in range(1, args.runs + 1):
                tail = LogTail(args.server_log)
                started = time.monotonic()
                curl_exit, http_code = api_reset(args.api_url.format(agent=binding.agent), args.server_password)
                if curl_exit != 0 or http_code != "200":
                    sink.write(kind="rotation", run=run, agent=binding.agent, port=binding.port, curl_exit=curl_exit, http_code=http_code, result="error", detail="reset command failed")
                    tail.close()
                    passed = False
                    continue
                re_register_ms: int | None = None
                first_success_ms: int | None = None
                while time.monotonic() - started < args.timeout:
                    elapsed_ms = int((time.monotonic() - started) * 1000)
                    if re_register_ms is None and tail.saw_reconnect(binding.agent):
                        re_register_ms = elapsed_ms
                    if first_success_ms is None:
                        rows, exit_code, _ = curl_rows(host, binding, user, password, args.target_url, 1)
                        if exit_code == 0 and rows[0].get("http_code", "000") != "000":
                            first_success_ms = elapsed_ms
                    if first_success_ms is not None and (not args.server_log or re_register_ms is not None):
                        break
                    time.sleep(args.retry_interval)
                tail.close()
                ok = first_success_ms is not None and (not args.server_log or re_register_ms is not None)
                sink.write(
                    kind="rotation",
                    run=run,
                    agent=binding.agent,
                    port=binding.port,
                    result="ok" if ok else "error",
                    re_register_ms=re_register_ms,
                    first_success_ms=first_success_ms,
                    detail="re-register not observed" if args.server_log and re_register_ms is None else "",
                )
                passed = ok and passed
    finally:
        sink.close()
    return 0 if passed else 1


def run_throughput(args: argparse.Namespace) -> int:
    host, user, password = require_proxy(args)
    if not Path(args.upload_file).is_file():
        raise ValueError("--upload-file must be a file")
    sink = ResultSink(args.out)
    passed = True
    try:
        for binding in args.binding:
            command = [
                "curl", "--config", "-", "--upload-file", args.upload_file, "--output", os.devnull,
                "--write-out", "%{speed_upload},%{http_code}", args.upload_url,
            ]
            completed = subprocess.run(command, input=curl_config(host, binding, user, password), text=True, capture_output=True, check=False)
            speed, _, code = completed.stdout.strip().partition(",")
            try:
                mbps = round(float(speed) * 8 / 1_000_000, 3)
            except ValueError:
                mbps = None
            ok = completed.returncode == 0 and code != "000" and mbps is not None
            sink.write(
                kind="throughput",
                agent=binding.agent,
                port=binding.port,
                curl_exit=completed.returncode,
                http_code=code,
                throughput_mbps=mbps,
                mobile_speedtest_mbps=args.mobile_upload_mbps,
                result="ok" if ok else "error",
                detail=completed.stderr.strip().replace("\n", " "),
            )
            passed = ok and passed
    finally:
        sink.close()
    return 0 if passed else 1


def percentile(values: list[float], percentage: float) -> float:
    if not values:
        raise ValueError("cannot calculate a percentile of no values")
    return sorted(values)[max(0, math.ceil(len(values) * percentage) - 1)]


def run_summary(args: argparse.Namespace) -> int:
    groups: dict[tuple[str, str, str, str], list[float]] = {}
    with open(args.input, newline="") as source:
        for row in csv.DictReader(source):
            if row.get("kind") != "sample" or row.get("result") != "ok":
                continue
            phase = row.get("phase", "")
            metrics = (
                (("client_rtt", "client_tcp_connect_s"), ("setup", "time_appconnect_s"), ("setup_to_first_byte", "time_starttransfer_s"))
                if phase == "new"
                else (("path_rtt", "time_starttransfer_s"),)
            )
            for metric, field in metrics:
                try:
                    value = float(row[field])
                except (KeyError, TypeError, ValueError):
                    continue
                key = (row.get("agent", ""), row.get("port", ""), row.get("mode", ""), metric)
                groups.setdefault(key, []).append(value)

    writer = csv.DictWriter(sys.stdout, fieldnames=("agent", "port", "mode", "metric", "count", "p50_ms", "p95_ms", "p99_ms"))
    writer.writeheader()
    for (agent, port, mode, metric), values in sorted(groups.items()):
        writer.writerow({
            "agent": agent,
            "port": port,
            "mode": mode,
            "metric": metric,
            "count": len(values),
            "p50_ms": round(percentile(values, 0.50) * 1000, 3),
            "p95_ms": round(percentile(values, 0.95) * 1000, 3),
            "p99_ms": round(percentile(values, 0.99) * 1000, 3),
        })
    return 0


def self_check() -> int:
    assert parse_binding("phone-a:51314") == Binding("phone-a", 51314)
    assert socks_address("127.0.0.1", 80) == b"\x01\x7f\x00\x00\x01\x00\x50"
    assert decode_udp_payload(b"\x00\x00\x00\x01\x7f\x00\x00\x01\x00\x35ok") == b"ok"
    assert percentile([1.0, 2.0, 3.0], 0.95) == 3.0
    print("t0_probe self-check: ok")
    return 0


def add_proxy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default=os.getenv("T0_SOCKS_HOST"), help="SOCKS VPS hostname (or T0_SOCKS_HOST)")
    parser.add_argument("--user", default=os.getenv("T0_SOCKS_USER"), help="SOCKS username (or T0_SOCKS_USER)")
    parser.add_argument("--password", default=os.getenv("T0_SOCKS_PASSWORD"), help="SOCKS password (or T0_SOCKS_PASSWORD)")
    parser.add_argument("--binding", type=parse_binding, action="append", required=True, help="agent:port; repeat for each phone")
    parser.add_argument("--out", default="t0-results.csv", help="append-only CSV output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    samples = commands.add_parser("samples", help="record cold/warm setup and reused-connection path RTT")
    add_proxy_args(samples)
    samples.add_argument("--target-url", required=True, help="stable HTTP(S) URL; the same URL is requested twice per curl process")
    samples.add_argument("--duration", type=int, default=48 * 60 * 60, help="seconds; default: 48 hours")
    samples.add_argument("--interval", type=int, default=30, help="seconds between normal samples per port")
    samples.add_argument("--cold-idle", type=int, default=0, help="optional seconds to leave a port idle after each warm sample; must be >=60")
    samples.set_defaults(run=run_samples)

    nat = commands.add_parser("nat", help="test post-idle TCP or UDP traffic through the tunnel")
    add_proxy_args(nat)
    nat.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    nat.add_argument("--target-url", help="HTTP(S) URL for TCP; it is requested only after the idle period")
    nat.add_argument("--udp-target", help="UDP echo host:port for UDP")
    nat.add_argument("--idle", type=int, action="append", help="seconds; defaults to 15,30,60,120,300")
    nat.set_defaults(run=run_nat)

    rotation = commands.add_parser("rotation", help="measure reset command to re-register and first successful request")
    add_proxy_args(rotation)
    rotation.add_argument("--api-url", required=True, help="reset endpoint with {agent}, e.g. https://proxy.example/{agent}?reset_ip")
    rotation.add_argument("--server-password", default=os.getenv("T0_SERVER_PASSWORD"), help="dashboard password (or T0_SERVER_PASSWORD)")
    rotation.add_argument("--target-url", required=True)
    rotation.add_argument("--server-log", help="optional live server log file; required to prove re-registration")
    rotation.add_argument("--timeout", type=int, default=300)
    rotation.add_argument("--retry-interval", type=float, default=1)
    rotation.add_argument("--runs", type=int, default=20, help="reset attempts per binding; default: 20")
    rotation.set_defaults(run=run_rotation)

    throughput = commands.add_parser("throughput", help="upload a file through each proxy and record mobile-path upload Mbps")
    add_proxy_args(throughput)
    throughput.add_argument("--upload-url", required=True, help="HTTP endpoint that accepts PUT uploads")
    throughput.add_argument("--upload-file", required=True, help="fixed-size file to upload")
    throughput.add_argument("--mobile-upload-mbps", type=float, help="speedtest upload measured on this mobile, for the CSV comparison")
    throughput.set_defaults(run=run_throughput)

    summary = commands.add_parser("summary", help="print p50/p95/p99 baseline rows from a probe CSV")
    summary.add_argument("--input", required=True, help="CSV written by samples/nat/rotation/throughput")
    summary.set_defaults(run=run_summary)

    commands.add_parser("self-check", help="run the no-network parser/protocol check").set_defaults(run=lambda _args: self_check())
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "nat" and args.protocol == "tcp" and not args.target_url:
        parser.error("nat --protocol tcp requires --target-url")
    if args.command == "nat" and not args.idle:
        args.idle = [15, 30, 60, 120, 300]
    try:
        return args.run(args)
    except (OSError, ValueError) as error:
        print(f"t0_probe: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
