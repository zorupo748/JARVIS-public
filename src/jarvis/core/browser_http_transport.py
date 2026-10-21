"""One bounded HTTP/1.1 exchange over the existing pinned HTTPS broker.

There is no alternate transport, injected connection, redirect/retry, cookie
jar, credential, request body or caller-supplied header. V1 accepts only GET /
HEAD with a V1 static path and separately encoded query parameters. Raw URLs,
raw queries, percent-encoded paths and fragments are not accepted. A trusted
caller must own the allowlist and non-secret local IDs; this API does not make
agent-supplied policy authoritative or authenticate constructible Python data.

The broker owns DNS, admission, numeric-IP pinning, peer checks and verified
TLS. origin_authorized reports only the origin preflight, not DNS admission.
tls_established is recorded only after broker handoff. A failed send has an
unknown send state, and only a completely validated response is returned.
HTTP status, including 4xx/5xx, is separate from transport success and never
demonstrates functional success or semantic validity of response content.

The admitted subset is ASCII HTTP/1.1 with final status 200..599, no folded
headers, duplicate singleton fields, trailers, chunk extensions, compression
or informational responses. Framing uses one Content-Length, one chunked
Transfer-Encoding, or clean TLS closure. HEAD/204/304 end at the headers;
205 must have a completely framed empty body. Content-Length and the final
chunk determine completion without another TLS read. Already buffered extra
bytes are rejected. Later bytes/errors are not probed: the connection is
closed locally, never reused or pooled. Only close-delimited bodies require
clean TLS closure. Requests continue to advertise Connection: close.

Per-I/O timeouts and a monotonic acceptance budget begin after TLS handoff;
the budget covers sending, headers, framing and body together. These are not
a hard whole-operation wall-clock guarantee: synchronous DNS, CA loading,
broker establishment and cleanup retain the broker's documented limits.
Raw response headers/body are bounded, in-memory only and excluded from repr;
they are untrusted and may contain secrets. Nothing is logged or persisted.
Size budgets bound HTTP plaintext/payload, not TLS traffic or process RSS;
bounded temporary copies are made while assembling the body.
This does not contain arbitrary Python networking or integrate a browser.
"""

from __future__ import annotations

import re
import ssl
import time
from dataclasses import dataclass, field, fields
from urllib.parse import quote

from jarvis.core import browser_https_broker as broker
from jarvis.core.browser_network_policy import evaluate_browser_network_resolution
from jarvis.core.browser_operation_contract import BrowserOrigin, normalize_static_operation_path

__all__ = (
    "BrowserHTTPRequest", "BrowserHTTPTransportLimits", "BrowserHTTPResponse",
    "BrowserHTTPExchangeResult", "execute_browser_http_request",
)

_INPUT_ERROR = "invalid browser HTTP transport input"
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_STATUS = re.compile(rb"HTTP/1\.1 ([0-9]{3}) [\x20-\x7e]*")
_DECIMAL = re.compile(r"[0-9]{1,19}")
_HEX = re.compile(rb"[0-9A-Fa-f]{1,16}")
_PARAMETER_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
_MAX_HEADERS = 65_536
_MAX_BODY = 16_777_216
_MAX_RESPONSE = 33_554_432
_SINGLETONS = frozenset({
    "content-length", "transfer-encoding", "content-encoding", "connection", "location",
})
_BROKER_ERRORS = frozenset({
    "invalid_input", "dns_failed", "resolution_denied", "destination_denied",
    "peer_mismatch", "tcp_failed", "tls_failed", "timeout", "budget_exceeded",
    "broker_busy", "cleanup_failed",
})
_ERRORS = frozenset({
    "origin_not_allowed", "send_failed", "receive_failed", "timeout", "budget_exceeded",
    "header_limit", "response_limit", "body_limit", "chunk_limit", "malformed_response",
    "ambiguous_framing", "truncated_response", "unsupported_response",
    "unsupported_encoding", "unexpected_data", "tls_truncated",
}) | frozenset("broker_" + code for code in _BROKER_ERRORS)


def _origin(value: BrowserOrigin) -> BrowserOrigin:
    if (type(value) is not BrowserOrigin or type(value.scheme) is not str
            or type(value.hostname) is not str or type(value.effective_port) is not int):
        raise ValueError(_INPUT_ERROR)
    try:
        return BrowserOrigin(value.scheme, value.hostname, value.effective_port)
    except ValueError:
        raise ValueError(_INPUT_ERROR) from None


def _request_target(path: str, parameters: tuple[tuple[str, str], ...]) -> str:
    if type(parameters) is not tuple or len(parameters) > 64:
        raise ValueError(_INPUT_ERROR)
    parts = []
    size = len(path)
    for pair in parameters:
        if (type(pair) is not tuple or len(pair) != 2
                or any(type(value) is not str for value in pair)):
            raise ValueError(_INPUT_ERROR)
        name, value = pair
        if (_PARAMETER_NAME.fullmatch(name) is None or len(value) > 1_024
                or any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)):
            raise ValueError(_INPUT_ERROR)
        try:
            if len(value.encode("utf-8")) > 2_048:
                raise ValueError(_INPUT_ERROR)
            encoded = name + "=" + quote(value, safe="-._~", encoding="utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ValueError(_INPUT_ERROR) from None
        size += 1 + len(encoded)
        if size > 8_192:
            raise ValueError(_INPUT_ERROR)
        parts.append(encoded)
    return path + ("?" + "&".join(parts) if parts else "")


@dataclass(frozen=True, slots=True)
class BrowserHTTPRequest:
    """Structural request, not an authorization. Static paths must be non-secret."""

    origin: BrowserOrigin
    method: str
    static_path: str = field(default="/", repr=False)
    query_parameters: tuple[tuple[str, str], ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        origin = _origin(self.origin)
        if origin.scheme != "https" or origin.effective_port != 443:
            raise ValueError(_INPUT_ERROR)
        if type(self.method) is not str or self.method not in {"GET", "HEAD"}:
            raise ValueError(_INPUT_ERROR)
        if type(self.static_path) is not str or not 1 <= len(self.static_path) <= 2_048:
            raise ValueError(_INPUT_ERROR)
        try:
            normalize_static_operation_path(self.static_path)
        except ValueError:
            raise ValueError(_INPUT_ERROR) from None
        _request_target(self.static_path, self.query_parameters)
        object.__setattr__(self, "origin", origin)


@dataclass(frozen=True, slots=True)
class BrowserHTTPTransportLimits:
    """Finite post-handoff time, memory and framing-processing limits."""

    io_timeout_ms: int = 5_000
    exchange_budget_ms: int = 15_000
    max_header_bytes: int = 16_384
    max_header_count: int = 64
    max_body_bytes: int = 1_048_576
    max_response_bytes: int = 2_097_152
    max_chunk_count: int = 4_096

    def __post_init__(self) -> None:
        for value, maximum in (
            (self.io_timeout_ms, 60_000), (self.exchange_budget_ms, 60_000),
            (self.max_header_bytes, _MAX_HEADERS), (self.max_header_count, 256),
            (self.max_body_bytes, _MAX_BODY), (self.max_response_bytes, _MAX_RESPONSE),
            (self.max_chunk_count, 65_536),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(_INPUT_ERROR)


def _header(line: bytes) -> tuple[str, str]:
    name, separator, value = line.partition(b":")
    if (not separator or _TOKEN.fullmatch(name) is None
            or any(byte != 9 and not 32 <= byte <= 126 for byte in value)):
        raise _Failure("malformed_response")
    return name.decode("ascii").lower(), value.decode("ascii").strip(" \t")


@dataclass(frozen=True, slots=True)
class BrowserHTTPResponse:
    """Bounded untrusted content; construction alone proves no network activity."""

    status_code: int
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body: bytes = field(repr=False)
    framing: str
    wire_bytes: int

    def __post_init__(self) -> None:
        if type(self.status_code) is not int or not 200 <= self.status_code <= 599:
            raise ValueError(_INPUT_ERROR)
        if type(self.headers) is not tuple or len(self.headers) > 256:
            raise ValueError(_INPUT_ERROR)
        size = 0
        for pair in self.headers:
            if (type(pair) is not tuple or len(pair) != 2
                    or any(type(value) is not str for value in pair)):
                raise ValueError(_INPUT_ERROR)
            name, value = pair
            size += len(name) + len(value) + 4
            if size > _MAX_HEADERS:
                raise ValueError(_INPUT_ERROR)
            try:
                parsed = _header((name + ":" + value).encode("ascii"))
            except (UnicodeEncodeError, _Failure):
                raise ValueError(_INPUT_ERROR) from None
            if parsed != pair:
                raise ValueError(_INPUT_ERROR)
        if type(self.body) is not bytes or len(self.body) > _MAX_BODY:
            raise ValueError(_INPUT_ERROR)
        if type(self.framing) is not str or self.framing not in {"none", "content_length", "chunked", "close"}:
            raise ValueError(_INPUT_ERROR)
        if self.framing == "none" and self.body:
            raise ValueError(_INPUT_ERROR)
        if type(self.wire_bytes) is not int or not len(self.body) <= self.wire_bytes <= _MAX_RESPONSE:
            raise ValueError(_INPUT_ERROR)

    @property
    def is_redirect(self) -> bool:
        return self.status_code in {300, 301, 302, 303, 307, 308}


@dataclass(frozen=True, slots=True)
class BrowserHTTPExchangeResult:
    """Observed execution stages, with no partial response on failure.

    origin_authorized is only exact HTTPS/443 origin preflight permission. It
    never means DNS admission or an attempt succeeded. These Python records
    remain constructible structural data, not authenticated evidence artifacts.
    """

    origin_authorized: bool
    tls_established: bool
    request_send_state: str
    response: BrowserHTTPResponse | None = field(repr=False)
    error_code: str | None

    def __post_init__(self) -> None:
        if type(self.origin_authorized) is not bool or type(self.tls_established) is not bool:
            raise ValueError(_INPUT_ERROR)
        if type(self.request_send_state) is not str or self.request_send_state not in {"not_sent", "unknown", "sent"}:
            raise ValueError(_INPUT_ERROR)
        if self.tls_established and not self.origin_authorized:
            raise ValueError(_INPUT_ERROR)
        if not self.tls_established and self.request_send_state != "not_sent":
            raise ValueError(_INPUT_ERROR)
        if self.error_code is not None:
            if type(self.error_code) is not str or self.error_code not in _ERRORS or self.response is not None:
                raise ValueError(_INPUT_ERROR)
        elif (not self.origin_authorized or not self.tls_established
              or self.request_send_state != "sent" or type(self.response) is not BrowserHTTPResponse):
            raise ValueError(_INPUT_ERROR)

    @property
    def response_validated(self) -> bool:
        return self.response is not None and self.error_code is None


class _Failure(Exception):
    """Internal fixed code; raw peer data and exceptions never leave the API."""


def _check_deadline(deadline: int) -> int:
    remaining = deadline - time.monotonic_ns()
    if remaining <= 0:
        raise _Failure("budget_exceeded")
    return remaining


def _set_timeout(transport: ssl.SSLSocket, deadline: int, limits: BrowserHTTPTransportLimits) -> None:
    transport.settimeout(min(_check_deadline(deadline) / 1_000_000_000, limits.io_timeout_ms / 1_000))


class _Reader:
    def __init__(self, transport: ssl.SSLSocket, deadline: int, limits: BrowserHTTPTransportLimits):
        self.transport = transport
        self.deadline = deadline
        self.limits = limits
        self.buffer = bytearray()
        self.wire_bytes = 0
        self.header_bytes = 0
        self.eof = False

    def receive(self) -> None:
        _set_timeout(self.transport, self.deadline, self.limits)
        maximum = min(4_096, self.limits.max_response_bytes - self.wire_bytes + 1)
        data = self.transport.recv(maximum)
        if type(data) is not bytes or len(data) > maximum:
            raise _Failure("receive_failed")
        self.wire_bytes += len(data)
        _check_deadline(self.deadline)
        if self.wire_bytes > self.limits.max_response_bytes:
            raise _Failure("response_limit")
        if not data:
            self.eof = True
        self.buffer.extend(data)

    def line(self, *, header: bool = False) -> bytes:
        maximum = self.limits.max_header_bytes - self.header_bytes if header else 128
        while True:
            end = self.buffer.find(b"\n")
            if end >= 0:
                if end == 0 or self.buffer[end - 1] != 13:
                    raise _Failure("malformed_response")
                length = end + 1
                if length > maximum:
                    raise _Failure("header_limit" if header else "malformed_response")
                line = bytes(self.buffer[:end - 1])
                del self.buffer[:length]
                if header:
                    self.header_bytes += length
                return line
            if len(self.buffer) >= maximum:
                raise _Failure("header_limit" if header else "malformed_response")
            if self.eof:
                raise _Failure("truncated_response")
            self.receive()

    def exact(self, size: int) -> bytes:
        output = bytearray()
        while len(output) < size:
            if not self.buffer:
                if self.eof:
                    raise _Failure("truncated_response")
                self.receive()
                continue
            amount = min(size - len(output), len(self.buffer))
            output.extend(self.buffer[:amount])
            del self.buffer[:amount]
        return bytes(output)

    def require_eof(self) -> None:
        if self.buffer:
            raise _Failure("unexpected_data")
        if not self.eof:
            self.receive()
        if self.buffer:
            raise _Failure("unexpected_data")


def _read_response(reader: _Reader, method: str) -> BrowserHTTPResponse:
    status_line = reader.line(header=True)
    match = _STATUS.fullmatch(status_line)
    if match is None:
        raise _Failure("malformed_response")
    status = int(match.group(1))
    if not 200 <= status <= 599:
        raise _Failure("unsupported_response")
    headers: list[tuple[str, str]] = []
    singletons: dict[str, str] = {}
    while True:
        line = reader.line(header=True)
        if not line:
            break
        if len(headers) >= reader.limits.max_header_count:
            raise _Failure("header_limit")
        name, value = _header(line)
        if name in _SINGLETONS:
            if name in singletons:
                raise _Failure("ambiguous_framing")
            singletons[name] = value
        if name == "trailer":
            raise _Failure("unsupported_response")
        headers.append((name, value))

    length_text = singletons.get("content-length")
    transfer = singletons.get("transfer-encoding")
    if length_text is not None and transfer is not None:
        raise _Failure("ambiguous_framing")
    length = None
    if length_text is not None:
        if _DECIMAL.fullmatch(length_text) is None or int(length_text) > 2**63 - 1:
            raise _Failure("ambiguous_framing")
        length = int(length_text)
    if transfer is not None and transfer.lower() != "chunked":
        raise _Failure("unsupported_response")
    if singletons.get("content-encoding", "identity").lower() != "identity":
        raise _Failure("unsupported_encoding")
    if "connection" in singletons:
        tokens = [part.strip().lower() for part in singletons["connection"].split(",")]
        if len(tokens) != 1 or tokens[0] not in {"close", "keep-alive"}:
            raise _Failure("ambiguous_framing")
    if status == 204 and (length is not None or transfer is not None):
        raise _Failure("ambiguous_framing")
    if status == 205 and length not in {None, 0}:
        raise _Failure("ambiguous_framing")

    if method == "HEAD" or status in {204, 304}:
        body, framing = b"", "none"
    elif length is not None:
        if length > reader.limits.max_body_bytes:
            raise _Failure("body_limit")
        body, framing = reader.exact(length), "content_length"
    elif transfer is not None:
        output = bytearray()
        chunks = 0
        while True:
            line = reader.line()
            if _HEX.fullmatch(line) is None:
                raise _Failure("unsupported_response")
            size = int(line, 16)
            if size == 0:
                if reader.line() != b"":
                    raise _Failure("unsupported_response")
                break
            if status == 205:
                raise _Failure("ambiguous_framing")
            chunks += 1
            if chunks > reader.limits.max_chunk_count:
                raise _Failure("chunk_limit")
            if len(output) + size > reader.limits.max_body_bytes:
                raise _Failure("body_limit")
            output.extend(reader.exact(size))
            if reader.exact(2) != b"\r\n":
                raise _Failure("malformed_response")
        body, framing = bytes(output), "chunked"
    else:
        output = bytearray()
        while True:
            if status == 205 and reader.buffer:
                raise _Failure("ambiguous_framing")
            if len(output) + len(reader.buffer) > reader.limits.max_body_bytes:
                raise _Failure("body_limit")
            output.extend(reader.buffer)
            reader.buffer.clear()
            if reader.eof:
                break
            reader.receive()
        body, framing = bytes(output), "close"
    if framing != "close":
        # A complete framed response does not require EOF on a persistent
        # connection. Never reuse this connection; reject any overread data.
        if reader.buffer:
            raise _Failure("unexpected_data")
    else:
        reader.require_eof()
    _check_deadline(reader.deadline)
    return BrowserHTTPResponse(status, tuple(headers), body, framing, reader.wire_bytes)


def execute_browser_http_request(
    request: BrowserHTTPRequest,
    allowed_origins: frozenset[BrowserOrigin],
    *, resolution_id: str, authorization_id: str, session_id: str, operation_id: str,
    selected_ip_address: str | None = None,
    limits: BrowserHTTPTransportLimits = BrowserHTTPTransportLimits(),
    broker_limits: broker.BrowserHTTPSBrokerLimits = broker.BrowserHTTPSBrokerLimits(),
) -> BrowserHTTPExchangeResult:
    """Execute one exchange solely through the pinned HTTPS broker.

    Invalid structural inputs raise a constant ValueError before I/O. Expected
    transport/protocol failures return fixed errors and no partial response.
    Programming and process-control exceptions propagate after broker cleanup.
    No caller-supplied DNS result, authorization object, connection or callback
    is accepted. Request content/headers are constructed internally only.
    """
    if type(request) is not BrowserHTTPRequest or type(limits) is not BrowserHTTPTransportLimits:
        raise ValueError(_INPUT_ERROR)
    request = BrowserHTTPRequest(request.origin, request.method, request.static_path, request.query_parameters)
    limits = BrowserHTTPTransportLimits(**{item.name: getattr(limits, item.name) for item in fields(limits)})
    if type(allowed_origins) is not frozenset or not 1 <= len(allowed_origins) <= 16:
        raise ValueError(_INPUT_ERROR)
    allowed_origins = frozenset(_origin(origin) for origin in allowed_origins)
    labels = (resolution_id, authorization_id, session_id, operation_id)
    if any(type(label) is not str or _ID.fullmatch(label) is None for label in labels):
        raise ValueError(_INPUT_ERROR)
    if len(set(labels)) != 4:
        raise ValueError(_INPUT_ERROR)
    if selected_ip_address is not None and (type(selected_ip_address) is not str or len(selected_ip_address) > 64):
        raise ValueError(_INPUT_ERROR)
    if type(broker_limits) is not broker.BrowserHTTPSBrokerLimits:
        raise ValueError(_INPUT_ERROR)
    try:
        broker_limits = broker.BrowserHTTPSBrokerLimits(
            broker_limits.tcp_timeout_ms, broker_limits.tls_timeout_ms,
            broker_limits.establishment_budget_ms, broker_limits.dns_limits,
        )
    except ValueError:
        raise ValueError(_INPUT_ERROR) from None
    preflight = evaluate_browser_network_resolution(request.origin, allowed_origins, ())
    if preflight.reason != "empty_resolution":
        return BrowserHTTPExchangeResult(False, False, "not_sent", None, "origin_not_allowed")

    wire_request = (
        f"{request.method} {_request_target(request.static_path, request.query_parameters)} HTTP/1.1\r\n"
        f"Host: {request.origin.hostname}\r\n"
        "Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    established, send_state, phase = False, "not_sent", "send_failed"
    try:
        with broker.open_browser_https_connection(
            request.origin, allowed_origins, resolution_id=resolution_id,
            authorization_id=authorization_id, session_id=session_id, operation_id=operation_id,
            selected_ip_address=selected_ip_address, limits=broker_limits,
        ) as transport:
            established = True
            deadline = time.monotonic_ns() + limits.exchange_budget_ms * 1_000_000
            _set_timeout(transport, deadline, limits)
            send_state = "unknown"
            transport.sendall(wire_request)
            send_state = "sent"
            _check_deadline(deadline)
            phase = "receive_failed"
            response = _read_response(_Reader(transport, deadline, limits), request.method)
            _check_deadline(deadline)
    except broker.BrowserHTTPSBrokerError as failure:
        return BrowserHTTPExchangeResult(True, established, send_state, None, "broker_" + failure.args[0])
    except _Failure as failure:
        return BrowserHTTPExchangeResult(True, established, send_state, None, failure.args[0])
    except ssl.SSLEOFError:
        return BrowserHTTPExchangeResult(True, established, send_state, None, "tls_truncated")
    except TimeoutError:
        return BrowserHTTPExchangeResult(True, established, send_state, None, "timeout")
    except OSError:
        return BrowserHTTPExchangeResult(True, established, send_state, None, phase)
    return BrowserHTTPExchangeResult(True, True, "sent", response, None)
