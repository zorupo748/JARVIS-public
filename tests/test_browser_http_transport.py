import ast
import inspect
import socket
import ssl
import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import Mock, patch

from jarvis.core import browser_http_transport as http
from jarvis.core import browser_https_broker as broker
from jarvis.core.browser_operation_contract import BrowserOrigin


ORIGIN = BrowserOrigin("https", "example.com", 443)
ALLOWLIST = frozenset({ORIGIN})
PUBLIC_IP = "8.8.8.8"
SOCKET_TYPE = socket.socket
TLS_TYPE = ssl.SSLSocket
CONTEXT_TYPE = ssl.SSLContext
GOOD = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"


def execute(request=None, **overrides):
    arguments = dict(
        request=request if request is not None else http.BrowserHTTPRequest(ORIGIN, "GET", "/page"),
        allowed_origins=ALLOWLIST, resolution_id="resolution-1",
        authorization_id="authorization-1", session_id="session-1", operation_id="operation-1",
    )
    arguments.update(overrides)
    return http.execute_browser_http_request(**arguments)


class StringSubclass(str):
    pass


class IntSubclass(int):
    pass


class TupleSubclass(tuple):
    pass


class SetSubclass(frozenset):
    pass


class OriginSubclass(BrowserOrigin):
    __slots__ = ()


class RequestSubclass(http.BrowserHTTPRequest):
    __slots__ = ()


class Hostile:
    def fail(self, *args, **kwargs):
        raise AssertionError("input callback executed")

    __str__ = __eq__ = __hash__ = __len__ = __iter__ = __call__ = fail

    @property
    def __class__(self):
        return self.fail()


class HTTPTransportTests(unittest.TestCase):
    """Exercise the actual broker/DNS/policy chain with only OS I/O simulated."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.tcp = Mock(spec=SOCKET_TYPE)
        self.tls = Mock(spec=TLS_TYPE)
        self.tcp.getpeername.return_value = (PUBLIC_IP, 443)
        self.tls.getpeername.return_value = (PUBLIC_IP, 443)
        record = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC_IP, 443))
        self.dns = self.stack.enter_context(patch("socket.getaddrinfo", return_value=[record]))
        self.factory = self.stack.enter_context(patch.object(broker.socket, "socket", return_value=self.tcp))
        self.stack.enter_context(patch.object(CONTEXT_TYPE, "load_default_certs", autospec=True))
        self.wrap = self.stack.enter_context(patch.object(CONTEXT_TYPE, "wrap_socket", autospec=True, side_effect=self.wrap_tls))
        self.open_broker = self.stack.enter_context(patch.object(
            broker, "open_browser_https_connection", wraps=broker.open_browser_https_connection,
        ))
        self.now = 0
        self.clock = self.stack.enter_context(patch.object(http.time, "monotonic_ns", side_effect=lambda: self.now))
        self.fragment = 4_096
        self.remaining = GOOD
        self.tls.recv.side_effect = self.receive

    def wrap_tls(self, context, tcp, **kwargs):
        self.tls.context = context
        self.tls.server_hostname = kwargs["server_hostname"]
        return self.tls

    def receive(self, maximum):
        data = self.remaining[:min(maximum, self.fragment)]
        self.remaining = self.remaining[len(data):]
        return data

    def wire(self, value):
        self.remaining = value
        self.tls.recv.side_effect = self.receive

    def assert_error(self, code, *, send_state="sent", established=True, authorized=True, **kwargs):
        result = execute(**kwargs)
        self.assertEqual(result.error_code, code)
        self.assertEqual(result.request_send_state, send_state)
        self.assertIs(result.origin_authorized, authorized)
        self.assertIs(result.tls_established, established)
        self.assertIsNone(result.response)
        self.assertIs(result.response_validated, False)
        self.assertNotIn("INTERNAL_SECRET", repr(result))
        if established:
            self.tls.close.assert_called()
            self.tcp.close.assert_called()
        return result

    def test_get_wire_request_and_valid_response(self):
        result = execute()
        self.assertIs(result.origin_authorized, True)
        self.assertIs(result.tls_established, True)
        self.assertEqual(result.request_send_state, "sent")
        self.assertIs(result.response_validated, True)
        self.assertIsNone(result.error_code)
        self.assertEqual(result.response.status_code, 200)
        self.assertEqual(result.response.body, b"hello")
        self.assertEqual(result.response.headers, (("content-length", "5"), ("content-type", "text/plain")))
        self.assertEqual(result.response.framing, "content_length")
        self.assertEqual(result.response.wire_bytes, len(GOOD))
        self.tls.sendall.assert_called_once_with(
            b"GET /page HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        )
        self.open_broker.assert_called_once()
        self.tls.close.assert_called_once()
        self.tcp.close.assert_called_once()

    def test_head_has_no_body_and_does_not_read_advertised_length(self):
        self.wire(b"HTTP/1.1 200 OK\r\nContent-Length: 9000000\r\n\r\n")
        result = execute(http.BrowserHTTPRequest(ORIGIN, "HEAD"))
        self.assertTrue(result.response_validated)
        self.assertEqual(result.response.body, b"")
        self.assertEqual(result.response.framing, "none")
        self.assertTrue(self.tls.sendall.call_args.args[0].startswith(b"HEAD / HTTP/1.1\r\n"))

    def test_get_and_head_queries_are_encoded_without_changing_destination(self):
        parameters = (("q", "café 😀 &?#=+/%0d%0a"), ("q", ""), ("page", "2"))
        for method in ("GET", "HEAD"):
            with self.subTest(method=method):
                self.wire(GOOD if method == "GET" else GOOD[:-5])
                request = http.BrowserHTTPRequest(ORIGIN, method, "/page", parameters)
                self.assertTrue(execute(request).response_validated)
                wire = self.tls.sendall.call_args.args[0]
                self.assertTrue(wire.startswith(
                    (method + " /page?q=caf%C3%A9%20%F0%9F%98%80%20%26%3F%23%3D%2B%2F%250d%250a&q=&page=2 HTTP/1.1\r\n").encode(),
                ))
                self.assertIn(b"Host: example.com\r\n", wire)
                self.assertEqual(self.tcp.connect.call_args.args[0], (PUBLIC_IP, 443))
                self.assertEqual(self.wrap.call_args.kwargs["server_hostname"], "example.com")
                self.assertEqual(request.query_parameters, parameters)

    def test_complete_zero_length_and_head_do_not_probe_eof(self):
        for method, length in (("GET", 0), ("HEAD", 1000)):
            with self.subTest(method=method):
                self.tls.recv.reset_mock()
                wire = f"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: {length}\r\n\r\n".encode()
                self.tls.recv.side_effect = [wire, ssl.SSLEOFError(8, "INTERNAL_SECRET")]
                result = execute(http.BrowserHTTPRequest(ORIGIN, method))
                self.assertTrue(result.response_validated)
                self.assertEqual(result.response.body, b"")
                self.tls.recv.assert_called_once()

    def test_fragmented_content_length_finishes_on_last_body_byte(self):
        self.tls.recv.side_effect = [GOOD[:-3], b"l", b"lo", TimeoutError("INTERNAL_SECRET")]
        self.assertEqual(execute().response.body, b"hello")
        self.assertEqual(self.tls.recv.call_count, 3)

    def test_complete_chunked_and_bodyless_responses_do_not_probe_eof(self):
        for method, wire in (
            ("GET", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n"),
            ("HEAD", b"HTTP/1.1 200 OK\r\n\r\n"),
            ("HEAD", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
            ("GET", b"HTTP/1.1 204 No Content\r\n\r\n"),
            ("GET", b"HTTP/1.1 304 Not Modified\r\n\r\n"),
        ):
            with self.subTest(method=method, wire=wire):
                self.tls.recv.reset_mock()
                self.tls.recv.side_effect = [wire, TimeoutError("INTERNAL_SECRET")]
                result = execute(http.BrowserHTTPRequest(ORIGIN, method))
                self.assertTrue(result.response_validated)
                self.tls.recv.assert_called_once()

    def test_205_requires_complete_empty_message_framing(self):
        for wire, valid in (
            (b"Content-Length: 0\r\n\r\n", True),
            (b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", True),
            (b"\r\n", True),
            (b"\r\nnonempty", False),
            (b"Transfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n", False),
        ):
            with self.subTest(wire=wire):
                self.wire(b"HTTP/1.1 205 Reset Content\r\n" + wire)
                result = execute()
                self.assertEqual(result.response_validated, valid)
                if not valid:
                    self.assertEqual(result.error_code, "ambiguous_framing")
                    self.assertIsNone(result.response)

    def test_incomplete_chunked_and_unframed_205_cannot_finish_early(self):
        for wire in (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n",
            b"HTTP/1.1 205 Reset Content\r\n\r\n",
        ):
            for error, code in ((TimeoutError(), "timeout"), (ssl.SSLEOFError(), "tls_truncated")):
                with self.subTest(wire=wire, code=code):
                    self.tls.recv.side_effect = [wire, error]
                    self.assert_error(code)

    def test_incomplete_content_length_still_rejects_timeout_and_tls_errors(self):
        for error, code in ((TimeoutError(), "timeout"), (ssl.SSLEOFError(), "tls_truncated"),
                            (ssl.SSLError(), "receive_failed")):
            with self.subTest(code=code):
                self.tls.recv.side_effect = [GOOD[:-1], error]
                self.assert_error(code)

    def test_modified_query_is_revalidated_before_broker(self):
        request = http.BrowserHTTPRequest(ORIGIN, "GET")
        object.__setattr__(request, "query_parameters", (("q", "secret\r\nInjected: yes"),))
        with self.assertRaises(ValueError) as caught:
            execute(request)
        self.assertNotIn("secret", str(caught.exception))
        self.open_broker.assert_not_called()
        self.dns.assert_not_called()

    def test_status_classes_do_not_become_network_errors_or_functional_claims(self):
        for status in (200, 201, 302, 307, 400, 404, 500, 503, 599):
            with self.subTest(status=status):
                self.wire(f"HTTP/1.1 {status} Response\r\nContent-Length: 0\r\n\r\n".encode())
                result = execute()
                self.assertTrue(result.response_validated)
                self.assertEqual(result.response.status_code, status)
                self.assertEqual(result.response.is_redirect, 300 <= status <= 399)
                self.assertFalse(hasattr(result, "sufficient"))

    def test_redirect_is_returned_without_following_or_dns_for_location(self):
        self.wire(b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/private\r\nContent-Length: 0\r\n\r\n")
        result = execute()
        self.assertTrue(result.response.is_redirect)
        self.assertIn(("location", "https://127.0.0.1/private"), result.response.headers)
        self.open_broker.assert_called_once()
        self.dns.assert_called_once()
        self.factory.assert_called_once()
        self.tls.sendall.assert_called_once()

    def test_chunked_response_and_uppercase_hex(self):
        self.wire(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\nA\r\n0123456789\r\n1\r\nx\r\n0\r\n\r\n")
        result = execute()
        self.assertEqual(result.response.body, b"0123456789x")
        self.assertEqual(result.response.framing, "chunked")

    def test_fragmented_headers_body_and_chunk_framing(self):
        self.fragment = 1
        for wire, expected in (
            (GOOD, b"hello"),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n", b"hi"),
        ):
            with self.subTest(wire=wire):
                self.wire(wire)
                self.assertEqual(execute().response.body, expected)

    def test_close_delimited_response_requires_clean_eof(self):
        self.wire(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello")
        result = execute()
        self.assertEqual(result.response.body, b"hello")
        self.assertEqual(result.response.framing, "close")
        self.assertIs(self.wrap.call_args.kwargs["suppress_ragged_eofs"], False)

    def test_bodyless_statuses(self):
        for status, headers in ((204, b""), (205, b"Content-Length: 0\r\n"), (304, b"Content-Length: 300\r\n")):
            with self.subTest(status=status):
                self.wire(f"HTTP/1.1 {status} No body\r\n".encode() + headers + b"\r\n")
                result = execute()
                self.assertEqual(result.response.body, b"")
                self.assertEqual(result.response.framing, "content_length" if status == 205 else "none")
                self.assertFalse(result.response.is_redirect)

    def test_response_headers_normalized_binary_body_preserved_and_no_cookie_replay(self):
        self.wire(b"HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 3\r\nX-Note: \tvalue\t \r\nSet-Cookie: secret=INTERNAL_SECRET\r\n\r\n\x00\xffx")
        result = execute()
        self.assertEqual(result.response.body, b"\x00\xffx")
        self.assertIn(("x-note", "value"), result.response.headers)
        self.assertNotIn("INTERNAL_SECRET", repr(result.response))
        self.wire(GOOD)
        execute()
        for call in self.tls.sendall.call_args_list:
            self.assertNotIn(b"secret", call.args[0])
            self.assertNotIn(b"Cookie:", call.args[0])

    def test_invalid_status_lines_and_bare_lf_are_rejected(self):
        for wire in (
            b"HTTP/1.0 200 OK\r\n\r\n", b"HTTP/2 200 OK\r\n\r\n",
            b"HTTP/1.1 20 OK\r\n\r\n", b"HTTP/1.1 200\r\n\r\n",
            b"HTTP/1.1 200 OK\n\n", b"HTTP/1.1 200 Bad\x00\r\n\r\n",
            b" HTTP/1.1 200 OK\r\n\r\n",
        ):
            with self.subTest(wire=wire):
                self.wire(wire)
                self.assert_error("malformed_response")

    def test_informational_upgrade_and_invalid_statuses_are_unsupported(self):
        for status in (100, 101, 103, 199, 600, 999):
            with self.subTest(status=status):
                self.wire(f"HTTP/1.1 {status} Status\r\n\r\n".encode())
                self.assert_error("unsupported_response")

    def test_malformed_headers_and_obs_fold_are_rejected(self):
        for header in (b"NoColon", b": empty", b"Name : value", b" folded", b"X: a\x00b", b"X: a\x7fb", b"X: \xff", b"X: a\rb"):
            with self.subTest(header=header):
                self.wire(b"HTTP/1.1 200 OK\r\n" + header + b"\r\n\r\n")
                self.assert_error("malformed_response")

    def test_duplicate_lengths_and_te_cl_are_ambiguous_even_for_head(self):
        for headers in (
            b"Content-Length: 5\r\nContent-Length: 5\r\n",
            b"Content-Length: 5\r\ncontent-length: 4\r\n",
            b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
            b"Transfer-Encoding: chunked\r\ntransfer-encoding: chunked\r\n",
        ):
            for method in ("GET", "HEAD"):
                with self.subTest(headers=headers, method=method):
                    self.wire(b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n")
                    self.assert_error("ambiguous_framing", request=http.BrowserHTTPRequest(ORIGIN, method))

    def test_invalid_content_length_formats(self):
        for length in (b"-1", b"+5", b"5, 5", b"5x", b"", b"1 0", b"9" * 100, b"9223372036854775808"):
            with self.subTest(length=length):
                self.wire(b"HTTP/1.1 200 OK\r\nContent-Length: " + length + b"\r\n\r\n")
                self.assert_error("ambiguous_framing")

    def test_unsupported_transfer_codings_compression_and_trailers(self):
        for header, code in (
            (b"Transfer-Encoding: gzip, chunked", "unsupported_response"),
            (b"Transfer-Encoding: chunked, chunked", "unsupported_response"),
            (b"Transfer-Encoding: identity", "unsupported_response"),
            (b"Trailer: X-Checksum", "unsupported_response"),
            (b"Content-Encoding: gzip", "unsupported_encoding"),
            (b"Content-Encoding: br", "unsupported_encoding"),
        ):
            with self.subTest(header=header):
                self.wire(b"HTTP/1.1 200 OK\r\n" + header + b"\r\n\r\n")
                self.assert_error(code)

    def test_connection_header_cannot_redefine_framing_or_upgrade(self):
        for value in (b"content-length", b"upgrade", b"close, keep-alive", b"close, close", b""):
            with self.subTest(value=value):
                self.wire(b"HTTP/1.1 200 OK\r\nConnection: " + value + b"\r\n\r\n")
                self.assert_error("ambiguous_framing")

    def test_truncated_status_headers_fixed_length_and_chunks(self):
        for wire in (
            b"", b"HTTP/1.1 200 OK\r", b"HTTP/1.1 200 OK\r\nX: unfinished",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhi",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n",
        ):
            with self.subTest(wire=wire):
                self.wire(wire)
                self.assert_error("truncated_response")

    def test_chunk_extensions_trailers_and_invalid_hex_are_rejected(self):
        prefix = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        for chunks, code in (
            (b"2;foo=bar\r\nhi\r\n0\r\n\r\n", "unsupported_response"),
            (b"-1\r\n", "unsupported_response"),
            (b"z\r\n", "unsupported_response"),
            (b" 2\r\n", "unsupported_response"),
            (b"2\r\nhiXX", "malformed_response"),
            (b"0\r\nX-Trailer: value\r\n\r\n", "unsupported_response"),
            (b"1" * 129, "malformed_response"),
        ):
            with self.subTest(chunks=chunks):
                self.wire(prefix + chunks)
                self.assert_error(code)

    def test_extra_data_after_fixed_chunked_head_or_bodyless_is_rejected(self):
        for wire, method in (
            (GOOD + b"x", "GET"),
            (GOOD + b"HTTP/1.1 200 OK\r\n\r\n", "GET"),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nx", "GET"),
            (GOOD, "HEAD"),
            (b"HTTP/1.1 204 No Content\r\n\r\nx", "GET"),
        ):
            with self.subTest(wire=wire, method=method):
                self.wire(wire)
                self.assert_error("unexpected_data", request=http.BrowserHTTPRequest(ORIGIN, method))

    def test_illegal_framing_on_204_and_205(self):
        for status, header in ((204, b"Content-Length: 0"), (204, b"Transfer-Encoding: chunked"), (205, b"Content-Length: 1")):
            with self.subTest(status=status, header=header):
                self.wire(f"HTTP/1.1 {status} Empty\r\n".encode() + header + b"\r\n\r\n")
                self.assert_error("ambiguous_framing")

    def test_header_byte_and_count_limits_are_inclusive(self):
        headers = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\n"
        limits = http.BrowserHTTPTransportLimits(max_header_bytes=len(headers), max_header_count=2)
        self.assertTrue(execute(limits=limits).response_validated)
        self.wire(GOOD)
        self.assert_error("header_limit", limits=replace(limits, max_header_bytes=len(headers) - 1))
        self.wire(GOOD)
        self.assert_error("header_limit", limits=replace(limits, max_header_count=1))

    def test_unterminated_oversized_headers_are_bounded(self):
        self.wire(b"HTTP/1.1 200 OK\r\nX: " + b"x" * 1000)
        self.assert_error("header_limit", limits=http.BrowserHTTPTransportLimits(max_header_bytes=64))

    def test_body_limits_for_each_framing_and_exact_boundary(self):
        self.assertTrue(execute(limits=http.BrowserHTTPTransportLimits(max_body_bytes=5)).response_validated)
        for wire in (
            GOOD,
            b"HTTP/1.1 200 OK\r\n\r\nhello",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        ):
            with self.subTest(wire=wire):
                self.wire(wire)
                self.assert_error("body_limit", limits=http.BrowserHTTPTransportLimits(max_body_bytes=4))

    def test_wire_size_limits_include_chunk_overhead_and_are_inclusive(self):
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n"
        self.wire(wire)
        self.assertTrue(execute(limits=http.BrowserHTTPTransportLimits(max_response_bytes=len(wire))).response_validated)
        self.wire(wire)
        self.assert_error("response_limit", limits=http.BrowserHTTPTransportLimits(max_response_bytes=len(wire) - 1))

    def test_chunk_count_bounds_work_for_tiny_chunks(self):
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n1\r\nb\r\n0\r\n\r\n"
        self.wire(wire)
        self.assertTrue(execute(limits=http.BrowserHTTPTransportLimits(max_chunk_count=2)).response_validated)
        self.wire(wire)
        self.assert_error("chunk_limit", limits=http.BrowserHTTPTransportLimits(max_chunk_count=1))

    def test_timeout_during_send_retains_unknown_send_state(self):
        self.tls.sendall.side_effect = TimeoutError("INTERNAL_SECRET")
        self.assert_error("timeout", send_state="unknown")
        self.tls.recv.assert_not_called()

    def test_send_failure_is_not_reported_as_not_sent_or_as_a_response(self):
        self.tls.sendall.side_effect = BrokenPipeError("INTERNAL_SECRET")
        self.assert_error("send_failed", send_state="unknown")

    def test_receive_timeout_and_connection_reset(self):
        for exception, code in ((TimeoutError("INTERNAL_SECRET"), "timeout"), (ConnectionResetError("INTERNAL_SECRET"), "receive_failed")):
            with self.subTest(code=code):
                self.tls.recv.side_effect = exception
                self.assert_error(code)

    def test_timeout_configuration_failure_does_not_claim_sending(self):
        original = self.tls.settimeout.side_effect
        # The first settimeout belongs to the broker's TLS establishment; the
        # second is the HTTP send stage after verified handoff.
        self.tls.settimeout.side_effect = [None, OSError("INTERNAL_SECRET")]
        self.assert_error("send_failed", send_state="not_sent")
        self.tls.sendall.assert_not_called()
        self.tls.settimeout.side_effect = original

    def test_ragged_tls_eof_never_finishes_close_delimited_or_incomplete_fixed_responses(self):
        for wire in (b"HTTP/1.1 200 OK\r\n\r\npartial", GOOD[:-1]):
            with self.subTest(wire=wire):
                self.tls.recv.side_effect = [wire, ssl.SSLEOFError(8, "INTERNAL_SECRET")]
                self.assert_error("tls_truncated")

    def test_complete_content_length_does_not_wait_for_persistent_peer(self):
        self.tls.recv.side_effect = [GOOD, TimeoutError("INTERNAL_SECRET")]
        self.assertTrue(execute().response_validated)
        self.tls.recv.assert_called_once()
        self.tls.close.assert_called_once()

    def test_monotonic_budget_caps_io_and_rejects_late_send(self):
        limits = http.BrowserHTTPTransportLimits(io_timeout_ms=5000, exchange_budget_ms=1000)
        self.tls.sendall.side_effect = lambda data: setattr(self, "now", 1_000_000_000)
        self.assert_error("budget_exceeded", limits=limits)
        self.assertEqual(self.tls.settimeout.call_args_list[-1].args, (1.0,))
        self.tls.recv.assert_not_called()

    def test_slow_trickle_cannot_reset_the_exchange_budget(self):
        limits = http.BrowserHTTPTransportLimits(io_timeout_ms=5000, exchange_budget_ms=1000)
        self.fragment = 1
        def slow(maximum):
            self.now += 100_000_000
            return self.receive(maximum)
        self.tls.recv.side_effect = slow
        self.assert_error("budget_exceeded", limits=limits)
        self.assertLessEqual(self.tls.recv.call_count, 10)
        self.assertEqual(self.tls.settimeout.call_args_list[-1].args, (0.1,))

    def test_late_eof_and_parser_work_cannot_produce_success(self):
        self.wire(b"HTTP/1.1 200 OK\r\n\r\nhello")
        def late(maximum):
            data = self.receive(maximum)
            if not data:
                self.now = 15_000_000_001
            return data
        self.tls.recv.side_effect = late
        self.assert_error("budget_exceeded")

    def test_dns_and_handshake_errors_never_claim_tls_or_sending(self):
        self.dns.side_effect = socket.gaierror("INTERNAL_SECRET")
        self.assert_error("broker_dns_failed", send_state="not_sent", established=False)
        self.factory.assert_not_called()
        self.dns.side_effect = None
        self.tls.do_handshake.side_effect = ssl.SSLCertVerificationError(1, "INTERNAL_SECRET")
        self.assert_error("broker_tls_failed", send_state="not_sent", established=False)
        self.tls.sendall.assert_not_called()
        self.tls.close.assert_called()

    def test_unauthorized_origin_is_rejected_before_broker_and_dns(self):
        request = http.BrowserHTTPRequest(BrowserOrigin("https", "other.example", 443), "GET")
        self.assert_error("origin_not_allowed", request=request, send_state="not_sent", established=False, authorized=False)
        self.open_broker.assert_not_called()
        self.dns.assert_not_called()
        self.factory.assert_not_called()

    def test_non_admitted_selection_never_connects_or_sends(self):
        for ip in ("1.1.1.1", "127.0.0.1", "169.254.169.254", "::ffff:8.8.8.8"):
            with self.subTest(ip=ip):
                self.assert_error("broker_destination_denied", send_state="not_sent", established=False, selected_ip_address=ip)
                self.factory.assert_not_called()
                self.tls.sendall.assert_not_called()

    def test_mixed_dns_resolution_blocks_the_entire_operation(self):
        private = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
        self.dns.return_value = self.dns.return_value + [private]
        self.assert_error("broker_resolution_denied", send_state="not_sent", established=False)
        self.factory.assert_not_called()
        self.tls.sendall.assert_not_called()

    def test_actual_peer_mismatch_prevents_http(self):
        self.tls.getpeername.return_value = ("1.1.1.1", 443)
        self.assert_error("broker_peer_mismatch", send_state="not_sent", established=False)
        self.tls.sendall.assert_not_called()

    def test_no_http_bytes_precede_handshake_and_post_tls_peer_validation(self):
        events = []
        self.tls.do_handshake.side_effect = lambda: events.append("handshake")
        def peer():
            events.append("peer_checked")
            return (PUBLIC_IP, 443)
        self.tls.getpeername.side_effect = peer
        self.tls.sendall.side_effect = lambda data: events.append("http_sent")
        self.assertTrue(execute().response_validated)
        self.assertEqual(events, ["handshake", "peer_checked", "http_sent"])

    def test_numeric_pinning_sni_tls_and_one_resolution_are_preserved(self):
        result = execute()
        self.assertTrue(result.response_validated)
        self.dns.assert_called_once_with("example.com", 443, family=socket.AF_UNSPEC,
                                         type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP, flags=0)
        self.tcp.connect.assert_called_once_with((PUBLIC_IP, 443))
        self.assertEqual(self.wrap.call_args.kwargs["server_hostname"], "example.com")
        context = self.wrap.call_args.args[0]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertIsNone(context.keylog_filename)
        self.tls.do_handshake.assert_called_once()
        self.tls.getpeername.assert_called_once()

    def test_ipv6_selected_ip_is_passed_to_broker_without_new_resolution(self):
        ip = "2606:4700:4700::1111"
        self.dns.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443, 0, 0))]
        self.tcp.getpeername.return_value = self.tls.getpeername.return_value = (ip, 443, 0, 0)
        self.assertTrue(execute(selected_ip_address=ip).response_validated)
        self.tcp.connect.assert_called_once_with((ip, 443, 0, 0))
        self.dns.assert_called_once()

    def test_cleanup_error_discards_even_a_validated_response(self):
        self.tls.close.side_effect = OSError("INTERNAL_SECRET")
        self.assert_error("broker_cleanup_failed")
        self.tcp.close.assert_called_once()
        self.tls.close.side_effect = None
        self.wire(GOOD)
        self.assertTrue(execute().response_validated)

    def test_programming_and_control_exceptions_propagate_after_cleanup(self):
        for error in (RuntimeError("programming error"), KeyboardInterrupt()):
            with self.subTest(error_type=type(error)):
                self.tls.recv.side_effect = error
                with self.assertRaises(type(error)) as caught:
                    execute()
                self.assertIs(caught.exception, error)
                self.tls.close.assert_called()
                self.tcp.close.assert_called()
        self.wire(GOOD)
        self.assertTrue(execute().response_validated)

    def test_no_alternative_clients_reconnections_callbacks_proxies_or_logging(self):
        targets = (
            "socket.create_connection", "socket.gethostbyname", "socket.gethostbyname_ex",
            "socket.setdefaulttimeout", "urllib.request.urlopen", "urllib.request.getproxies",
            "http.client.HTTPConnection.connect", "http.client.HTTPSConnection.connect",
            "http.client.HTTPConnection.request", "ssl.create_default_context", "logging.Logger._log",
        )
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(name, side_effect=AssertionError("alternate I/O"))) for name in targets]
            self.assertTrue(execute().response_validated)
            for guard in guards:
                guard.assert_not_called()
        self.tls.connect.assert_not_called()
        self.tls.makefile.assert_not_called()
        self.tls.unwrap.assert_not_called()
        self.factory.assert_called_once()

    def test_broker_denial_cannot_fall_back_to_another_transport(self):
        self.open_broker.side_effect = broker.BrowserHTTPSBrokerError("broker_busy")
        self.assert_error("broker_broker_busy", send_state="not_sent", established=False)
        self.dns.assert_not_called()
        self.factory.assert_not_called()

    def test_no_second_request_while_existing_broker_slot_is_active(self):
        with broker.open_browser_https_connection(
            ORIGIN, ALLOWLIST, resolution_id="resolution-active", authorization_id="authorization-active",
            session_id="session-active", operation_id="operation-active",
        ):
            self.assert_error("broker_broker_busy", send_state="not_sent", established=False)
            self.tls.sendall.assert_not_called()
            self.factory.assert_called_once()
            self.dns.assert_called_once()

    def test_invalid_request_or_limits_are_revalidated_before_io(self):
        request = http.BrowserHTTPRequest(ORIGIN, "GET")
        object.__setattr__(request, "method", "GET\r\nInjected: value")
        limits = http.BrowserHTTPTransportLimits()
        object.__setattr__(limits, "max_body_bytes", True)
        for arguments in ({"request": request}, {"limits": limits}, {"request": RequestSubclass(ORIGIN, "GET")}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                execute(**arguments)
        self.open_broker.assert_not_called()
        self.dns.assert_not_called()

    def test_invalid_allowlists_ids_and_selection_types_never_call_broker(self):
        for value in ([], {ORIGIN}, SetSubclass({ORIGIN}), frozenset(), frozenset({"DO_NOT_LEAK"})):
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError):
                execute(allowed_origins=value)
        for name in ("resolution_id", "authorization_id", "session_id", "operation_id"):
            for value in ("", "DO_NOT_LEAK/SECRET", "x" * 129, StringSubclass("local"), Hostile()):
                with self.subTest(name=name, value_type=type(value)), self.assertRaises(ValueError) as caught:
                    execute(**{name: value})
                self.assertEqual(str(caught.exception), "invalid browser HTTP transport input")
        with self.assertRaises(ValueError):
            execute(operation_id="session-1")
        for value in (StringSubclass(PUBLIC_IP), Hostile(), "x" * 65):
            with self.assertRaises(ValueError):
                execute(selected_ip_address=value)
        self.open_broker.assert_not_called()
        self.dns.assert_not_called()

    def test_no_caller_injected_headers_bodies_connection_resolver_or_authorization(self):
        callback = Mock(side_effect=AssertionError("callback executed"))
        for name in ("headers", "body", "cookies", "token", "connection", "socket", "resolver", "ssl_context", "authorization", "admission"):
            with self.subTest(name=name), self.assertRaises(TypeError):
                execute(**{name: callback})
        callback.assert_not_called()
        self.open_broker.assert_not_called()


class HTTPStructuralTests(unittest.TestCase):
    def test_query_structure_controls_and_types_are_rejected(self):
        for parameters in (
            [], "q=1", TupleSubclass(), (("q",),), (["q", "1"],),
            ((StringSubclass("q"), "1"),), (("q", StringSubclass("1")),),
            (("q", Hostile()),), (("q", 1),), (("", "1"),), (("q name", "1"),),
            (("q\r\nHost", "1"),), (("https://other.example", "1"),),
            (("q", "x\r\nInjected: yes"),), (("q", "\x00"),), (("q", "\x7f"),),
            (("q", "\x85"),), (("q", "\ud800"),),
        ):
            with self.subTest(parameter_type=type(parameters)), self.assertRaises(ValueError) as caught:
                http.BrowserHTTPRequest(ORIGIN, "GET", query_parameters=parameters)
            self.assertEqual(str(caught.exception), "invalid browser HTTP transport input")

    def test_query_bounds_and_repr_are_safe(self):
        parameters = tuple((f"p{i}", "") for i in range(64))
        self.assertEqual(http.BrowserHTTPRequest(ORIGIN, "GET", query_parameters=parameters).query_parameters, parameters)
        self.assertEqual(http.BrowserHTTPRequest(ORIGIN, "GET", query_parameters=(("n" * 64, "x" * 1024),)).method, "GET")
        for parameters in (
            parameters + (("extra", ""),), (("n" * 65, ""),), (("q", "x" * 1025),),
            (("q", "😀" * 513),), tuple((f"p{i}", "x" * 1024) for i in range(8)),
        ):
            with self.subTest(count=len(parameters)), self.assertRaises(ValueError):
                http.BrowserHTTPRequest(ORIGIN, "GET", query_parameters=parameters)
        request = http.BrowserHTTPRequest(ORIGIN, "GET", query_parameters=(("q", "DO_NOT_LEAK_VALUE"),))
        self.assertNotIn("DO_NOT_LEAK_VALUE", repr(request))
        self.assertEqual(hash(request), hash(replace(request)))

    def test_request_rejects_method_path_and_origin_injection(self):
        for method in ("get", "POST", "GET\r\nX: value", "GET /", "GET\t", None, StringSubclass("GET"), Hostile()):
            with self.subTest(method_type=type(method)), self.assertRaises(ValueError):
                http.BrowserHTTPRequest(ORIGIN, method)
        for path in ("", "//other.example/", "/a/../b", "/a%0d%0aX:value", "/?token=secret", "/#fragment", "/\r\nX:value", "/a b", "https://other.example/", "/" + "x" * 2048, StringSubclass("/"), Hostile()):
            with self.subTest(path_type=type(path)), self.assertRaises(ValueError):
                http.BrowserHTTPRequest(ORIGIN, "GET", path)
        for origin in (BrowserOrigin("http", "example.com", 80), BrowserOrigin("https", "example.com", 8443), OriginSubclass("https", "example.com", 443), "https://example.com", Hostile()):
            with self.subTest(origin_type=type(origin)), self.assertRaises(ValueError):
                http.BrowserHTTPRequest(origin, "GET")

    def test_nested_origin_string_subclasses_are_not_executed(self):
        origin = BrowserOrigin(StringSubclass("https"), StringSubclass("example.com"), 443)
        with self.assertRaises(ValueError):
            http.BrowserHTTPRequest(origin, "GET")

    def test_limits_are_exact_bounded_and_replace_revalidates(self):
        limits = http.BrowserHTTPTransportLimits()
        maxima = dict(io_timeout_ms=60000, exchange_budget_ms=60000, max_header_bytes=65536,
                      max_header_count=256, max_body_bytes=16777216, max_response_bytes=33554432,
                      max_chunk_count=65536)
        for name, maximum in maxima.items():
            self.assertEqual(getattr(replace(limits, **{name: 1}), name), 1)
            self.assertEqual(getattr(replace(limits, **{name: maximum}), name), maximum)
            for value in (0, -1, maximum + 1, True, False, 1.0, None, IntSubclass(1), Hostile()):
                with self.subTest(name=name, value_type=type(value)), self.assertRaises(ValueError):
                    replace(limits, **{name: value})

    def test_result_stage_coherence_and_no_partial_response(self):
        response = http.BrowserHTTPResponse(200, (), b"", "close", 19)
        valid = http.BrowserHTTPExchangeResult(True, True, "sent", response, None)
        self.assertTrue(valid.response_validated)
        for arguments in (
            (False, True, "sent", response, None), (True, False, "sent", None, "timeout"),
            (True, True, "unknown", response, None), (True, True, "sent", response, "timeout"),
            (True, True, "sent", None, None), (1, True, "sent", response, None),
            (True, True, "sent", None, "INTERNAL_SECRET"),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                http.BrowserHTTPExchangeResult(*arguments)

    def test_response_fields_are_immutable_bounded_and_do_not_leak_in_repr(self):
        response = http.BrowserHTTPResponse(200, (("set-cookie", "INTERNAL_SECRET"),), b"INTERNAL_SECRET", "close", 100)
        self.assertNotIn("INTERNAL_SECRET", repr(response))
        for arguments in (
            (True, (), b"", "close", 0), (200, [], b"", "close", 0),
            (200, (("X", "value"),), b"", "close", 0),
            (200, (("x", "injected\r\nvalue"),), b"", "close", 0),
            (200, (), bytearray(), "close", 0), (200, (), b"x", "none", 1),
            (200, (), b"x", "close", 0),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                http.BrowserHTTPResponse(*arguments)

    def test_public_records_are_frozen_slots_and_hashable(self):
        records = (
            http.BrowserHTTPRequest(ORIGIN, "GET"), http.BrowserHTTPTransportLimits(),
            http.BrowserHTTPResponse(200, (), b"", "close", 19),
            http.BrowserHTTPExchangeResult(True, False, "not_sent", None, "broker_dns_failed"),
        )
        for record in records:
            self.assertFalse(hasattr(record, "__dict__"))
            self.assertEqual(hash(record), hash(replace(record)))
            with self.assertRaises(FrozenInstanceError):
                setattr(record, fields(record)[0].name, None)

    def test_http_layer_imports_have_no_network_client_or_socket_factory(self):
        imports = set()
        for node in ast.walk(ast.parse(inspect.getsource(http))):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module)
        self.assertEqual(imports, {
            "__future__", "re", "ssl", "time", "dataclasses", "jarvis.core",
            "urllib.parse",
            "jarvis.core.browser_network_policy", "jarvis.core.browser_operation_contract",
        })


if __name__ == "__main__":
    unittest.main()
