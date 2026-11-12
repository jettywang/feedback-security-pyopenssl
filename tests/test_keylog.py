# Copyright (c) The pyOpenSSL developers
# See LICENSE for details.

"""
Tests for per-connection, explicitly authorized TLS key logging in
:mod:`OpenSSL.keylog`.
"""

from __future__ import annotations

import os
import re
import threading
from typing import Any

import pytest

from OpenSSL import crypto
from OpenSSL._util import lib as _lib
from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.keylog import FileKeyLogSink, KeyLogAuthority
from OpenSSL.SSL import (
    Connection,
    Context,
    TLSv1_2_METHOD,
    WantReadError,
)

from . import conftest
from .test_crypto import root_cert_pem, root_key_pem

keylog_available = pytest.mark.skipif(
    not getattr(_lib, "Cryptography_HAS_KEYLOG", 0),
    reason="SSL_CTX_set_keylog_callback unavailable",
)
renegotiation_available = pytest.mark.skipif(
    conftest.is_awslc,
    reason="aws-lc doesn't support renegotiation",
)


# NSS SSLKEYLOGFILE lines look like "<LABEL> <client-random hex> <secret hex>".
# TLS 1.2 emits CLIENT_RANDOM; TLS 1.3 emits labels such as
# CLIENT_HANDSHAKE_TRAFFIC_SECRET.
_KEYLOG_LINE = rb"^[A-Z_]+ [0-9a-f]+ [0-9a-f]+$"


def _server_context(authority: KeyLogAuthority) -> Context:
    """
    Build one shared server context with the authority installed.
    """
    context = Context(TLSv1_2_METHOD)
    context.use_certificate(
        crypto.load_certificate(FILETYPE_PEM, root_cert_pem)
    )
    context.use_privatekey(crypto.load_privatekey(FILETYPE_PEM, root_key_pem))
    authority.install(context)
    return context


def _client_context() -> Context:
    context = Context(TLSv1_2_METHOD)
    context.use_certificate(
        crypto.load_certificate(FILETYPE_PEM, root_cert_pem)
    )
    context.use_privatekey(crypto.load_privatekey(FILETYPE_PEM, root_key_pem))
    return context


def _client_random_hex(connection: Connection) -> bytes:
    """
    Return a finished connection's client random as lowercase hex bytes.
    """
    random = connection.client_random()
    assert random is not None
    return random.hex().encode()


class _BioPair:
    """
    A server/client connection pair wired together through memory BIOs.
    """

    def __init__(self, server_context: Context) -> None:
        self.server = Connection(server_context, None)
        self.server.set_accept_state()
        self.client = Connection(_client_context(), None)
        self.client.set_connect_state()

    def _pump(self, source: Connection, sink: Connection) -> None:
        while True:
            try:
                chunk = source.bio_read(65536)
            except WantReadError:
                return
            sink.bio_write(chunk)

    def pump(self) -> None:
        self._pump(self.server, self.client)
        self._pump(self.client, self.server)

    def step_handshake(self) -> None:
        for connection in (self.client, self.server):
            try:
                connection.do_handshake()
            except WantReadError:
                pass

    def handshake(self, max_steps: int = 50) -> None:
        for _ in range(max_steps):
            self.step_handshake()
            if self.server.get_finished() and self.client.get_finished():
                return
            self.pump()
        raise AssertionError("memory BIO handshake did not converge")

    def renegotiate(self) -> None:
        """
        Drive a server-initiated renegotiation over the memory BIOs.

        Data is pumped first so the client actually sees the server's
        HelloRequest.  The client is driven before the server each round and
        convergence is judged by the *client* leaving the renegotiation
        state: current OpenSSL builds leave the server's
        ``renegotiate_pending`` flag set even after the handshake has
        completed, while the client clears it promptly and application data
        flows normally in both directions afterwards.
        """
        before = self.server.total_renegotiations()
        assert self.server.renegotiate() is True
        for _ in range(50):
            self.pump()
            for connection in (self.client, self.server):
                try:
                    connection.do_handshake()
                except WantReadError:
                    pass
            self.pump()
            if (
                self.server.total_renegotiations() > before
                and not self.client.renegotiate_pending()
            ):
                return
        raise AssertionError("renegotiation did not converge")

    def exchange(self, payload: bytes) -> None:
        self._transfer(self.server, self.client, payload)
        self._transfer(self.client, self.server, payload)

    def exchange_client_first(self, payload: bytes) -> None:
        # After a renegotiation the client side settles first; sending from
        # the client avoids the server's sticky renegotiation flag.
        self._transfer(self.client, self.server, payload)
        self._transfer(self.server, self.client, payload)

    def _transfer(
        self, sender: Connection, receiver: Connection, payload: bytes
    ) -> None:
        sender.send(payload)
        for _ in range(20):
            self.pump()
            try:
                got = receiver.recv(len(payload))
            except WantReadError:
                continue
            assert got == payload
            return
        raise AssertionError("data did not traverse the memory BIOs")


class RecordingSink:
    """
    Sink that records every line it receives, for assertions.
    """

    def __init__(self) -> None:
        self.lines: list[bytes] = []

    def write_line(self, line: bytes) -> None:
        self.lines.append(line)


class FailingSink:
    """
    Sink that always raises, carrying the secret in its exception text so we
    can prove the diagnostic path does not propagate that text.
    """

    def __init__(self, secret_line: bytes) -> None:
        self._secret_line = secret_line

    def write_line(self, line: bytes) -> None:
        raise RuntimeError(f"boom while writing {self._secret_line!r}")

    def flush(self) -> None:
        raise RuntimeError("boom while flushing")


class BlockingSink:
    """
    Sink whose ``write_line`` blocks until an event is set, used to exercise
    revoke() from another thread while a write is in flight.
    """

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.lines: list[bytes] = []

    def write_line(self, line: bytes) -> None:
        self.lines.append(line)
        self.entered.set()
        self.release.wait(timeout=10)


class BufferingSink:
    """
    Sink that buffers accepted lines and only drains them on ``flush()``.
    """

    def __init__(self) -> None:
        self._buffered: list[bytes] = []
        self.flushed: list[bytes] = []

    def write_line(self, line: bytes) -> None:
        self._buffered.append(line)

    def flush(self) -> None:
        self.flushed.extend(self._buffered)
        self._buffered = []


@keylog_available
class TestKeyLogAuthority:
    def test_install_enables_nothing_by_default(self) -> None:
        """
        Installing the context-wide callback logs nothing: a handshake on an
        unauthorized connection produces no sink traffic and is counted as
        refused.
        """
        authority = KeyLogAuthority()
        context = _server_context(authority)
        pair = _BioPair(context)

        pair.handshake()

        assert authority.delivered == 0
        assert authority.refused >= 1
        assert authority.sink_failures == 0
        assert authority.is_authorized(pair.server) is False

    def test_sslkeylogfile_environment_is_ignored(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        """
        Pointing SSLKEYLOGFILE at a path must not implicitly turn on key
        logging: no file is created and lines are still refused.
        """
        target = tmp_path / "env-keylog.txt"
        monkeypatch.setenv("SSLKEYLOGFILE", str(target))

        authority = KeyLogAuthority()
        context = _server_context(authority)
        pair = _BioPair(context)
        pair.handshake()

        assert not target.exists()
        assert authority.delivered == 0
        assert authority.refused >= 1

    def test_shared_context_interleaved_authorization(self) -> None:
        """
        Two real memory-BIO handshakes share one server context and are
        driven in lock-step so their key log callbacks interleave.  Only one
        connection is authorized; its lines reach the sink and are valid
        NSS key log lines, while the other connection's lines are refused
        and never appear.
        """
        authority = KeyLogAuthority()
        context = _server_context(authority)
        first = _BioPair(context)
        second = _BioPair(context)

        authorized_sink = RecordingSink()
        authority.authorize(first.server, authorized_sink)

        # Interleave the two handshakes: one step of each per round.
        for _ in range(50):
            first.step_handshake()
            second.step_handshake()
            first.pump()
            second.pump()
            if (
                first.server.get_finished()
                and first.client.get_finished()
                and second.server.get_finished()
                and second.client.get_finished()
            ):
                break
        else:  # pragma: no cover
            raise AssertionError("interleaved handshakes did not converge")

        # Post-handshake application data still works on both connections.
        first.exchange(b"one")
        second.exchange(b"two")

        authorized_random = _client_random_hex(first.server)
        unauthorized_random = _client_random_hex(second.server)

        assert authorized_sink.lines, "authorized connection logged nothing"
        assert authority.delivered == len(authorized_sink.lines)
        # The shared callback also fired for the unauthorized connection.
        assert authority.refused >= 1

        joined = b"\n".join(authorized_sink.lines)
        assert authorized_random in joined
        assert unauthorized_random not in joined

        # Every emitted line is a recognizable SSLKEYLOGFILE entry, so
        # Wireshark/tshark and similar debug tooling can parse it.
        for line in authorized_sink.lines:
            assert re.fullmatch(_KEYLOG_LINE, line)
            assert line.startswith(b"CLIENT_RANDOM ")

    def test_unauthorized_connection_never_reaches_sink(self) -> None:
        authority = KeyLogAuthority()
        context = _server_context(authority)
        pair = _BioPair(context)
        sink = RecordingSink()
        # Note: no authorize() call at all.
        pair.handshake()
        assert sink.lines == []

    @renegotiation_available
    def test_revoke_seals_connection_before_more_key_material(self) -> None:
        """
        After revoke() returns, the connection keeps working through a
        renegotiation and further data exchange, yet nothing new reaches the
        sink.  Lines legitimately emitted during the authorization window
        remain in place.
        """
        authority = KeyLogAuthority()
        context = _server_context(authority)
        pair = _BioPair(context)
        sink = RecordingSink()
        authority.authorize(pair.server, sink)

        pair.handshake()
        pair.exchange(b"before")
        authorized_lines = list(sink.lines)
        assert authorized_lines
        delivered_at_revoke = authority.delivered

        assert authority.revoke(pair.server) is True
        assert authority.is_authorized(pair.server) is False
        # Idempotent: revoking again has nothing to do.
        assert authority.revoke(pair.server) is False

        # Keep the same, still-alive connection busy with fresh key
        # material (renegotiation) and more application data.
        pair.renegotiate()
        assert pair.server.total_renegotiations() == 1
        pair.exchange_client_first(b"after")

        assert sink.lines == authorized_lines
        assert authority.delivered == delivered_at_revoke

    def test_revoke_blocks_new_shared_context_connection(self) -> None:
        """
        The decisive post-revoke check: a *new* connection on the same shared
        context (whose handshake does emit a fresh key log line) receives no
        sink delivery once the original connection's authorization has been
        revoked - the gate is per connection, not per context.
        """
        authority = KeyLogAuthority()
        context = _server_context(authority)
        first = _BioPair(context)
        sink = RecordingSink()
        authority.authorize(first.server, sink)
        first.handshake()
        assert sink.lines
        assert authority.revoke(first.server) is True

        before = len(sink.lines)
        refused_before = authority.refused

        second = _BioPair(context)  # never authorized
        second.handshake()
        second.exchange(b"new-connection")

        assert len(sink.lines) == before
        assert authority.refused > refused_before
        assert authority.delivered == before

    def test_re_authorize_after_revoke_works(self) -> None:
        """
        A fresh connection can be authorized into a new sink after an earlier
        authorization was revoked.
        """
        authority = KeyLogAuthority()
        context = _server_context(authority)
        first = _BioPair(context)
        first_sink = RecordingSink()
        authority.authorize(first.server, first_sink)
        first.handshake()
        assert authority.revoke(first.server) is True
        assert first_sink.lines

        second = _BioPair(context)
        second_sink = RecordingSink()
        authority.authorize(second.server, second_sink)
        assert authority.is_authorized(second.server) is True
        second.handshake()

        assert second_sink.lines
        assert first_sink.lines != second_sink.lines
        # The revoked connection still cannot write anywhere.
        assert authority.is_authorized(first.server) is False

    def test_revoke_from_another_thread_waits_for_in_flight_write(
        self,
    ) -> None:
        """
        revoke() called from a different thread blocks while a sink write is
        in flight and, once it returns, guarantees no further delivery.
        """
        authority = KeyLogAuthority()
        context = _server_context(authority)
        pair = _BioPair(context)
        sink = BlockingSink()
        authority.authorize(pair.server, sink)

        # Drive the handshake (which fires the key log callback) on a worker
        # thread so the main thread can revoke concurrently.
        handshake_done = threading.Event()

        def worker() -> None:
            pair.handshake()
            handshake_done.set()

        thread = threading.Thread(target=worker)
        thread.start()
        assert sink.entered.wait(timeout=10)

        revoked = threading.Event()

        def revoker() -> None:
            assert authority.revoke(pair.server) is True
            revoked.set()

        revoke_thread = threading.Thread(target=revoker)
        revoke_thread.start()
        # Give the revoker time to block on the in-flight write.
        assert not revoked.wait(timeout=0.5)

        sink.release.set()
        assert revoked.wait(timeout=10)
        assert handshake_done.wait(timeout=10)
        thread.join()
        revoke_thread.join()

        # Boundary guarantee: everything delivered happened before revoke
        # returned; nothing new can be delivered afterwards.
        assert authority.delivered == len(sink.lines)
        assert authority.is_authorized(pair.server) is False

    def test_revoke_timeout_returns_false_but_keeps_gate_closed(
        self,
    ) -> None:
        """
        A revoke() whose timeout expires while a sink write is still running
        returns False, yet the gate stays closed so no further line can be
        delivered once the stuck write finishes.
        """
        authority = KeyLogAuthority()
        context = _server_context(authority)
        pair = _BioPair(context)
        sink = BlockingSink()
        authority.authorize(pair.server, sink)

        handshake_done = threading.Event()

        def worker() -> None:
            pair.handshake()
            handshake_done.set()

        thread = threading.Thread(target=worker)
        thread.start()
        assert sink.entered.wait(timeout=10)

        result: list[bool] = []

        def revoker() -> None:
            result.append(authority.revoke(pair.server, timeout=0.2))

        revoke_thread = threading.Thread(target=revoker)
        revoke_thread.start()
        revoke_thread.join(timeout=10)
        assert result == [False]
        # Closed regardless of the timeout.
        assert authority.is_authorized(pair.server) is False

        # Let the stuck write finish; the handshake completes normally.
        sink.release.set()
        assert handshake_done.wait(timeout=10)
        thread.join()

    def test_reentrant_revoke_inside_sink_does_not_deadlock(self) -> None:
        """
        A sink that revokes its own connection must return immediately
        instead of waiting for the write it is currently executing.
        """
        authority = KeyLogAuthority()
        context = _server_context(authority)
        pair = _BioPair(context)

        class SelfRevokingSink:
            def __init__(self) -> None:
                self.lines: list[bytes] = []
                self.revoked_inside = False

            def write_line(self, line: bytes) -> None:
                self.lines.append(line)
                # Re-entrant call on the same thread: must not block.
                assert authority.revoke(pair.server) is True
                self.revoked_inside = True

        sink = SelfRevokingSink()
        authority.authorize(pair.server, sink)
        pair.handshake()

        assert sink.revoked_inside
        assert authority.is_authorized(pair.server) is False

    def test_sink_failure_is_sanitized_and_non_fatal(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """
        A raising sink must not break the handshake, must be reported through
        the diagnostics callback with no key material in the message, and the
        failed line must not leak into ordinary (stderr) logs.
        """
        authority = KeyLogAuthority()
        context = _server_context(authority)
        pair = _BioPair(context)

        # A plausible secret that must never appear in any diagnostic text.
        secret = b"CLIENT_RANDOM " + b"ab" * 32 + b" " + b"cd" * 48
        sink = FailingSink(secret)
        authority.authorize(pair.server, sink)

        diagnostics: list[tuple[Connection, str, str]] = []
        authority._on_sink_error = (
            lambda connection, phase, error_type: diagnostics.append(
                (connection, phase, error_type)
            )
        )

        pair.handshake()  # must not raise despite the failing sink

        assert diagnostics
        connection, phase, error_type = diagnostics[0]
        assert connection is pair.server
        assert phase == "write"
        assert error_type == "RuntimeError"

        # The secret/key line is absent from diagnostics and stderr.
        diagnostic_blob = repr(diagnostics) + capsys.readouterr().err
        assert secret not in diagnostic_blob.encode()
        assert b"cd" * 48 not in diagnostic_blob.encode()
        assert authority.sink_failures >= 1
        assert authority.dropped >= 1
        assert authority.delivered == 0

    def test_default_diagnostics_never_contains_key_line(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        authority = KeyLogAuthority()
        context = _server_context(authority)
        pair = _BioPair(context)
        secret = b"CLIENT_RANDOM " + b"ef" * 32 + b" " + b"12" * 48
        authority.authorize(pair.server, FailingSink(secret))

        pair.handshake()

        stderr = capsys.readouterr().err
        assert "sink failure" in stderr
        assert secret not in stderr.encode()
        assert b"12" * 48 not in stderr.encode()

    def test_broken_diagnostics_callback_is_swallowed(self) -> None:
        def broken_diagnostics(
            connection: Connection, phase: str, error_type: str
        ) -> None:
            raise RuntimeError("diagnostics itself failed")

        authority = KeyLogAuthority(on_sink_error=broken_diagnostics)
        context = _server_context(authority)
        pair = _BioPair(context)
        authority.authorize(pair.server, FailingSink(b"CLIENT_RANDOM x y"))
        # Must propagate neither the sink error nor the diagnostics error.
        pair.handshake()

    def test_revoke_flushes_buffering_sink(self) -> None:
        """
        Lines already accepted by a buffering sink are drained via flush()
        when authorization is revoked; the authority itself discards nothing
        because it never buffers.
        """
        authority = KeyLogAuthority()
        context = _server_context(authority)
        pair = _BioPair(context)
        sink = BufferingSink()
        authority.authorize(pair.server, sink)

        pair.handshake()
        assert sink.flushed == []
        assert sink._buffered

        assert authority.revoke(pair.server) is True
        assert sink.flushed
        assert sink._buffered == []

    def test_revoke_unknown_connection_is_noop(self) -> None:
        authority = KeyLogAuthority()
        context = _server_context(authority)
        pair = _BioPair(context)
        pair.handshake()
        assert authority.revoke(pair.server) is False

    def test_authorize_validates_sink(self) -> None:
        authority = KeyLogAuthority()
        context = _server_context(authority)
        pair = _BioPair(context)
        with pytest.raises(TypeError):
            authority.authorize(pair.server, object())  # type: ignore[arg-type]


@keylog_available
class TestFileKeyLogSink:
    def test_writes_only_authorized_lines(self, tmp_path: Any) -> None:
        path = str(tmp_path / "keys.log")
        authority = KeyLogAuthority()
        context = _server_context(authority)

        authorized = _BioPair(context)
        unauthorized = _BioPair(context)
        sink = FileKeyLogSink(path)
        authority.authorize(authorized.server, sink)

        authorized.handshake()
        unauthorized.handshake()
        sink.close()

        blob = open(path, "rb").read()
        authorized_random = _client_random_hex(authorized.server)
        unauthorized_random = _client_random_hex(unauthorized.server)
        assert authorized_random in blob
        assert unauthorized_random not in blob
        for line in blob.splitlines():
            assert re.fullmatch(_KEYLOG_LINE, line)

    def test_file_is_not_created_until_first_authorized_line(
        self, tmp_path: Any
    ) -> None:
        path = str(tmp_path / "unused.log")
        sink = FileKeyLogSink(path)
        assert not os.path.exists(path)
        authority = KeyLogAuthority()
        context = _server_context(authority)
        pair = _BioPair(context)  # never authorized
        pair.handshake()
        sink.close()
        assert not os.path.exists(path)

    def test_flush_is_idempotent_and_safe_before_first_line(
        self, tmp_path: Any
    ) -> None:
        sink = FileKeyLogSink(str(tmp_path / "x.log"))
        sink.flush()  # no file yet: must be a no-op
        sink.write_line(b"CLIENT_RANDOM " + b"a" * 64 + b" " + b"b" * 96)
        sink.flush()
        sink.close()
