# Copyright (c) The pyOpenSSL developers
# See LICENSE for details.

"""
Tests for the non-blocking memory-BIO send adapter
(:mod:`OpenSSL.bio_nb`).
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from OpenSSL.bio_nb import (
    AdapterClosed,
    BioSendAdapter,
    PumpState,
    QueueFull,
    SendFailed,
)
from OpenSSL.SSL import (
    TLS_METHOD,
    VERIFY_NONE,
    Connection,
    Context,
    WantReadError,
)


def _self_signed_context() -> Context:
    """Build a TLS context carrying an ephemeral self-signed certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bio-nb")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(int(uuid.uuid4()))
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .sign(key, hashes.SHA256())
    )

    context = Context(TLS_METHOD)
    context.use_certificate(cert)
    context.use_privatekey(key)
    context.set_verify(VERIFY_NONE, lambda *args: True)
    return context


class ControlledWire:
    """
    In-memory transport with a controllable per-write ceiling.

    ``writer`` is the callable handed to the adapter.  Each writer call
    consumes at most ``write_limit`` bytes; ``blocked=True`` makes every
    call consume nothing (the EAGAIN case).  Nothing here knows anything
    about an event loop.
    """

    def __init__(self, write_limit: int) -> None:
        self.to_server = bytearray()
        self.to_client = bytearray()
        self.write_limit = write_limit
        self.blocked = False
        self.write_calls = 0
        self.max_observed_chunk = 0

    def writer(self, data: bytes) -> int:
        self.write_calls += 1
        if self.blocked:
            return 0
        take = min(len(data), self.write_limit)
        self.max_observed_chunk = max(self.max_observed_chunk, take)
        self.to_server.extend(data[:take])
        return take

    def server_inbox(self) -> bytes:
        return bytes(self.to_server)


def _new_pair() -> tuple[Connection, Connection]:
    client = Connection(_self_signed_context(), None)
    server = Connection(_self_signed_context(), None)
    client.set_connect_state()
    server.set_accept_state()
    return client, server


class ServerPeer:
    """
    The memory-BIO server side of a test connection.

    One :meth:`pump` feeds queued client records, drives the handshake as
    far as it can, drains application data and queues any reply records
    for the client.
    """

    def __init__(self, connection: Connection, wire: ControlledWire) -> None:
        self._connection = connection
        self._wire = wire
        self._handshake_done = False
        self.app_data = bytearray()

    def pump(self) -> bytes:
        if self._wire.to_server:
            self._connection.bio_write(self._wire.server_inbox())
            self._wire.to_server.clear()

        if not self._handshake_done:
            try:
                self._connection.do_handshake()
                self._handshake_done = True
            except WantReadError:
                pass

        while True:
            try:
                self.app_data.extend(self._connection.recv(4096))
            except WantReadError:
                break

        while True:
            try:
                self._wire.to_client.extend(self._connection.bio_read(4096))
            except WantReadError:
                break
        return bytes(self.app_data)


def _drive_until_idle(
    adapter: BioSendAdapter,
    peer: ServerPeer,
    wire: ControlledWire,
    max_iterations: int = 500,
) -> bytes:
    """Alternate bounded adapter pumps and server pumps until IDLE."""
    for _ in range(max_iterations):
        result = adapter.pump(max_transfer=wire.write_limit)
        peer.pump()
        if wire.to_client:
            adapter.feed_network(bytes(wire.to_client))
            wire.to_client.clear()
        if result.state == PumpState.IDLE:
            return bytes(peer.app_data)
    raise AssertionError("adapter never reached idle")


class TestBioSendAdapter:
    def _adapter(
        self,
        max_queued: int = 1 << 20,
        write_limit: int = 4096,
    ) -> tuple[BioSendAdapter, ServerPeer, ControlledWire]:
        client, server = _new_pair()
        wire = ControlledWire(write_limit)
        adapter = BioSendAdapter(client, wire.writer, max_queued)
        peer = ServerPeer(server, wire)
        return adapter, peer, wire

    def test_buffer_ownership_taken_at_submit(self) -> None:
        """
        Mutating or releasing the caller's buffer after submit never
        changes what the peer receives; the original full sequences of
        two distinct messages arrive intact.
        """
        adapter, peer, wire = self._adapter(write_limit=333)

        first = bytearray(b"FIRST-MESSAGE-" + b"1" * 64)
        original_first = bytes(first)
        # Sliced memoryview over a bytearray with surrounding bytes.
        backing = bytearray(b"X" + b"SECOND-MESSAGE-" + b"2" * 96 + b"Y")
        second_view = memoryview(backing)[1:-1]
        original_second = bytes(second_view)

        adapter.submit(first)
        adapter.submit(second_view)

        # Reuse both buffers immediately, before any pump ran.
        first[:] = b"Z" * len(first)
        backing[:] = b"Q" * len(backing)
        second_view.release()

        received = _drive_until_idle(adapter, peer, wire)
        assert received == original_first + original_second

    def test_submit_rejected_when_full_keeps_buffer(self) -> None:
        """QueueFull copies nothing and leaves the caller's buffer alone."""
        adapter, _peer, _wire = self._adapter(max_queued=10)
        adapter.submit(b"abc")

        payload = bytearray(b"too-large-to-fit")
        original = bytes(payload)
        with pytest.raises(QueueFull):
            adapter.submit(payload)
        assert bytes(payload) == original
        assert adapter.queued_bytes == 3
        assert adapter.queued_messages == 1

    def test_backpressure_when_transport_blocks(self) -> None:
        """
        A writer returning 0 produces WANT_WRITE, retains the bytes, and
        resumes with the identical prefix once writable again - no loss
        and no duplicate delivery.
        """
        adapter, peer, wire = self._adapter(write_limit=257)
        message = b"BLOCK-" + b"b" * 2000
        adapter.submit(message)

        # Let the first handshake record leave, then block the transport.
        adapter.pump(max_transfer=257)
        peer.pump()
        if wire.to_client:
            adapter.feed_network(bytes(wire.to_client))
            wire.to_client.clear()

        wire.blocked = True
        blocked_result = adapter.pump(max_transfer=257)
        assert blocked_result.state == PumpState.WANT_WRITE
        assert blocked_result.transport_delta == 0
        frozen_total = adapter.transport_bytes

        wire.blocked = False
        received = _drive_until_idle(adapter, peer, wire)
        assert received == message
        # Nothing was delivered while blocked; nothing was duplicated.
        assert adapter.transport_bytes > frozen_total

    def test_retry_keeps_same_message_order(self) -> None:
        """
        With a tiny pump budget the head message is retried in place; the
        second message never overtakes it.
        """
        adapter, peer, wire = self._adapter(write_limit=64)
        first = b"A" * 500
        second = b"B" * 500
        adapter.submit(first)
        adapter.submit(second)

        seen_states = set()
        for _ in range(500):
            result = adapter.pump(max_transfer=64)
            seen_states.add(result.state)
            assert result.transport_delta <= 64
            peer.pump()
            if wire.to_client:
                adapter.feed_network(bytes(wire.to_client))
                wire.to_client.clear()
            if result.state == PumpState.IDLE:
                break
        else:
            raise AssertionError("never idled")

        assert PumpState.WANT_WRITE in seen_states
        assert bytes(peer.app_data) == first + second

    def test_cancel_returns_exact_progress(self) -> None:
        """
        Cancelling mid-flight reports confirmed transport progress and
        every un-sent byte, and freezes the adapter without touching
        another connection.
        """
        client, server = _new_pair()
        wire = ControlledWire(128)
        adapter = BioSendAdapter(client, wire.writer, 1 << 20)
        peer = ServerPeer(server, wire)

        first = b"CANCEL-ONE-" + b"1" * 300
        second = b"CANCEL-TWO-" + b"2" * 300
        original_first = bytes(first)
        adapter.submit(first)
        adapter.submit(second)

        for _ in range(12):
            adapter.pump(max_transfer=128)
            peer.pump()
            if wire.to_client:
                adapter.feed_network(bytes(wire.to_client))
                wire.to_client.clear()

        report = adapter.cancel()
        assert adapter.state == "closed"
        assert report.transport_bytes == adapter.transport_bytes
        assert isinstance(report.egress_pending, bytes)
        assert len(report.egress_pending) == adapter.pending_egress_bytes
        # TLS-accepted prefixes never exceed their message lengths, and
        # untouched messages report zero progress.
        for item in report.unsent:
            assert 0 <= item.tls_accepted <= len(item.payload)
        assert report.unsent[-1].tls_accepted == 0
        # The head message is still the intact original first message.
        assert report.unsent[0].payload == original_first
        assert [item.payload for item in report.unsent][-1] == second

        with pytest.raises(AdapterClosed):
            adapter.submit(b"no-more")
        with pytest.raises(AdapterClosed):
            adapter.pump()
        # cancel is idempotent.
        assert adapter.cancel() == report

    def test_transport_failure_freezes_and_reports(self) -> None:
        """
        A raising writer fails the adapter once, preserves the un-sent
        bytes, and never redirects them anywhere.
        """
        client, server = _new_pair()
        wire = ControlledWire(512)
        adapter = BioSendAdapter(client, wire.writer, 1 << 20)
        peer = ServerPeer(server, wire)
        message = b"FAIL-ME-" + b"f" * 4096
        adapter.submit(message)

        def boom(data: bytes) -> int:
            raise OSError("transport exploded")

        adapter._transport = boom  # simulate transport death
        with pytest.raises(SendFailed) as exc_info:
            for _ in range(50):
                adapter.pump(max_transfer=512)
                peer.pump()
                if wire.to_client:
                    adapter.feed_network(bytes(wire.to_client))
                    wire.to_client.clear()

        failure = exc_info.value
        assert adapter.state == "failed"
        assert isinstance(failure.cause, OSError)
        assert failure.report.unsent[0].payload == message
        # Bytes already on the wire stay on the wire; the rest are held.
        assert failure.report.transport_bytes == adapter.transport_bytes

        # A brand-new adapter on a brand-new connection receives nothing:
        # the failed adapter never forwarded un-acknowledged bytes itself.
        fresh_client, fresh_server = _new_pair()
        fresh_wire = ControlledWire(512)
        fresh = BioSendAdapter(fresh_client, fresh_wire.writer, 1 << 20)
        fresh_peer = ServerPeer(fresh_server, fresh_wire)
        for _ in range(50):
            result = fresh.pump(max_transfer=512)
            fresh_peer.pump()
            if fresh_wire.to_client:
                fresh.feed_network(bytes(fresh_wire.to_client))
                fresh_wire.to_client.clear()
            if result.state == PumpState.IDLE:
                break
        assert fresh_wire.server_inbox() == b""
        assert bytes(fresh_peer.app_data) == b""
        assert fresh.queued_messages == 0

        with pytest.raises(AdapterClosed):
            adapter.pump()

    def test_submit_before_handshake_completes(self) -> None:
        """Messages queued before the handshake are sent after it."""
        adapter, peer, wire = self._adapter(write_limit=512)
        adapter.submit(b"early-bird")
        received = _drive_until_idle(adapter, peer, wire)
        assert received == b"early-bird"
        assert adapter.state == "open"

    def test_pump_respects_transfer_budget(self) -> None:
        """No single pump hands more than max_transfer to the writer."""
        adapter, peer, wire = self._adapter(write_limit=1024)
        adapter.submit(b"x" * 8192)
        deltas = []
        for _ in range(400):
            result = adapter.pump(max_transfer=128)
            deltas.append(result.transport_delta)
            peer.pump()
            if wire.to_client:
                adapter.feed_network(bytes(wire.to_client))
                wire.to_client.clear()
            if result.state == PumpState.IDLE:
                break
        assert max(deltas) <= 128
        assert wire.max_observed_chunk <= 128
        assert bytes(peer.app_data) == b"x" * 8192

    def test_invalid_construction_arguments(self) -> None:
        client, _server = _new_pair()
        with pytest.raises(ValueError):
            BioSendAdapter(client, lambda data: len(data), 0)
        adapter = BioSendAdapter(client, lambda data: len(data), 10)
        with pytest.raises(ValueError):
            adapter.pump(max_transfer=0)
