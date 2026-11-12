# Copyright (C) AB Strakt
# See LICENSE for details.

"""
Tests for the mandatory ALPN policy helpers in :mod:`OpenSSL.alpn`.
"""

from __future__ import annotations

import pytest

from OpenSSL import SSL, alpn
from OpenSSL.crypto import FILETYPE_PEM, load_certificate, load_privatekey
from OpenSSL.SSL import (
    VERIFY_PEER,
    Connection,
    Context,
    SSLv23_METHOD,
    WantReadError,
    _ALPNSelectCallback,
    _NoOverlappingProtocols,
)

from .test_crypto import server_cert_pem, server_key_pem

ALLOWED = [b"h2", b"http/1.1"]
PAYLOAD = b"GET / HTTP/1.1\r\n\r\n"


def _server_context() -> Context:
    context = Context(SSLv23_METHOD)
    context.use_privatekey(load_privatekey(FILETYPE_PEM, server_key_pem))
    context.use_certificate(load_certificate(FILETYPE_PEM, server_cert_pem))
    return context


def _make_pair(
    policy: alpn.ALPNPolicy,
    *,
    client_offers: list[bytes] | None = None,
    configure_client: bool = True,
    configure_server: bool = True,
    server_callback: _ALPNSelectCallback | None = None,
    client_verify_mode: int | None = None,
) -> tuple[alpn.GuardedConnection, alpn.GuardedConnection]:
    client_context = Context(SSLv23_METHOD)
    if configure_client:
        policy.configure_client(client_context)
    if client_offers is not None:
        client_context.set_alpn_protos(client_offers)
    if client_verify_mode is not None:
        # Must be configured before the Context creates a Connection.
        client_context.set_verify(client_verify_mode, None)

    server_context = _server_context()
    if server_callback is not None:
        server_context.set_alpn_select_callback(server_callback)
    elif configure_server:
        policy.configure_server(server_context)

    raw_client, raw_server = alpn.memory_bio_pair(
        client_context, server_context
    )
    return (
        policy.wrap(raw_client, is_server=False),
        policy.wrap(raw_server, is_server=True),
    )


def _pump_app_data(
    sender: alpn.GuardedConnection, receiver: alpn.GuardedConnection
) -> None:
    """Move any records the sender produced into the receiver's input BIO."""
    raw_sender = sender.connection
    raw_receiver = receiver.connection
    while True:
        try:
            chunk = raw_sender.bio_read(4096)
        except WantReadError:
            return
        raw_receiver.bio_write(chunk)


class TestALPNPolicyConfiguration:
    """Pre-handshake configuration stage."""

    def test_protocols_are_validated_and_deduped(self) -> None:
        policy = alpn.ALPNPolicy([b"h2", b"h2", b"http/1.1"])
        assert policy.protocols == (b"h2", b"http/1.1")

    @pytest.mark.parametrize(
        "protos",
        [
            [],
            [b""],
            [b"h2", ""],
            [b"x" * 256],
        ],
    )
    def test_invalid_protocols_rejected(self, protos: list[bytes]) -> None:
        with pytest.raises((ValueError, TypeError)):
            alpn.ALPNPolicy(protos)

    def test_check_before_handshake_is_not_an_implicit_pass(self) -> None:
        policy = alpn.ALPNPolicy(ALLOWED)
        client, server = _make_pair(policy)
        # Neither handshake has run: the gate must not assume success.
        with pytest.raises(alpn.ALPNError) as exc:
            policy.check(server.connection, is_server=True)
        assert exc.value.reason is alpn.ALPNRejectReason.NOT_HANDSHAKED


class TestMandatoryALPNHandshake:
    """End-to-end behavior over paired in-memory BIOs."""

    def test_allowed_protocol_completes_and_carries_data(self) -> None:
        policy = alpn.ALPNPolicy(ALLOWED)
        client, server = _make_pair(policy)

        alpn.handshake_in_memory(client, server)

        assert client.get_alpn_proto_negotiated() == b"h2"
        assert server.get_alpn_proto_negotiated() == b"h2"
        assert client.require_negotiated_protocol() == b"h2"

        # Application data flows in both directions once authorized.
        client.send(PAYLOAD)
        _pump_app_data(client, server)
        assert server.recv(len(PAYLOAD)) == PAYLOAD

        server.send(b"pong")
        _pump_app_data(server, client)
        assert client.recv(4) == b"pong"

    def test_client_without_alpn_extension_is_rejected(self) -> None:
        policy = alpn.ALPNPolicy(ALLOWED)
        client, server = _make_pair(policy, configure_client=False)

        with pytest.raises(alpn.ALPNError) as exc:
            alpn.handshake_in_memory(client, server)

        # The server selection callback never ran because no extension arrived.
        assert exc.value.reason is alpn.ALPNRejectReason.MISSING_EXTENSION
        assert exc.value.negotiated == b""
        assert not policy._server_was_called.get(server.connection, False)

    def test_no_intersection_is_rejected_on_both_sides(self) -> None:
        policy = alpn.ALPNPolicy(ALLOWED)
        client, server = _make_pair(
            policy, client_offers=[b"spdy/2", b"ftp/1.0"]
        )

        with pytest.raises(alpn.ALPNError) as exc:
            alpn.handshake_in_memory(client, server)
        assert exc.value.reason is alpn.ALPNRejectReason.NO_COMMON_PROTOCOL

        # The hardened callback ran and correctly declined to select.
        assert policy._server_was_called.get(server.connection, False)
        assert server.get_alpn_proto_negotiated() == b""
        assert client.get_alpn_proto_negotiated() == b""

    def test_rejected_connection_delivers_no_application_data(self) -> None:
        policy = alpn.ALPNPolicy(ALLOWED)
        client, server = _make_pair(policy, configure_client=False)

        with pytest.raises(alpn.ALPNError):
            alpn.handshake_in_memory(client, server)

        # Every application entry point is gated on both ends.
        for guarded in (client, server):
            with pytest.raises(alpn.ALPNError):
                guarded.send(PAYLOAD)
            with pytest.raises(alpn.ALPNError):
                guarded.recv(1024)
            with pytest.raises(alpn.ALPNError):
                guarded.sendall(PAYLOAD)

    def test_callback_returning_disallowed_value_is_refused(self) -> None:
        policy = alpn.ALPNPolicy(ALLOWED)
        # A raw, non-hardened callback tries to select a protocol outside the
        # policy. The post-handshake gate is the authoritative enforcement
        # point and must not trust it.
        client, server = _make_pair(
            policy,
            client_offers=[b"evil/1.0", b"h2"],
            server_callback=lambda conn, offered: b"evil/1.0",
        )

        alpn.pump_in_memory(client.connection, server.connection)
        policy.mark_handshake_done(client.connection)
        policy.mark_handshake_done(server.connection)

        assert server.get_alpn_proto_negotiated() == b"evil/1.0"
        with pytest.raises(alpn.ALPNError) as exc:
            server.require_negotiated_protocol()
        assert exc.value.reason is alpn.ALPNRejectReason.PROTOCOL_NOT_ALLOWED
        with pytest.raises(alpn.ALPNError):
            server.send(PAYLOAD)
        with pytest.raises(alpn.ALPNError):
            server.recv(1024)

    def test_application_data_is_not_delivered_to_rejected_end(self) -> None:
        policy = alpn.ALPNPolicy(ALLOWED)
        # Both ends complete a TLS handshake on a disallowed protocol, so the
        # raw connection could physically carry data. The guard must still
        # prevent that data from being delivered to the rejected end.
        client, server = _make_pair(
            policy,
            client_offers=[b"evil/1.0"],
            server_callback=lambda conn, offered: b"evil/1.0",
        )
        alpn.pump_in_memory(client.connection, server.connection)
        policy.mark_handshake_done(client.connection)
        policy.mark_handshake_done(server.connection)

        # The client end is outside the policy gate here; use it only to emit
        # genuine encrypted application records toward the server.
        client.connection.send(PAYLOAD)
        _pump_app_data(client, server)

        # The raw server has the records available, but the guarded server
        # refuses to surface them as application data.
        with pytest.raises(alpn.ALPNError) as exc:
            server.recv(len(PAYLOAD))
        assert exc.value.reason is alpn.ALPNRejectReason.PROTOCOL_NOT_ALLOWED
        policy = alpn.ALPNPolicy(ALLOWED)
        seen: list[list[bytes]] = []

        def spy(
            conn: Connection, offered: list[bytes]
        ) -> bytes | _NoOverlappingProtocols:
            seen.append(offered)
            return policy._select(conn, offered)

        client_context = Context(SSLv23_METHOD)
        client_context.set_alpn_protos([b"spdy/2", b"http/1.1", b"h2"])
        server_context = _server_context()
        server_context.set_alpn_select_callback(spy)

        raw_client, raw_server = alpn.memory_bio_pair(
            client_context, server_context
        )
        client = policy.wrap(raw_client, is_server=False)
        server = policy.wrap(raw_server, is_server=True)
        alpn.handshake_in_memory(client, server)

        assert seen == [[b"spdy/2", b"http/1.1", b"h2"]]
        # The policy's own preference order wins, never a disallowed value.
        assert server.get_alpn_proto_negotiated() == b"h2"

    def test_certificate_failure_is_distinct_from_policy_failure(self) -> None:
        policy = alpn.ALPNPolicy(ALLOWED)
        # Trust nothing: the self-signed server certificate fails verification.
        client, server = _make_pair(policy, client_verify_mode=VERIFY_PEER)

        with pytest.raises(SSL.Error) as exc:
            alpn.handshake_in_memory(client, server)
        assert "certificate verify failed" in str(exc.value)
        assert not isinstance(exc.value, alpn.ALPNError)

    def test_guarded_do_handshake_enforces_gate(self) -> None:
        policy = alpn.ALPNPolicy(ALLOWED)
        client, server = _make_pair(policy, configure_client=False)

        # A single call before any bytes flow just reports non-blocking
        # progress; once the exchange is driven to completion the gate fires.
        with pytest.raises(WantReadError):
            client.do_handshake()

        with pytest.raises(alpn.ALPNError):
            alpn.handshake_in_memory(client, server)
        # Even after the handshake settled, both guarded ends stay locked.
        with pytest.raises(alpn.ALPNError):
            server.do_handshake()
        with pytest.raises(alpn.ALPNError):
            client.do_handshake()

    def test_guarded_connection_delegates_plumbing(self) -> None:
        policy = alpn.ALPNPolicy(ALLOWED)
        client, server = _make_pair(policy)
        alpn.handshake_in_memory(client, server)

        # Non-application attributes/methods pass through to the raw
        # connection, including the memory-BIO plumbing.
        assert client.get_alpn_proto_negotiated() == b"h2"
        assert isinstance(client.connection, SSL.Connection)
        with pytest.raises(WantReadError):
            client.bio_read(10)


class TestLegacyOptionalALPN:
    """The old, optional ALPN usage must keep working unchanged."""

    def test_no_policy_allows_handshake_without_alpn(self) -> None:
        client_context = Context(SSLv23_METHOD)
        # Client offers ALPN, server has no selection callback at all.
        client_context.set_alpn_protos(ALLOWED)
        server_context = _server_context()

        raw_client, raw_server = alpn.memory_bio_pair(
            client_context, server_context
        )
        alpn.pump_in_memory(raw_client, raw_server)

        # No policy gate: the connection is fully usable despite no ALPN.
        assert raw_client.get_alpn_proto_negotiated() == b""
        assert raw_server.get_alpn_proto_negotiated() == b""
        raw_client.send(PAYLOAD)
        while True:
            try:
                chunk = raw_client.bio_read(4096)
            except WantReadError:
                break
            raw_server.bio_write(chunk)
        assert raw_server.recv(len(PAYLOAD)) == PAYLOAD

    def test_no_overlapping_protocols_sentinel_still_optional(self) -> None:
        client_context = Context(SSLv23_METHOD)
        client_context.set_alpn_protos([b"spdy/2"])
        server_context = _server_context()
        server_context.set_alpn_select_callback(
            lambda conn, offered: SSL.NO_OVERLAPPING_PROTOCOLS
        )

        raw_client, raw_server = alpn.memory_bio_pair(
            client_context, server_context
        )
        alpn.pump_in_memory(raw_client, raw_server)

        # Legacy semantics: handshake completes with no protocol selected and
        # the connection remains usable.
        assert raw_client.get_alpn_proto_negotiated() == b""
        raw_server.send(b"ok")
        while True:
            try:
                chunk = raw_server.bio_read(4096)
            except WantReadError:
                break
            raw_client.bio_write(chunk)
        assert raw_client.recv(2) == b"ok"
