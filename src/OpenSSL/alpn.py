# Copyright (C) AB Strakt
# See LICENSE for details.

"""
Mandatory Application Layer Protocol Negotiation (ALPN) helpers.

The plain :class:`~OpenSSL.SSL.Context` ALPN API
(:meth:`~OpenSSL.SSL.Context.set_alpn_protos` /
:meth:`~OpenSSL.SSL.Context.set_alpn_select_callback`) treats ALPN as an
optional hint: if the peer sends no ALPN extension, no protocol overlaps, or
the selection callback declines, the TLS handshake may still complete with
``get_alpn_proto_negotiated()`` returning ``b""``.  Nothing then stops
application data from flowing over a connection whose negotiated protocol was
never approved.

This module layers a *mandatory* ALPN policy on top of that API.  A policy is
configured before the handshake and re-checked after it, independently of
whether the server selection callback ran, so a connection can never reach
application read/write state without negotiating one of the explicitly
allowed protocols.

Legacy callers that want to permit "no ALPN negotiated" keep using
:meth:`~OpenSSL.SSL.Context.set_alpn_protos` /
:meth:`~OpenSSL.SSL.Context.set_alpn_select_callback` directly and are
unaffected.
"""

from __future__ import annotations

import enum
from typing import Any
from weakref import WeakKeyDictionary

from OpenSSL.SSL import (
    NO_OVERLAPPING_PROTOCOLS,
    Connection,
    Context,
    WantReadError,
    _Buffer,
    _NoOverlappingProtocols,
)

__all__ = [
    "ALPNError",
    "ALPNRejectReason",
    "ALPNPolicy",
    "GuardedConnection",
    "memory_bio_pair",
    "pump_in_memory",
    "handshake_in_memory",
]


class ALPNRejectReason(enum.Enum):
    """
    Why a mandatory ALPN policy refused a connection.

    These reasons describe *negotiation policy* failures only.  Ordinary
    certificate verification failures are still reported by
    :class:`OpenSSL.SSL.Error` and never carry one of these values.
    """

    #: The peer did not send the ALPN extension at all.
    MISSING_EXTENSION = "missing-alpn-extension"

    #: Both sides offered ALPN but had no protocol in common.
    NO_COMMON_PROTOCOL = "no-common-protocol"

    #: The selection callback chose a protocol that is not on the allow list
    #: (server-side policy enforcement).
    PROTOCOL_NOT_ALLOWED = "protocol-not-allowed"

    #: The result was checked before any handshake completed.
    NOT_HANDSHAKED = "not-handshaked"


class ALPNError(Exception):
    """
    A mandatory ALPN policy was not satisfied.

    This is deliberately **not** a subclass of :class:`OpenSSL.SSL.Error`, so
    callers can reliably distinguish an ALPN negotiation-policy rejection
    (this exception) from ordinary TLS failures such as certificate
    verification problems (:class:`OpenSSL.SSL.Error`).

    :ivar reason: The :class:`ALPNRejectReason` explaining the rejection.
    :ivar negotiated: The protocol that was actually negotiated, or ``b""``
        when nothing was negotiated.
    :ivar allowed: The protocols the policy required.
    """

    def __init__(
        self,
        reason: ALPNRejectReason,
        allowed: tuple[bytes, ...],
        negotiated: bytes = b"",
    ) -> None:
        self.reason = reason
        self.allowed = tuple(allowed)
        self.negotiated = negotiated
        super().__init__(
            f"mandatory ALPN policy not satisfied: {reason.value} "
            f"(negotiated={negotiated!r}, allowed={list(self.allowed)!r})"
        )


def _validate_protos(
    protos: list[bytes] | tuple[bytes, ...],
) -> tuple[bytes, ...]:
    if not isinstance(protos, (list, tuple)) or not protos:
        raise ValueError("at least one protocol must be specified")

    normalized: list[bytes] = []
    for proto in protos:
        if not isinstance(proto, bytes) or not proto:
            raise TypeError(
                "each ALPN protocol must be a non-empty byte string"
            )
        if len(proto) > 255:
            raise ValueError(
                "ALPN protocol names must be shorter than 256 bytes"
            )
        if proto not in normalized:
            normalized.append(proto)
    return tuple(normalized)


class ALPNPolicy:
    """
    A reusable mandatory ALPN allow list applied to many contexts.

    The same policy object can configure any number of client and server
    contexts.  Two independent stages are enforced:

    * **Before the handshake** the context is wired up so the client offers
      exactly the allowed protocols and the server selection callback only
      ever returns an allowed protocol (or
      :data:`~OpenSSL.SSL.NO_OVERLAPPING_PROTOCOLS`).
    * **After the handshake** :meth:`check` inspects the negotiated result
      with :meth:`Connection.get_alpn_proto_negotiated`.  This does not trust
      the callback: even if the callback never ran or a raw callback was
      installed, a connection that did not negotiate an allowed protocol is
      rejected before it can carry application data.

    :param protos: The only protocols that may be negotiated, in preference
        order, e.g. ``[b"h2", b"http/1.1"]``.
    """

    def __init__(self, protos: list[bytes] | tuple[bytes, ...]) -> None:
        self._protos = _validate_protos(protos)
        # Per-connection bookkeeping so the post-handshake check can tell a
        # missing extension apart from an empty intersection without relying
        # on the selection callback having run.
        self._server_was_called: WeakKeyDictionary[Connection, bool] = (
            WeakKeyDictionary()
        )
        # Connections whose do_handshake() has returned successfully.
        self._handshake_done: WeakKeyDictionary[Connection, bool] = (
            WeakKeyDictionary()
        )

    @property
    def protocols(self) -> tuple[bytes, ...]:
        """The protocols the policy requires, in preference order."""
        return self._protos

    def _select(
        self, connection: Connection, offered: list[bytes]
    ) -> bytes | _NoOverlappingProtocols:
        # Record what the peer offered and that the callback ran. The
        # post-handshake gate never trusts this state to authorize the
        # connection; it only makes the rejection reason more precise.
        self._server_was_called[connection] = True

        for proto in self._protos:
            if proto in offered:
                return proto
        # Nothing on the allow list was offered. Ask OpenSSL to continue the
        # handshake without selecting a protocol; check() then fails it.
        return NO_OVERLAPPING_PROTOCOLS

    def configure_client(self, context: Context) -> None:
        """
        Configure a client-side context to offer exactly the allowed
        protocols.

        Call this before creating any :class:`Connection` from *context*
        (and before the handshake).  A peer that does not select one of the
        allowed protocols is later rejected by :meth:`check` /
        :meth:`wrap`.
        """
        context.set_alpn_protos(list(self._protos))

    def configure_server(self, context: Context) -> None:
        """
        Configure a server-side context with a hardened selection callback.

        The installed callback only ever returns an allowed protocol or
        :data:`~OpenSSL.SSL.NO_OVERLAPPING_PROTOCOLS`; it can never select a
        disallowed value.  The handshake itself may still complete without a
        selection, so :meth:`check` remains the authoritative gate.
        """
        context.set_alpn_select_callback(self._select)

    def _server_reason(self, connection: Connection) -> ALPNRejectReason:
        negotiated = connection.get_alpn_proto_negotiated()
        if negotiated:
            # A protocol was selected (possibly by a raw callback that bypassed
            # the hardened one) but it is not on the allow list.
            return ALPNRejectReason.PROTOCOL_NOT_ALLOWED
        if not self._server_was_called.get(connection, False):
            # The callback did not run, so the client sent no ALPN extension.
            # Do not treat "callback absent" as an implicit pass.
            return ALPNRejectReason.MISSING_EXTENSION
        return ALPNRejectReason.NO_COMMON_PROTOCOL

    def mark_handshake_done(self, connection: Connection) -> None:
        """
        Record that the TLS handshake for *connection* completed.

        :meth:`GuardedConnection.do_handshake` calls this automatically; it is
        part of the public surface so custom handshake drivers can report
        completion before invoking :meth:`check`.
        """
        self._handshake_done[connection] = True

    def check(self, connection: Connection, *, is_server: bool) -> bytes:
        """
        Post-handshake authorization gate.

        Must be called only after the handshake has completed (for example
        from :meth:`Connection.do_handshake` or a memory-BIO pump loop).  It
        returns the negotiated protocol when it is on the allow list and
        raises :class:`ALPNError` otherwise.

        :param connection: The connection whose negotiated ALPN result is
            checked.
        :param is_server: ``True`` when checking the accepting side, ``False``
            for the connecting side.  This only affects how the rejection
            reason is classified.
        :raises ALPNError: If no allowed protocol was negotiated.
        """
        negotiated = connection.get_alpn_proto_negotiated()

        if negotiated in self._protos:
            return negotiated

        if not self._handshake_done.get(connection, False):
            reason = ALPNRejectReason.NOT_HANDSHAKED
        elif is_server:
            reason = self._server_reason(connection)
        else:
            # A configured client always sends the ALPN extension, so an
            # empty result means the server selected nothing (no overlap or a
            # disallowed server-side choice), never a missing extension.
            reason = ALPNRejectReason.NO_COMMON_PROTOCOL

        raise ALPNError(reason, self._protos, negotiated)

    def wrap(
        self, connection: Connection, *, is_server: bool
    ) -> GuardedConnection:
        """
        Return a guarded connection that cannot carry application data
        unless this policy is satisfied.

        Every application entry point (:meth:`~GuardedConnection.do_handshake`,
        :meth:`~GuardedConnection.send`, :meth:`~GuardedConnection.sendall`,
        :meth:`~GuardedConnection.recv`, :meth:`~GuardedConnection.recv_into`)
        invokes :meth:`check` first.  BIO plumbing methods
        (:meth:`~OpenSSL.SSL.Connection.bio_read`,
        :meth:`~OpenSSL.SSL.Connection.bio_write`) stay available so memory-BIO
        handshake pumps keep working even when the policy ultimately rejects
        the connection.
        """
        return GuardedConnection(connection, self, is_server=is_server)


class GuardedConnection:
    """
    A proxy over :class:`~OpenSSL.SSL.Connection` that enforces an
    :class:`ALPNPolicy` on every application operation.

    Instances are created with :meth:`ALPNPolicy.wrap`; they are not meant to
    be constructed directly.  Attributes other than the guarded application
    methods are delegated to the wrapped connection unchanged.
    """

    __slots__ = ("_connection", "_policy", "_is_server")

    def __init__(
        self,
        connection: Connection,
        policy: ALPNPolicy,
        *,
        is_server: bool,
    ) -> None:
        self._connection = connection
        self._policy = policy
        self._is_server = is_server

    @property
    def connection(self) -> Connection:
        """The wrapped, unguarded :class:`~OpenSSL.SSL.Connection`."""
        return self._connection

    def require_negotiated_protocol(self) -> bytes:
        """
        Return the negotiated protocol or raise :class:`ALPNError`.

        This is the explicit gate callers can use before touching
        application data.
        """
        return self._policy.check(self._connection, is_server=self._is_server)

    def do_handshake(self) -> None:
        try:
            self._connection.do_handshake()
        except WantReadError:
            # Still waiting for handshake bytes from the peer.
            raise
        # A normal return means the TLS handshake finished on this side.
        self._policy.mark_handshake_done(self._connection)
        self.require_negotiated_protocol()

    def send(self, buf: _Buffer, flags: int = 0) -> int:
        self.require_negotiated_protocol()
        return self._connection.send(buf, flags)

    def sendall(self, buf: _Buffer, flags: int = 0) -> int:
        self.require_negotiated_protocol()
        return self._connection.sendall(buf, flags)

    def recv(self, bufsiz: int, flags: int | None = None) -> bytes:
        self.require_negotiated_protocol()
        return self._connection.recv(bufsiz, flags)

    def recv_into(
        self,
        buffer: Any,
        nbytes: int | None = None,
        flags: int | None = None,
    ) -> int:
        self.require_negotiated_protocol()
        return self._connection.recv_into(buffer, nbytes, flags)

    def __getattr__(self, name: str) -> Any:
        # Delegating accessor: only reached for names not found on the proxy
        # itself, so the guarded methods above always win.
        return getattr(self._connection, name)

    def __repr__(self) -> str:
        return (
            f"<GuardedConnection is_server={self._is_server} "
            f"protos={list(self._policy.protocols)!r} "
            f"wrapped={self._connection!r}>"
        )


def memory_bio_pair(
    client_context: Context, server_context: Context
) -> tuple[Connection, Connection]:
    """
    Build a client/server :class:`~OpenSSL.SSL.Connection` pair wired together
    with paired in-memory BIOs (``socket=None``).

    The returned connections are put into connect/accept state but no
    handshake bytes have been exchanged yet; drive them with
    :func:`pump_in_memory` or :func:`handshake_in_memory`.
    """
    server = Connection(server_context, None)
    client = Connection(client_context, None)
    server.set_accept_state()
    client.set_connect_state()
    return client, server


def _drain_bio(source: Connection, sink: Connection) -> bool:
    moved = False
    while True:
        try:
            chunk = source.bio_read(4096)
        except WantReadError:
            return moved
        sink.bio_write(chunk)
        moved = True


def _advance(connection: Connection) -> bool:
    """
    Let one side process incoming handshake records.

    Return ``True`` when its handshake has finished, ``False`` when it is still
    waiting for more bytes.  Any other :class:`OpenSSL.SSL.Error` (a fatal
    alert such as "no application protocol") propagates to the caller.
    """
    try:
        connection.do_handshake()
    except WantReadError:
        return False
    return True


def pump_in_memory(
    client: Connection, server: Connection, max_rounds: int = 1024
) -> None:
    """
    Drive handshakes on two memory-BIO connections to completion.

    Each round lets both sides process any incoming records by calling
    :meth:`~OpenSSL.SSL.Connection.do_handshake`, then copies every TLS record
    each side produced into the other side's input BIO.  Only handshake/BIO
    plumbing is used, so application data is never delivered even if a
    connection somehow reached that state.

    :raises OpenSSL.SSL.Error: If a side aborts the handshake (for example a
        fatal "no application protocol" alert).
    :raises RuntimeError: If the exchange stops making progress without either
        side finishing (defensive loop guard).
    """
    client_done = False
    server_done = False

    for _ in range(max_rounds):
        if not client_done:
            client_done = _advance(client)
        if not server_done:
            server_done = _advance(server)

        progressed = _drain_bio(client, server) or _drain_bio(server, client)

        if client_done and server_done:
            return

        if not progressed and not (client_done or server_done):
            raise RuntimeError("memory BIO handshake stalled without progress")

    raise RuntimeError("memory BIO handshake exceeded maximum pump rounds")


def handshake_in_memory(
    client: GuardedConnection, server: GuardedConnection
) -> None:
    """
    Complete a TLS handshake over paired memory BIOs and enforce the mandatory
    ALPN policy on both ends.

    *client* and *server* must be :class:`GuardedConnection` objects wrapping
    connections created with ``socket=None`` (see
    :func:`memory_bio_pair`).  On success both connections have negotiated an
    allowed protocol; otherwise the first detected error is raised:

    * :class:`OpenSSL.SSL.Error` for an ordinary TLS failure such as a
      certificate verification problem or a fatal ALPN alert, or
    * :class:`ALPNError` when the handshake finished but did not negotiate an
      allowed protocol.

    A rejected connection can never carry application data because every
    guarded read/write re-runs the policy gate.
    """
    raw_client = client.connection
    raw_server = server.connection

    # Pump records and drive the raw handshakes.  A failed handshake (for
    # example a fatal "no application protocol" alert) surfaces here as an
    # OpenSSL.SSL.Error before any policy check.
    pump_in_memory(raw_client, raw_server)

    # Record completion, then run the authoritative post-handshake
    # authorization on both sides.  This does not depend on a selection
    # callback having run: a missing extension and an empty intersection both
    # leave get_alpn_proto_negotiated() returning b"" and are rejected.  Check
    # the server first so that "peer sent no ALPN extension" (its selection
    # callback never ran) is reported distinctly from an empty intersection.
    client._policy.mark_handshake_done(raw_client)
    server._policy.mark_handshake_done(raw_server)
    server.require_negotiated_protocol()
    client.require_negotiated_protocol()
