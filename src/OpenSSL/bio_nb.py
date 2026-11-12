# Copyright (c) The pyOpenSSL developers
# See LICENSE for details.

"""
A small non-blocking send adapter for pyOpenSSL connections that use
memory BIOs.

A :class:`Connection` created with ``sock=None`` never touches a socket
itself.  Every TLS record it produces lands in its write-side memory BIO
and is retrieved with :meth:`Connection.bio_read`; every record the peer
sends is fed back with :meth:`Connection.bio_write`.  This module adds
the bookkeeping that makes plain application data safe to queue on top of
such a connection without taking a dependency on any event loop:

* Byte ownership is taken at :meth:`BioSendAdapter.submit` time.  The
  caller's ``bytearray`` or ``memoryview`` is copied immediately, so the
  caller is free to mutate or release the original buffer on return.
* Retries always reuse the *same* message.  A
  :class:`~OpenSSL.SSL.WantReadError` or
  :class:`~OpenSSL.SSL.WantWriteError` never advances the offset of the
  message at the head of the queue; the next :meth:`pump` call retries
  exactly the un-sent prefix instead of moving on to the next message.
* The queue is bounded and applies backpressure through
  :class:`QueueFull`.
* Every pump moves a bounded amount of data, driven by a caller supplied
  transport writer.  A writer that returns ``0`` means "would block" and
  produces :data:`PumpState.WANT_WRITE`; data already encrypted into the
  egress buffer stays there and is retried first next time.
* Cancellation and failure return an exact accounting of confirmed
  progress and the still-un-sent bytes.  The adapter never opens another
  connection and never forwards un-acknowledged bytes anywhere itself.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import (
    Callable,
    Final,
    Literal,
    NoReturn,
    Protocol,
    runtime_checkable,
)

from OpenSSL.SSL import (
    Connection,
    WantReadError,
    WantWriteError,
)
from OpenSSL.SSL import (
    Error as SSLError,
)

__all__ = [
    "AdapterClosed",
    "BioSendAdapter",
    "DrainReport",
    "PumpResult",
    "PumpState",
    "QueueFull",
    "SendFailed",
    "UnsentMessage",
]


class AdapterClosed(Exception):
    """
    The adapter has been cancelled or has failed and no longer accepts
    work.
    """


class QueueFull(Exception):
    """
    A submission would make the queued, not-yet-accepted-by-TLS byte
    count exceed the adapter's ``max_queued_bytes`` limit.

    Nothing is enqueued and nothing is copied when this is raised; the
    caller retains full ownership of the rejected buffer.
    """


class SendFailed(Exception):
    """
    The TLS connection or the transport writer reported a hard error.

    The adapter is frozen in the failed state.  :attr:`report` describes
    exactly which bytes were accepted by TLS or handed to the transport
    and which remain un-sent, so the application can decide what to do
    (for example, reconnect and re-send the un-sent prefix after its own
    de-duplication).  The adapter never performs that re-delivery itself.
    """

    def __init__(self, report: DrainReport, cause: BaseException) -> None:
        super().__init__(str(cause))
        self.report = report
        self.cause = cause


@dataclass(frozen=True)
class UnsentMessage:
    """
    A message that was not fully accepted by TLS when work stopped.

    :ivar payload: The full bytes originally submitted (an owned copy).
    :ivar tls_accepted: How many leading bytes of ``payload`` were
        accepted by :meth:`Connection.send` before the stop.  These bytes
        were handed to TLS but may not have reached the peer, so they may
        need to be re-sent after the application's own de-duplication.
    """

    payload: bytes
    tls_accepted: int


@dataclass(frozen=True)
class DrainReport:
    """
    The accounting returned by cancellation or failure.

    :ivar transport_bytes: Total bytes handed to the transport writer
        across the lifetime of the adapter.  These left the adapter but
        are not necessarily acknowledged by the peer.
    :ivar egress_pending: Bytes already encrypted into TLS records and
        waiting in the adapter's egress buffer (never handed to the
        transport).
    :ivar unsent: Messages still on the queue, in submission order.  The
        first element is the partially TLS-accepted message, if any; the
        rest were never touched by TLS.
    """

    transport_bytes: int
    egress_pending: bytes
    unsent: tuple[UnsentMessage, ...]


PumpStateValue = Literal["idle", "want-write", "want-read"]


class PumpState:
    """
    The possible states reported by :meth:`BioSendAdapter.pump`.
    """

    #: Nothing more can be done right now: the egress buffer is empty,
    #: the handshake (if any) finished, and no queued message remains.
    IDLE: Final[PumpStateValue] = "idle"

    #: The transport writer refused data (returned ``0``) or the
    #: connection asked for the write BIO to be drained.  Call
    #: :meth:`~BioSendAdapter.pump` again once the transport is writable.
    #: The same message prefix is retried.
    WANT_WRITE: Final[PumpStateValue] = "want-write"

    #: Progress was made but the connection is waiting for more records
    #: from the peer (typically handshake data).  Feed those records with
    #: :meth:`~BioSendAdapter.feed_network` and pump again.
    WANT_READ: Final[PumpStateValue] = "want-read"


@dataclass(frozen=True)
class PumpResult:
    """
    The outcome of one bounded :meth:`BioSendAdapter.pump` call.

    :ivar state: One of the :class:`PumpState` constants.
    :ivar transport_delta: Bytes handed to the transport writer during
        this call (never greater than the call's ``max_transfer``).
    """

    state: PumpStateValue
    transport_delta: int


@runtime_checkable
class TransportWriter(Protocol):
    """
    A callable that moves one chunk of TLS records towards the peer.

    It must return the number of bytes consumed.  Returning ``0`` means
    the underlying transport would block; the bytes are retained by the
    adapter and retried on the next pump.  Raising an exception is a hard
    failure and freezes the adapter.
    """

    def __call__(self, data: bytes) -> int: ...


class _Message:
    __slots__ = ("payload", "sent")

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.sent = 0


class BioSendAdapter:
    """
    Bounded, non-blocking, loop-free sender for a memory-BIO connection.

    :param connection: A pyOpenSSL :class:`Connection` created with a
        memory BIO (``sock=None``).  The adapter does not change its
        blocking mode; memory-BIO connections are inherently non-blocking.
    :param transport: A callable taking ``bytes`` and returning the
        number of bytes written (``0`` for "would block").  See
        :class:`TransportWriter`.
    :param max_queued_bytes: Upper bound on bytes that have been
        submitted but not yet fully accepted by :meth:`Connection.send`.
    """

    def __init__(
        self,
        connection: Connection,
        transport: Callable[[bytes], int],
        max_queued_bytes: int,
    ) -> None:
        if max_queued_bytes < 1:
            raise ValueError("max_queued_bytes must be positive")
        self._connection = connection
        self._transport = transport
        self._max_queued_bytes = max_queued_bytes

        self._queue: deque[_Message] = deque()
        self._queued_bytes = 0
        self._egress = b""
        self._transport_total = 0
        self._handshake_done = False
        self._failed = False
        self._closed = False

    @property
    def state(self) -> str:
        """``"failed"``, ``"closed"`` or ``"open"``."""
        if self._failed:
            return "failed"
        if self._closed:
            return "closed"
        return "open"

    @property
    def queued_bytes(self) -> int:
        """Bytes submitted but not yet fully accepted by TLS."""
        return self._queued_bytes

    @property
    def queued_messages(self) -> int:
        """Number of messages still on the queue (head may be partial)."""
        return len(self._queue)

    @property
    def pending_egress_bytes(self) -> int:
        """Encrypted bytes buffered before the transport writer."""
        return len(self._egress)

    @property
    def transport_bytes(self) -> int:
        """Total bytes ever handed to the transport writer."""
        return self._transport_total

    def submit(self, data: bytes | bytearray | memoryview) -> int:
        """
        Take ownership of ``data`` and enqueue it behind earlier
        messages.

        Ownership is taken *here*, synchronously, by copying the bytes
        into an internal ``bytes`` object.  As soon as this call returns
        the caller may reuse, mutate or release ``data``; later pumps can
        never observe those mutations.  A non-contiguous ``memoryview`` is
        copied just as safely as a ``bytearray``.

        :return: The new queued byte count.
        :raises QueueFull: If accepting the message would exceed
            ``max_queued_bytes``.  The buffer is not copied in that case.
        :raises AdapterClosed: If the adapter was cancelled or failed.
        """
        self._ensure_live()
        size = len(data)
        if self._queued_bytes + size > self._max_queued_bytes:
            raise QueueFull(
                f"queue limit {self._max_queued_bytes} bytes exceeded: "
                f"{self._queued_bytes} queued + {size} requested"
            )
        # bytes(memoryview/bytearray) performs an independent copy, so the
        # adapter no longer aliases the caller's buffer after this point.
        owned = bytes(data)
        self._queue.append(_Message(owned))
        self._queued_bytes += size
        return self._queued_bytes

    def feed_network(self, record: bytes) -> None:
        """
        Deliver TLS records read from the peer into the connection's
        read-side memory BIO.

        Call this whenever the real transport becomes readable, then call
        :meth:`pump` so the connection can consume them (finishing a
        handshake, unblocking a renegotiation, ...).
        """
        self._ensure_live()
        view = memoryview(record)
        try:
            while view:
                try:
                    written = self._connection.bio_write(view)
                except (WantReadError, WantWriteError):
                    # Read BIO full: pump first so the connection can
                    # consume it, then the caller retries the remainder.
                    raise
                except SSLError as exc:
                    self._fail(exc)
                view = view[written:]
        finally:
            view.release()

    def pump(self, max_transfer: int = 16384) -> PumpResult:
        """
        Make one bounded, non-blocking round of progress.

        Each call first retries any buffered egress, then performs at most
        one TLS-level operation (one handshake step or one
        :meth:`Connection.send` attempt on the head message) and drains
        the records it produced.  No more than ``max_transfer`` bytes are
        handed to the transport writer in total, and the same head message
        is always retried after a WANT condition - the queue order never
        changes underneath a partial write.

        :param max_transfer: Maximum bytes handed to the transport in
            this call. Must be positive.
        :raises AdapterClosed: If cancelled or already failed.
        :raises SendFailed: If TLS or the transport reports a hard error.
        """
        self._ensure_live()
        if max_transfer < 1:
            raise ValueError("max_transfer must be positive")

        before = self._transport_total
        budget = max_transfer
        budget = self._flush_egress(budget)
        if budget == 0:
            return PumpResult(
                PumpState.WANT_WRITE, self._transport_total - before
            )

        blocked_on_read = False

        # At most one SSL-level attempt per call.  WANT conditions leave
        # the head message's offset untouched for the next call.
        if not self._handshake_done:
            try:
                self._connection.do_handshake()
                self._handshake_done = True
            except (WantReadError, WantWriteError):
                blocked_on_read = True
            except SSLError as exc:
                self._fail(exc)
        elif self._queue:
            blocked_on_read = self._send_head()

        if budget:
            drained = self._drain_bio(budget)
            budget -= len(drained)
            if drained:
                self._egress += drained
                self._flush_egress(budget)

        # Only bytes actually accepted by the transport count; records
        # drained into the egress buffer but refused by a blocking writer
        # stay owned by the adapter and are retried on the next pump.
        return PumpResult(
            self._outcome(blocked_on_read),
            self._transport_total - before,
        )

    def cancel(self) -> DrainReport:
        """
        Stop accepting work and return the full accounting.

        The underlying TLS connection is not closed or modified; only the
        adapter is stopped.  Idempotent: repeated calls return the same
        report.  No bytes are delivered to any other connection.
        """
        if self._failed or self._closed:
            return self._build_report()
        self._closed = True
        return self._build_report()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_live(self) -> None:
        if self._failed:
            raise AdapterClosed("adapter has failed")
        if self._closed:
            raise AdapterClosed("adapter was cancelled")

    def _outcome(self, blocked_on_read: bool) -> PumpStateValue:
        if self._egress:
            # The transport cannot take everything right now; retry the
            # same buffered (and therefore same head) bytes later.
            return PumpState.WANT_WRITE
        if not self._handshake_done:
            return PumpState.WANT_READ
        if self._queue:
            if blocked_on_read:
                return PumpState.WANT_READ
            return PumpState.WANT_WRITE
        return PumpState.IDLE

    def _send_head(self) -> bool:
        """
        Make one :meth:`Connection.send` attempt on the head message.

        Returns ``True`` if the connection raised WANT_READ (it is
        waiting for the peer), ``False`` otherwise.  WANT_WRITE and
        WANT_READ leave ``sent`` untouched; a partial accept advances it.
        """
        message = self._queue[0]
        remaining = memoryview(message.payload)[message.sent :]
        try:
            try:
                accepted = self._connection.send(remaining)
            except (WantReadError, WantWriteError):
                # Retry the SAME prefix on the next pump.  Do not dequeue.
                return True
            except SSLError as exc:
                self._fail(exc)
        finally:
            remaining.release()

        message.sent += accepted
        if message.sent == len(message.payload):
            self._queued_bytes -= len(message.payload)
            self._queue.popleft()
        return False

    def _drain_bio(self, limit: int) -> bytes:
        """Read at most ``limit`` bytes from the write-side memory BIO."""
        chunks: list[bytes] = []
        remaining = limit
        while remaining:
            size = min(4096, remaining)
            try:
                chunk = self._connection.bio_read(size)
            except WantReadError:
                break
            except SSLError as exc:
                self._fail(exc)
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _flush_egress(self, budget: int) -> int:
        """
        Push buffered egress to the transport while the budget lasts.

        A writer returning ``0`` means "would block": the retained prefix
        is retried first on the next pump.
        """
        while self._egress and budget:
            try:
                written = self._transport(self._egress[:budget])
            except Exception as exc:
                self._fail(exc)
            if written <= 0:
                break
            self._egress = self._egress[written:]
            self._transport_total += written
            budget -= written
        return budget

    def _fail(self, cause: BaseException) -> NoReturn:
        self._failed = True
        raise SendFailed(self._build_report(), cause)

    def _build_report(self) -> DrainReport:
        unsent = tuple(
            UnsentMessage(payload=item.payload, tls_accepted=item.sent)
            for item in self._queue
        )
        return DrainReport(
            transport_bytes=self._transport_total,
            egress_pending=self._egress,
            unsent=unsent,
        )
