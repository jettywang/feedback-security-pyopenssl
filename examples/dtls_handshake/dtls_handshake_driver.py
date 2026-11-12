"""Embed-friendly DTLS handshake driver for pyOpenSSL.

This module drives a DTLS :class:`~OpenSSL.SSL.Connection` that uses a
*memory BIO*.  It never opens a socket and never performs a blocking wait:

* every datagram OpenSSL produces is handed back to the embedding
  application through an ``on_datagram`` callback;
* retransmission timing is taken from OpenSSL itself through
  :meth:`~OpenSSL.SSL.Connection.DTLSv1_get_timeout` and
  :meth:`~OpenSSL.SSL.Connection.DTLSv1_handle_timeout`, and the actual
  waiting is delegated to an injectable scheduler.

The scheduler interface (:class:`Scheduler`) is intentionally tiny so the
driver can be embedded in asyncio, Twisted, a select loop or, as in the
accompanying demo, a fully simulated clock.  No busy waiting is involved:
the driver schedules exactly one timer per connection and stays idle until
either an inbound datagram or the timer fires.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable, Protocol

from OpenSSL import SSL


class HandshakeState(str, Enum):
    """Lifecycle state of a single DTLS handshake."""

    PENDING = "pending"
    CONNECTED = "connected"
    CANCELLED = "cancelled"
    FAILED = "failed"


class TimerHandle(Protocol):
    """Opaque object returned by a :class:`Scheduler`."""

    def cancel(self) -> None:
        """Cancel the timer.  Cancelling an already-fired timer is a no-op."""


class Scheduler(Protocol):
    """Minimal scheduling contract the driver depends on.

    Implementations measure time with whatever clock the embedding event
    loop uses (``monotonic``, a simulated clock, ...).  ``call_later`` must
    return an object whose ``cancel()`` unschedules the callback.
    """

    def call_later(
        self, delay: float, callback: Callable[[], None], owner: str
    ) -> TimerHandle:
        """Run ``callback`` after roughly ``delay`` seconds."""


DatagramSink = Callable[[str, bytes], None]
"""Called as ``sink(connection_id, datagram)`` for each outbound datagram."""


class DtlsHandshakeDriver:
    """Drive one memory-BIO DTLS connection through its handshake.

    :param connection: a :class:`~OpenSSL.SSL.Connection` already placed in
        connect or accept state and configured with a memory BIO.
    :param connection_id: stable identifier used in callbacks and logs; this
        is what makes every scheduled timer attributable to a connection.
    :param scheduler: injectable :class:`Scheduler` used for retransmission.
    :param on_datagram: called with ``(connection_id, payload)`` for every
        datagram OpenSSL wants sent.  The embedding code owns the actual
        transport; this class never touches a socket.
    """

    def __init__(
        self,
        connection: SSL.Connection,
        connection_id: str,
        scheduler: Scheduler,
        on_datagram: DatagramSink,
    ) -> None:
        self._ssl = connection
        self.connection_id = connection_id
        self._scheduler = scheduler
        self._on_datagram = on_datagram
        self.state = HandshakeState.PENDING
        self.failure: SSL.Error | None = None
        self._timer: TimerHandle | None = None
        # Bumped every time a timer is (re)armed.  A stale timer callback
        # carrying an older generation must never touch a finished SSL object.
        self._generation = 0
        # Audit trail of every timer this driver armed, newest last.  Each
        # entry records which connection it belongs to and why it existed.
        self.timer_events: list[dict[str, Any]] = []

    @property
    def is_terminal(self) -> bool:
        """Whether the handshake has reached a final state."""
        return self.state in (
            HandshakeState.CONNECTED,
            HandshakeState.CANCELLED,
            HandshakeState.FAILED,
        )

    @property
    def ssl(self) -> SSL.Connection:
        """The underlying connection, exposed for post-handshake use."""
        return self._ssl

    @property
    def current_timeout(self) -> float | None:
        """OpenSSL's current retransmission deadline, in seconds.

        Mirrors :meth:`~OpenSSL.SSL.Connection.DTLSv1_get_timeout` so callers
        can audit the live deadline without reaching into private members.
        ``None`` means OpenSSL has no retransmission pending.
        """
        return self._ssl.DTLSv1_get_timeout()

    def start(self) -> None:
        """Kick off the handshake and emit the first flight."""
        if self.state is not HandshakeState.PENDING:
            raise RuntimeError(
                f"connection {self.connection_id} already {self.state.value}"
            )
        self._pump()

    def feed(self, datagram: bytes) -> None:
        """Deliver one inbound datagram to OpenSSL and advance the state.

        Duplicated datagrams are safe to feed: OpenSSL's DTLS state machine
        silently ignores a replayed record rather than failing.  Datagrams
        arriving after the handshake reached a terminal state are dropped.
        """
        if self.is_terminal:
            self.timer_events.append(
                {
                    "connection_id": self.connection_id,
                    "event": "datagram_dropped_terminal",
                    "state": self.state.value,
                }
            )
            return
        self._ssl.bio_write(datagram)
        self._pump()

    def cancel(self) -> None:
        """Abort the handshake.

        The pending timer (if any) is cancelled and no further datagrams are
        emitted.  We deliberately do not call :meth:`SSL.Connection.shutdown`
        so that cancelling never produces surprise outbound traffic.
        """
        if self.is_terminal:
            return
        self.state = HandshakeState.CANCELLED
        self._cancel_timer()
        self.timer_events.append(
            {
                "connection_id": self.connection_id,
                "event": "cancelled",
                "state": self.state.value,
            }
        )

    def _pump(self) -> None:
        """Advance the OpenSSL state machine once and reconcile I/O/timers."""
        if self.is_terminal:
            return
        try:
            self._ssl.do_handshake()
        except SSL.WantReadError:
            # OpenSSL is waiting for the peer or for its retransmission
            # timer.  Drain anything it queued, then (re)arm the timer.
            self._drain_outbound()
            self._sync_timer()
        except SSL.Error as exc:
            # A definitive OpenSSL failure (e.g. certificate verification).
            # This is terminal: nothing is retried, no timer stays armed.
            self.failure = exc
            self.state = HandshakeState.FAILED
            self._cancel_timer()
            # The fatal alert OpenSSL just generated still has to reach the
            # peer; emit it through the same caller-owned datagram path.
            self._drain_outbound()
            self.timer_events.append(
                {
                    "connection_id": self.connection_id,
                    "event": "failed",
                    "detail": exc.args[0] if exc.args else None,
                }
            )
        else:
            self.state = HandshakeState.CONNECTED
            self._cancel_timer()
            self._drain_outbound()
            self.timer_events.append(
                {
                    "connection_id": self.connection_id,
                    "event": "connected",
                    "state": self.state.value,
                }
            )

    def _drain_outbound(self) -> None:
        """Forward every queued memory-BIO datagram to the embedding code."""
        while True:
            try:
                datagram = self._ssl.bio_read(65536)
            except SSL.WantReadError:
                return
            if not datagram:
                return
            self._on_datagram(self.connection_id, datagram)

    def _sync_timer(self) -> None:
        """Mirror OpenSSL's retransmission deadline onto the scheduler."""
        self._cancel_timer()
        timeout = self._ssl.DTLSv1_get_timeout()
        if timeout is None:
            # No retransmission pending (e.g. waiting purely on the peer).
            return
        generation = self._generation
        self._timer = self._scheduler.call_later(
            timeout,
            lambda: self._on_timeout(generation),
            self.connection_id,
        )
        self.timer_events.append(
            {
                "connection_id": self.connection_id,
                "event": "timer_armed",
                "delay": timeout,
                "generation": generation,
            }
        )

    def _on_timeout(self, generation: int) -> None:
        self._timer = None
        # Guard against a stale callback resurfacing after completion,
        # failure, cancellation or a newer timer replacing this one.
        if self.is_terminal or generation != self._generation:
            self.timer_events.append(
                {
                    "connection_id": self.connection_id,
                    "event": "stale_timer_ignored",
                    "generation": generation,
                    "state": self.state.value,
                }
            )
            return
        handled = self._ssl.DTLSv1_handle_timeout()
        self.timer_events.append(
            {
                "connection_id": self.connection_id,
                "event": "timer_fired",
                "retransmitted": handled,
                "generation": generation,
            }
        )
        if handled:
            # OpenSSL queued the retransmitted flight; the caller still owns
            # sending it, exactly like any other outbound datagram.
            self._drain_outbound()
        # Re-query OpenSSL for the next (exponentially backed off) deadline.
        self._sync_timer()

    def _cancel_timer(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        self._generation += 1
