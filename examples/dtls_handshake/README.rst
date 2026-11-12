Embeddable DTLS handshake driver
================================

This example shows how to drive a DTLS handshake with pyOpenSSL from inside an
existing event loop, using **memory BIOs** and an **injectable scheduler**.
It deliberately adds no networking framework and never opens a socket: every
datagram OpenSSL produces is returned to the embedding code, which is free to
send it over UDP, a tunnel, a simulated link, or anything else.

Files
-----

``dtls_handshake_driver.py``
    The reusable piece.  ``DtlsHandshakeDriver`` wraps one memory-BIO
    :class:`~OpenSSL.SSL.Connection`, advances its handshake, drains outbound
    datagrams into a callback, and mirrors OpenSSL's retransmission deadline
    onto a pluggable scheduler.

``dtls_demo.py``
    A self-contained, fully in-memory demonstration and assertion suite.  A
    ``VirtualScheduler`` records timer deadlines and a ``VirtualTransport``
    moves datagrams between two drivers with pluggable loss and duplication
    policies.  The whole run guards ``socket.socket`` so that creating a real
    socket would fail the program.

How retransmission timing works (no busy waiting)
-------------------------------------------------

OpenSSL owns the DTLS retransmission state machine.  After each handshake
step the driver calls:

* ``Connection.DTLSv1_get_timeout()`` to read the seconds remaining until
  OpenSSL wants to retransmit, and schedules exactly one callback with the
  injected scheduler;
* when that callback runs, ``Connection.DTLSv1_handle_timeout()`` tells
  OpenSSL to emit the retransmitted flight, which the driver drains through
  the same caller-owned datagram callback as every other outbound record.

There is no polling loop.  Between an inbound datagram and the next timer
nothing happens.  When ``get_timeout`` returns ``None`` no timer is armed at
all.

The scheduler contract is the three-line ``Scheduler`` protocol in the driver
module (``call_later(delay, callback, owner)`` returning an object with
``cancel()``), so an asyncio adapter is simply::

    class AsyncioScheduler:
        def call_later(self, delay, callback, owner):
            return asyncio.get_running_loop().call_later(delay, callback)

Stale timers cannot resurrect a finished connection
---------------------------------------------------

Each time a timer is armed it gets a generation number, and cancelling or
re-arming increments it.  A callback whose generation no longer matches is
discarded and recorded as ``stale_timer_ignored``; terminal states
(``connected``, ``cancelled``, ``failed``) are checked first.  An old timer
therefore can never reactivate a completed or closed SSL object, and a timer
firing after completion results in zero extra datagrams.

Demonstrated scenarios
----------------------

Run ``python examples/dtls_handshake/dtls_demo.py`` (about two seconds of real
waiting, because OpenSSL's first DTLS retransmit deadline is one second and
its internal monotonic clock cannot be virtualised through the public API).

1. **Happy path** - both sides reach ``CONNECTED`` and no timer remains armed.
2. **Lost handshake datagram** - the first ClientHello is dropped; the
   retransmission timer fires once, the retransmitted ClientHello is handed
   back to the caller and the handshake completes.
3. **Duplicated delivery** - the first ClientHello is delivered twice;
   OpenSSL ignores the replay and the handshake still completes once.
4. **Timer after completion** - calling ``handle_timeout`` and replaying a
   stale driver callback on a connected connection produces no sends and
   leaves the state as ``CONNECTED``.
5. **Cancellation** - cancelling while waiting to retransmit retires the
   timer and guarantees no further datagrams or inbound processing.
6. **Definitive OpenSSL failure** - the server presents an untrusted chain,
   the client fails with ``certificate verify failed``, emits a fatal alert
   through the caller path, and enters a terminal ``FAILED`` state with no
   retry scheduled; ``handle_timeout`` cannot resurrect it.

Every driver keeps a ``timer_events`` audit trail and every entry carries the
owning ``connection_id``, so the printed audit shows precisely which
connection each timer belonged to.  Handshake terminal states are read from
the drivers themselves (``state``, plus ``failure`` for the OpenSSL error).
