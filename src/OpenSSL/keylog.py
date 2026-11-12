# Copyright (C) AB Strakt
# See LICENSE for details.

"""
Per-connection, explicitly authorized TLS key logging.

OpenSSL (and therefore pyOpenSSL) only exposes a *context-wide* key log
callback via :meth:`OpenSSL.SSL.Context.set_keylog_callback`.  When many
connections share one :class:`~OpenSSL.SSL.Context`, that callback fires for
every one of them.  Operations only occasionally needs key material to debug
a single connection, and the session keys of every other connection sharing
the context must never be written to disk alongside it.

This module adds the missing authorization layer:

* key logging is **off by default** and is never enabled implicitly - in
  particular the ``SSLKEYLOGFILE`` environment variable is not consulted;
* a connection only reaches the configured *sink* after an explicit
  :meth:`KeyLogAuthority.authorize` call, and can be revoked again with
  :meth:`KeyLogAuthority.revoke` before the connection ends;
* revocation is safe to call from a different thread than the one driving
  the TLS connection; once :meth:`~KeyLogAuthority.revoke` returns, no new
  key line for that connection can reach the sink;
* a failing sink produces a controllable, sanitized diagnostic.  Key lines
  are never embedded in diagnostics or written to ordinary application logs.

The authority itself never buffers key lines: a line that is not currently
authorized is dropped synchronously inside the OpenSSL callback.  See the
:meth:`KeyLogAuthority.revoke` documentation for the exact semantics of
lines already accepted and lines still cached inside a buffering sink.
"""

from __future__ import annotations

import threading
from io import BufferedWriter
from typing import Protocol, runtime_checkable

from OpenSSL._util import lib as _lib
from OpenSSL.SSL import Connection, Context

__all__ = [
    "KeyLogAuthority",
    "FileKeyLogSink",
    "KeyLogSink",
    "KeyLogDiagnostics",
]


@runtime_checkable
class KeyLogSink(Protocol):
    """
    A receiver of authorized TLS key log lines.

    ``write_line`` is called from the OpenSSL key log callback, i.e. from the
    thread driving the TLS connection, while holding no internal lock of the
    :class:`KeyLogAuthority`.  Implementations must not block indefinitely
    and must not raise back into the caller - failures are reported through
    the authority's diagnostics callback instead.

    An optional ``flush`` callable is invoked by
    :meth:`KeyLogAuthority.revoke` after the gate has been closed, so that a
    buffering sink can drain the lines it already accepted.
    """

    def write_line(self, line: bytes) -> None:
        """
        Deliver one NSS ``SSLKEYLOGFILE`` formatted key log *line*.

        The line does not include a trailing newline.
        """


# ``flush`` is optional, so the runtime check performed in ``authorize``
# only looks for ``write_line`` instead of relying on isinstance(), which
# would require every protocol member to be present.


class KeyLogDiagnostics(Protocol):
    """
    Callable used to report problems with a key log sink.

    The arguments never contain key material: *error_type* is the exception
    class name and *phase* is ``"write"`` or ``"flush"``.
    """

    def __call__(
        self, connection: Connection, phase: str, error_type: str
    ) -> None: ...


def _default_diagnostics(
    connection: Connection, phase: str, error_type: str
) -> None:
    """
    Default sink-failure diagnostic: a single sanitized line on stderr.

    The key line itself is deliberately excluded; only the phase and the
    exception's type name are emitted, so secrets can never reach ordinary
    application logs.
    """
    import sys

    sys.stderr.write(
        f"OpenSSL.keylog: sink failure during {phase} "
        f"(error type: {error_type}); key line discarded\n"
    )


class _Gate:
    """
    The authorization state for a single connection.

    Each connection gets its own gate and its own lock, so authorizing or
    revoking one connection never blocks key log delivery for another.
    """

    def __init__(self, connection: Connection, sink: KeyLogSink) -> None:
        self.connection = connection
        self.sink = sink
        # The condition carries its own re-entrant lock; all gate state is
        # mutated while holding it.
        self.condition = threading.Condition()
        self.authorized = True
        # Number of threads currently executing the sink for this gate.
        self.in_flight = 0
        # Identity of the thread (if any) currently inside the sink, used to
        # detect re-entrant revoke() calls made from inside the sink.
        self.sink_thread: int | None = None


class KeyLogAuthority:
    """
    Authorizes TLS key logging per connection on a shared context.

    A single authority is installed on a :class:`~OpenSSL.SSL.Context`
    before any connection is created:

    >>> authority = KeyLogAuthority()
    >>> authority.install(server_context)   # doctest: +SKIP

    Nothing is logged until a specific connection is explicitly authorized,
    passing the sink that should receive its key lines:

    >>> authority.authorize(
    ...     server_conn, FileKeyLogSink(path)
    ... )  # doctest: +SKIP

    Authorization can be withdrawn at any time, from any thread, with
    :meth:`revoke`.
    """

    def __init__(
        self,
        on_sink_error: KeyLogDiagnostics | None = None,
    ) -> None:
        """
        :param on_sink_error: optional callable invoked when a sink raises.
            It receives the connection, the phase (``"write"`` or
            ``"flush"``) and the *type name* of the exception.  It must not
            raise.  When omitted, a single sanitized line is written to
            stderr.  Key material is never passed to this callable.
        """
        self._on_sink_error = on_sink_error or _default_diagnostics
        self._registry_lock = threading.Lock()
        self._gates: dict[Connection, _Gate] = {}
        # Diagnostics counters, useful for tests and operational monitoring.
        self.delivered = 0
        self.refused = 0
        self.dropped = 0
        self.sink_failures = 0

    def install(self, context: Context) -> None:
        """
        Install this authority's context-wide key log callback.

        pyOpenSSL only allows a key log callback to be set on a context
        before it has been used to create a connection, so this must be
        called once, up front.  Installing the callback enables nothing by
        itself: every connection remains unauthorized until
        :meth:`authorize` is called for it explicitly.

        :raises NotImplementedError: if the linked OpenSSL build does not
            provide a key log callback at all.
        """
        if not getattr(_lib, "Cryptography_HAS_KEYLOG", 0):
            raise NotImplementedError(
                "Key logging is not available in the linked OpenSSL build"
            )
        context.set_keylog_callback(self._context_keylog_callback)

    def authorize(self, connection: Connection, sink: KeyLogSink) -> None:
        """
        Explicitly authorize key logging for *connection* into *sink*.

        Only key material generated or received by *connection* afterwards
        is delivered to *sink*.  Other connections sharing the context are
        unaffected.  Re-authorizing a connection that was revoked replaces
        its sink and starts a fresh authorization period.

        :raises TypeError: if *sink* does not provide ``write_line``.
        """
        if not isinstance(sink, KeyLogSink):
            raise TypeError("sink must provide a write_line(bytes) method")
        gate = _Gate(connection, sink)
        with self._registry_lock:
            self._gates[connection] = gate

    def revoke(
        self,
        connection: Connection,
        timeout: float | None = None,
    ) -> bool:
        """
        Revoke key logging authorization for *connection*.

        Semantics:

        * after this method returns, no new key line for *connection* can
          reach its sink - the context-wide callback drops them;
        * a key line whose sink call was already in progress when revoke
          was requested is allowed to finish (the line was already handed
          to the sink); the method waits for those in-flight calls, up to
          *timeout* seconds, so that callers get a precise boundary;
        * the authority itself never buffers lines, so there is nothing to
          purge at this layer.  Lines still held inside a *buffering sink*
          are not discarded: if the sink provides ``flush()`` it is invoked
          once the gate is closed, giving the sink a chance to write the
          lines it already accepted.  Sinks that want revoke to discard
          pending data should implement that policy in their own
          ``flush()``/close logic - the authority cannot reach into them;
        * revoking a connection that was never authorized, or revoking it
          twice, is a no-op returning ``False``;
        * when *timeout* elapses while a sink call is still running,
          returns ``False`` instead of blocking forever.  The gate stays
          closed either way, so no new lines can be delivered.

        Re-entrant use: if :meth:`revoke` is called from inside the sink
        (same thread), the method closes the gate and returns immediately
        rather than waiting for the sink call that is still on the stack -
        waiting would deadlock.

        :param timeout: maximum seconds to wait for in-flight sink calls;
            ``None`` (the default) waits indefinitely.
        :return: ``True`` if an authorization was revoked and no sink call
            remained in flight, ``False`` if there was nothing to revoke or
            the timeout expired.
        """
        with self._registry_lock:
            gate = self._gates.pop(connection, None)
        if gate is None:
            return False

        current_thread = threading.get_ident()
        with gate.condition:
            gate.authorized = False
            reentrant = gate.sink_thread == current_thread
            if not reentrant:
                if timeout is None:
                    gate.condition.wait_for(lambda: gate.in_flight == 0)
                elif not gate.condition.wait_for(
                    lambda: gate.in_flight == 0, timeout
                ):
                    return False

        # The gate is closed. Give a buffering sink a chance to drain lines
        # it already accepted. No lock is held, and a failure here cannot
        # re-open the gate.
        flush = getattr(gate.sink, "flush", None)
        if callable(flush):
            try:
                flush()
            except Exception as exc:
                self._report_failure(connection, "flush", type(exc).__name__)
        return True

    def is_authorized(self, connection: Connection) -> bool:
        """
        Return whether *connection* currently has an active authorization.
        """
        with self._registry_lock:
            gate = self._gates.get(connection)
        return gate is not None and gate.authorized

    def _context_keylog_callback(
        self, connection: Connection, line: bytes
    ) -> None:
        """
        The single context-wide callback installed by :meth:`install`.

        It looks up the per-connection gate and drops the line unless that
        exact connection has been explicitly authorized.
        """
        with self._registry_lock:
            gate = self._gates.get(connection)
        if gate is None or not gate.authorized:
            self.refused += 1
            return

        thread_id = threading.get_ident()
        with gate.condition:
            # Re-check under the gate lock: revoke() may have run between
            # the registry lookup and here.
            if not gate.authorized:
                self.refused += 1
                return
            gate.in_flight += 1
            gate.sink_thread = thread_id

        try:
            gate.sink.write_line(line)
        except Exception as exc:
            # Never let a sink failure escape into OpenSSL, and never put
            # the key line into the diagnostic.
            self.dropped += 1
            self._report_failure(connection, "write", type(exc).__name__)
        else:
            self.delivered += 1
        finally:
            with gate.condition:
                gate.in_flight -= 1
                if gate.sink_thread == thread_id:
                    gate.sink_thread = None
                if gate.in_flight == 0:
                    gate.condition.notify_all()

    def _report_failure(
        self, connection: Connection, phase: str, error_type: str
    ) -> None:
        self.sink_failures += 1
        try:
            self._on_sink_error(connection, phase, error_type)
        except Exception:
            # A broken diagnostics callback must not take down the TLS
            # connection; swallow it.
            pass


class FileKeyLogSink:
    """
    A :class:`KeyLogSink` that appends authorized key lines to a file.

    Only lines of connections explicitly authorized for this sink are ever
    written to it.  The file is opened lazily on the first line, kept open
    for the lifetime of the sink, and flushed after every write so that a
    crash still leaves a usable (Wireshark-compatible) key log.

    The sink opens its own path; this class deliberately never reads
    ``SSLKEYLOGFILE`` or any other environment variable.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._file: BufferedWriter | None = None
        self._lock = threading.Lock()

    def write_line(self, line: bytes) -> None:
        with self._lock:
            if self._file is None:
                # Binary mode: key lines are bytes and must never be
                # re-encoded by a text layer.
                self._file = open(self._path, "ab")
            self._file.write(line + b"\n")
            self._file.flush()

    def flush(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.flush()

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.close()
                self._file = None

    @property
    def path(self) -> str:
        return self._path
