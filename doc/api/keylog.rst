.. _openssl-keylog:

:py:mod:`OpenSSL.keylog` --- Per-connection, authorized TLS key logging
=======================================================================

.. py:module:: OpenSSL.keylog
   :synopsis: Per-connection, explicitly authorized TLS key logging


.. versionadded:: 26.4.1

OpenSSL only offers a *context-wide* key log callback, so a callback set on a
:class:`~OpenSSL.SSL.Context` fires for every connection that shares it.
This module adds an explicit, per-connection authorization layer on top of
that callback so that operations can capture the session keys of a single
connection being debugged without ever writing the keys of the other
connections sharing the same context.

Key logging is **off by default** and is never enabled implicitly.  In
particular the ``SSLKEYLOGFILE`` environment variable is not consulted; a
connection only reaches a sink after an explicit
:meth:`~KeyLogAuthority.authorize` call, and the authorization can be
withdrawn again with :meth:`~KeyLogAuthority.revoke` before the connection
ends.

A minimal, file-backed debugging session looks like this::

    from OpenSSL.keylog import KeyLogAuthority, FileKeyLogSink

    authority = KeyLogAuthority()
    # Must run before the context creates any connection.
    authority.install(server_context)

    # Later, for exactly the connection under investigation:
    sink = FileKeyLogSink("/var/tmp/debug-connection.keylog")
    authority.authorize(debug_connection, sink)

    # Stop capture at any point, from any thread. Once this returns, no new
    # key line for that connection can reach the sink.
    authority.revoke(debug_connection)

The resulting file uses the NSS ``SSLKEYLOGFILE`` line format and can be
loaded directly by tools such as Wireshark/tshark.

Revocation and threading semantics
----------------------------------

* :meth:`~KeyLogAuthority.revoke` is safe to call from a thread other than
  the one driving the TLS connection.  After it returns, the context-wide
  callback drops every subsequent line for that connection.
* A sink call already in progress when revocation is requested is allowed to
  finish; :meth:`~KeyLogAuthority.revoke` waits for it (optionally bounded by
  a timeout) so the caller gets a precise cut-off point.
* Calling :meth:`~KeyLogAuthority.revoke` from inside the sink on the same
  thread returns immediately instead of waiting for the sink call that is
  still on the stack, which would deadlock.
* The authority itself never buffers key lines, so there is nothing to purge
  at this layer: a line that is not authorized at callback time is dropped
  synchronously.  A *sink* that buffers accepted lines may optionally expose
  ``flush()``; it is invoked once the gate is closed so the sink can drain
  data it already accepted.  Whether such pending data is written or
  discarded is the sink's own policy.

Failure handling
----------------

A sink that raises never breaks the handshake.  Failures are reported through
a diagnostics callable that receives only the connection, the phase
(``"write"`` or ``"flush"``) and the *type name* of the exception.  The key
line itself is never included, so secrets cannot leak into diagnostics or
ordinary application logs.


.. autoclass:: KeyLogAuthority
   :members:

.. autoclass:: KeyLogSink
   :members:

.. autoclass:: FileKeyLogSink
   :members:
