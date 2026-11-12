.. _openssl-alpn:

:py:mod:`OpenSSL.alpn` --- Mandatory ALPN policy
=================================================

.. py:module:: OpenSSL.alpn
    :synopsis: Mandatory Application Layer Protocol Negotiation policy


The plain :class:`OpenSSL.SSL.Context` ALPN methods
(:meth:`~OpenSSL.SSL.Context.set_alpn_protos` and
:meth:`~OpenSSL.SSL.Context.set_alpn_select_callback`) treat ALPN as optional:
if the peer omits the ALPN extension, no offered protocol overlaps, or the
selection callback declines, the handshake can still complete with
:meth:`~OpenSSL.SSL.Connection.get_alpn_proto_negotiated` returning ``b""`` and
nothing stops application data from flowing.

:mod:`OpenSSL.alpn` layers a *mandatory* policy on top of that API.  A policy
is configured before the handshake and independently re-checked afterwards, so
a connection never reaches application read/write state unless one of the
explicitly allowed protocols was actually negotiated.  The post-handshake
check does not trust the selection callback: a connection whose callback never
ran (the peer sent no extension) is rejected rather than silently accepted.

Legacy callers that want to allow "no ALPN negotiated" keep using the
:mod:`OpenSSL.SSL` methods directly and are unaffected.

A runnable, end-to-end demonstration using paired in-memory BIOs lives in
``examples/mandatory_alpn.py``.


.. py:class:: ALPNPolicy(protos)

    A reusable mandatory ALPN allow list.  The same object can configure any
    number of client and server contexts.

    *protos* is a non-empty list of non-empty byte strings, in preference
    order, for example ``[b"h2", b"http/1.1"]``.  Duplicates are removed and
    invalid entries raise :class:`ValueError` or :class:`TypeError`.

    .. py:attribute:: protocols

        The tuple of protocols the policy requires, in preference order.

    .. py:method:: configure_client(context)

        Configure a client :class:`~OpenSSL.SSL.Context` to offer exactly the
        allowed protocols.  Must be called before the context creates a
        :class:`~OpenSSL.SSL.Connection`.

    .. py:method:: configure_server(context)

        Install a hardened selection callback on a server
        :class:`~OpenSSL.SSL.Context`.  The callback only ever returns an
        allowed protocol or
        :data:`~OpenSSL.SSL.NO_OVERLAPPING_PROTOCOLS`, never a disallowed
        value.  The handshake may still finish without a selection, so
        :meth:`check` remains the authoritative gate.

    .. py:method:: check(connection, is_server)

        Post-handshake authorization gate.  Returns the negotiated protocol
        when it is on the allow list, otherwise raises :class:`ALPNError`.
        Set *is_server* to ``True`` for the accepting side so that a missing
        ALPN extension (the selection callback never ran) is reported
        distinctly from an empty intersection.  Calling this before the
        handshake completes raises :class:`ALPNError` with
        :attr:`ALPNRejectReason.NOT_HANDSHAKED` instead of implicitly
        passing.

    .. py:method:: mark_handshake_done(connection)

        Record that the TLS handshake for *connection* finished.  Custom
        handshake drivers call this before :meth:`check`; the guarded
        connection and :func:`handshake_in_memory` do it automatically.

    .. py:method:: wrap(connection, is_server)

        Return a :class:`GuardedConnection` enforcing this policy on every
        application operation.


.. py:class:: GuardedConnection

    A proxy returned by :meth:`ALPNPolicy.wrap`.  Each application entry point
    (:meth:`do_handshake`, :meth:`send`, :meth:`sendall`, :meth:`recv`,
    :meth:`recv_into`) runs the policy gate first and raises
    :class:`ALPNError` if no allowed protocol was negotiated.  The BIO
    plumbing methods (``bio_read`` / ``bio_write``) and all other attributes
    are delegated to the wrapped :class:`~OpenSSL.SSL.Connection`, so memory-BIO
    handshake pumps keep working even when the policy ultimately rejects the
    connection.

    .. py:method:: require_negotiated_protocol()

        Return the negotiated protocol or raise :class:`ALPNError`.

    .. py:attribute:: connection

        The wrapped, unguarded :class:`~OpenSSL.SSL.Connection`.


.. py:exception:: ALPNError

    Raised when a mandatory policy is not satisfied.  This is deliberately
    **not** a subclass of :class:`OpenSSL.SSL.Error`, so callers can
    distinguish an ALPN negotiation-policy rejection from an ordinary TLS
    failure such as certificate verification.

    .. py:attribute:: reason

        An :class:`ALPNRejectReason` member explaining the rejection.

    .. py:attribute:: negotiated

        The protocol that was actually negotiated, or ``b""``.

    .. py:attribute:: allowed

        The tuple of protocols the policy required.


.. py:class:: ALPNRejectReason

    :class:`enum.Enum` of negotiation-policy failure reasons.  Certificate
    verification failures are :class:`OpenSSL.SSL.Error` and never carry one
    of these values.

    .. py:attribute:: MISSING_EXTENSION

        The peer did not send an ALPN extension.

    .. py:attribute:: NO_COMMON_PROTOCOL

        Both sides offered ALPN but had no protocol in common.

    .. py:attribute:: PROTOCOL_NOT_ALLOWED

        A protocol was selected that is not on the allow list.

    .. py:attribute:: NOT_HANDSHAKED

        The result was checked before any handshake completed.


.. py:function:: memory_bio_pair(client_context, server_context)

    Create a client/server :class:`~OpenSSL.SSL.Connection` pair wired
    together with paired in-memory BIOs (``socket=None``), placed in
    connect/accept state.


.. py:function:: pump_in_memory(client, server)

    Drive the two memory-BIO connections' handshakes to completion, moving TLS
    records between them without ever delivering application data.  Raises
    :class:`OpenSSL.SSL.Error` if a side aborts the handshake (for example a
    fatal "no application protocol" alert).


.. py:function:: handshake_in_memory(client, server)

    Complete a handshake over paired memory BIOs for two
    :class:`GuardedConnection` objects and enforce the policy on both ends.
    Raises :class:`OpenSSL.SSL.Error` for an ordinary TLS failure or
    :class:`ALPNError` when the handshake finished without an allowed
    protocol.
