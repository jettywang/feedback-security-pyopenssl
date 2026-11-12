DTLS MTU security regression
============================

These assets verify that pyOpenSSL's DTLS MTU interface
(``Connection.set_ciphertext_mtu`` / ``Connection.get_cleartext_mtu``) gives the
application a real datagram size contract and that the backend never treats a
DTLS connection as an arbitrary TLS byte stream that can be split or
truncated.

Everything runs over *memory BIOs* with a certificate generated in memory, so
no UDP socket, port, disk file or network is required.

What is measured
----------------

For every supported cipher suite three sizes are cross-checked:

1. the configured **ciphertext MTU** (the UDP payload budget passed to
   ``set_ciphertext_mtu``);
2. the **cleartext MTU** returned by the library *after* the handshake via
   ``get_cleartext_mtu`` (``DTLS_get_data_mtu``) -- the largest application
   write that still fits the configured path;
3. the **actual on-wire datagram length** observed in the memory BIO.

The cleartext budget is always taken from the library return value. It changes
with the negotiated cipher suite (GCM, ChaCha20-Poly1305 and CBC have different
record overhead), which is why subtracting a hardcoded "fixed header" from the
ciphertext MTU cannot be correct and is deliberately not done anywhere.

Security properties asserted
----------------------------

* **Datagram boundary preserved.** Every accepted ``write`` produces exactly
  one datagram, and the peer reassembles the identical bytes. Records are
  never silently merged or split.
* **Exactly at the limit.** A write sized to the library-reported cleartext
  MTU yields one datagram no larger than the configured ciphertext MTU.
* **One byte over the path MTU.** Still a single, whole datagram that exceeds
  the path budget -- it is neither fragmented nor truncated. The application is
  expected to gate sends on ``get_cleartext_mtu`` or use the explicit
  fragmentation layer shown in the matrix.
* **Past the DTLS record plaintext cap (2**14).** ``write`` and ``sendall``
  raise ``OpenSSL.SSL.Error`` ("dtls message too big") and emit no datagram,
  so an oversized message can never be silently shortened into a record the
  receiver mistakes for a complete secure message.
* **Runtime reconfiguration.** Lowering or raising the ciphertext MTU on a
  live connection updates the library-reported cleartext MTU immediately.
* **Stale cached value.** Reusing a cleartext length cached from before a
  shrink still produces one whole (now path-oversized) datagram; the backend
  does not chop it into path-sized pieces.
* **Explicit application fragmentation.** A message larger than one record can
  be sent safely with an explicit framing protocol whose fragment size is
  derived from the library cleartext MTU; every datagram stays within the path
  budget and the receiver reassembles the exact message.

Capability gaps
---------------

If an OpenSSL build lacks a capability, the matrix and tests record the gap
instead of guessing:

* no ``DTLS_get_data_mtu`` (pre-1.1.1) -> ``get_cleartext_mtu`` raises
  ``NotImplementedError``;
* no DTLS 1.3 in the build -> the DTLS 1.3 matrix row is skipped with the
  negotiated version recorded.

Running
-------

Standalone, re-runnable matrix (human-readable table)::

    python examples/dtls/dtls_mtu_matrix.py

Machine-readable output and non-default MTUs::

    python examples/dtls/dtls_mtu_matrix.py --json
    python examples/dtls/dtls_mtu_matrix.py --mtu 900 --reduced-mtu 400

Pytest regression (part of the normal test suite)::

    python -m pytest tests/test_ssl.py::TestDTLSMTU -v
