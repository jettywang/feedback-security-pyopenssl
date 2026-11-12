Certificate chain verification diagnostics (pyOpenSSL)
=======================================================

This example distinguishes two things that secure-communication diagnostics
must never conflate:

1. **The peer message** — the certificates the remote side actually sends,
   kept in wire order with duplicates and any embedded self-signed root
   preserved. Nothing in this message is ever treated as a trust anchor.
2. **The locally adopted chain** — the chain the local
   ``OpenSSL.X509Store`` actually validates, taken exclusively from
   ``X509StoreContext.get_verified_chain()``. Alternative cross-signed
   branches that were not adopted are reported separately and can never be
   presented as the final chain.

The verdict is strictly binary: ``trusted`` or ``untrusted``. A failed
verification keeps full diagnostics (OpenSSL error code, depth, failing
certificate, topology hints) but never emits a "partially trusted" state and
never carries an adopted chain.

Files
-----

``pki_factory.py``
    Builds, fully offline, a PKI with two independent self-signed roots and
    a cross-signed intermediate. The intermediate exists as two distinct
    certificates that share one subject name and one public key (Kx): one is
    signed by Root A, the other by Root B. An untrusted "rogue" root and an
    expired leaf are generated for the negative cases.

``chain_diagnostic.py``
    Peer-message analysis, explicit trust-store construction, pyOpenSSL
    verification, and the structured ``VerificationReport`` model.

``run_scenarios.py``
    Runs eleven scenarios with assertions against the real verification
    result and writes ``chain_verification_reports.json``.

``test_chain_verification.py``
    pytest coverage of the security invariants.

Run
---

::

    python examples/chain_verification_diagnostic/run_scenarios.py
    python -m pytest examples/chain_verification_diagnostic/ -q

Topology
--------

::

    Root A (self-signed)          Root B (self-signed)
        |                             |
        | signs                       | cross-signs the SAME
        v                             v intermediate name + key Kx
    Intermediate X (by A)         Intermediate X (by B)
                    \\               /
                     \\             /
                      v           v
                       leaf (example.test)

One input, two trust stores, two paths
--------------------------------------

Scenarios 4 and 5 feed the *identical* wire message
``[leaf, Intermediate X (by A), Intermediate X (by B)]`` to two different
trust stores:

* store A trusts only Root A → the validated chain is
  ``leaf -> Intermediate X (by A, from peer) -> Root A (anchor)``.
* store B ships the Root B cross-certificate plus Root B (the realistic case
  for trust stores that distribute cross-signed intermediates). OpenSSL's
  trusted-first selection ignores the peer ordering and validates
  ``leaf -> Intermediate X (by B, from store) -> Root B (anchor)``.

Both paths are backed by an actual successful
``X509StoreContext.get_verified_chain()`` result, and each report lists the
other cross-certificate under ``alternative_branches_not_adopted``.

Trust boundary rules that are asserted
--------------------------------------

* A self-signed root sent by the peer with no matching local anchor fails
  with ``X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN``; it never becomes an anchor.
* ``PARTIAL_CHAIN`` is left off, so peer-supplied roots cannot shortcut
  validation.
* Missing intermediate → ``X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY``
  with the diagnostic depth OpenSSL reports; no chain is marked trusted.
* A root-only trust store that cannot locally resolve a cross branch fails
  rather than back-tracking into an untrusted alternative — diagnostic only.
* Expired leaf → ``X509_V_ERR_CERT_HAS_EXPIRED`` at depth 0.
* Duplicate and shuffled peer certificates are tolerated by the verifier but
  still recorded in the peer-message section of the report.
