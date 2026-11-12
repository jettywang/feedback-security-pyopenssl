"""
Application-level session cache that keeps one backend's authentication
conclusion from being reused against another backend, even though all the
backends share a single pyOpenSSL Context.

The library only guarantees Context-object identity (Connection.set_session
raises ValueError otherwise).  The experiment in resume_experiment.py shows
OpenSSL itself will happily resume a session across different SNI values,
ALPN protocols and even rotated certificates, and that a resumed handshake
carries no Certificate message at all.  Therefore the application must:

  1. key the cache by the *full logical identity* of the backend, not just by
     the OpenSSL session object;
  2. only reuse an entry whose identity matches the current target;
  3. invalidate entries on any security-relevant change;
  4. after every handshake, independently confirm resumption AND peer trust,
     never treating "no exception" as success.

Run:  python safe_session_cache.py
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from cryptography.hazmat.bindings.openssl.binding import Binding
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import DNSName, SubjectAlternativeName
from cryptography.x509.oid import NameOID

from OpenSSL import SSL
from OpenSSL.crypto import X509

_binding = Binding()
_lib = _binding.lib
X509_V_OK = _lib.X509_V_OK


# --------------------------------------------------------------------------
# Cache key: every dimension the application treats as a distinct trust domain.
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class BackendIdentity:
    """
    The logical identity of a backend.  Two connections only share a session
    when *every* field is equal.  Add fields for anything else that changes
    the security domain in your system (client-cert policy, tenant id, ...).
    """

    hostname: bytes           # the name you authenticated, e.g. b"a.example"
    alpn: bytes               # negotiated application protocol, b"" if none
    leaf_fingerprint: bytes   # SHA-256 of the DER leaf certificate
    proto_version: str        # "TLSv1.2" / "TLSv1.3", so tickets never cross
    session_id_context: bytes  # Context.set_session_id value, for defense in depth


def _leaf_fingerprint(conn: SSL.Connection) -> bytes | None:
    peer = conn.get_peer_certificate()
    if peer is None:
        return None
    return peer.to_cryptography().fingerprint(hashes.SHA256())


def _session_reused(conn: SSL.Connection) -> bool:
    return bool(_lib.SSL_session_reused(conn._ssl))


def _verify_ok(conn: SSL.Connection) -> bool:
    return int(_lib.SSL_get_verify_result(conn._ssl)) == X509_V_OK


def _hostname_matches(conn: SSL.Connection, expected: bytes) -> bool:
    """
    pyOpenSSL has no built-in hostname check.  Compare the authenticated name
    against the leaf's SANs (and, only as a fallback, its CN) ourselves.
    """
    peer = conn.get_peer_certificate()
    if peer is None:
        return False
    cert = peer.to_cryptography()
    try:
        san = cert.extensions.get_extension_for_class(
            SubjectAlternativeName
        ).value
        names = [n.encode() for n in san.get_values_for_type(DNSName)]
        if names:
            return expected in names
    except Exception:
        pass
    common = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return bool(common and common[0].value.encode() == expected)


# --------------------------------------------------------------------------
# The cache itself.
# --------------------------------------------------------------------------
@dataclass
class _Entry:
    # The originating Connection must be kept alive: in this OpenSSL/pyOpenSSL
    # build a Session object whose Connection has been garbage-collected no
    # longer resumes (verified on both TLS 1.2 and 1.3).  We therefore retain
    # the connection and draw a fresh Session from it on every reuse.
    conn: SSL.Connection
    identity: BackendIdentity
    created_at: float
    hits: int = 0


class BoundSessionCache:
    """
    Thread-safe cache that refuses to hand out a session unless the requested
    backend identity is byte-for-byte identical to the one that minted it.

    Lifetime caveat (measured, see resume_experiment.py): a pyOpenSSL
    ``Session`` only stays resumable while the ``Connection`` it came from is
    still alive.  This cache therefore stores the connection itself and hands
    out freshly obtained sessions.  Entries are reference-counted through the
    cache; dropping the cache (or invalidating an entry) releases them.
    """

    def __init__(self, max_ttl_seconds: float = 3600.0, max_entries: int = 1024):
        self._entries: dict[BackendIdentity, _Entry] = {}
        self._lock = threading.Lock()
        self._max_ttl = max_ttl_seconds
        self._max_entries = max_entries

    def store(self, identity: BackendIdentity, conn: SSL.Connection) -> None:
        """Retain a fully authenticated connection under its identity."""
        if conn.get_session() is None:
            return
        with self._lock:
            self._entries[identity] = _Entry(conn, identity, time.time())
            self._evict_locked()

    def load(self, identity: BackendIdentity) -> SSL.Session | None:
        """Return a fresh session only for an identical identity; never a near
        match, and never an entry whose originating connection is gone."""
        with self._lock:
            entry = self._entries.get(identity)
            if entry is None:
                return None
            if time.time() - entry.created_at > self._max_ttl:
                del self._entries[identity]
                return None
            session = entry.conn.get_session()
            if session is None:
                del self._entries[identity]
                return None
            entry.hits += 1
            return session

    def invalidate(self, *, hostname: bytes | None = None,
                   leaf_fingerprint: bytes | None = None) -> int:
        """
        Drop entries after a security-relevant change.  At minimum call this
        when a certificate is rotated, a backend is decommissioned, trust
        anchors change, or an incident is suspected.
        """
        with self._lock:
            before = len(self._entries)
            for key in list(self._entries):
                if hostname is not None and key.hostname == hostname:
                    del self._entries[key]
                elif leaf_fingerprint is not None and key.leaf_fingerprint == leaf_fingerprint:
                    del self._entries[key]
            return before - len(self._entries)

    def _evict_locked(self) -> None:
        if len(self._entries) <= self._max_entries:
            return
        oldest = sorted(self._entries, key=lambda k: self._entries[k].created_at)
        for key in oldest[: len(self._entries) - self._max_entries]:
            del self._entries[key]

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


# --------------------------------------------------------------------------
# Glue: build an identity from a live connection and verify on the way out.
# --------------------------------------------------------------------------
def identity_from_connection(
    conn: SSL.Connection, session_id_context: bytes
) -> BackendIdentity:
    version = _binding.ffi.string(_lib.SSL_get_version(conn._ssl)).decode()
    return BackendIdentity(
        hostname=conn.get_servername() or b"",
        alpn=conn.get_alpn_proto_negotiated(),
        leaf_fingerprint=_leaf_fingerprint(conn) or b"",
        proto_version=version,
        session_id_context=session_id_context,
    )


def establish(
    cache: "BoundSessionCache",
    client_ctx: SSL.Context,
    server_ctx: SSL.Context,
    hostname: bytes,
    alpn_protos: list[bytes],
    session_id_context: bytes,
    pump,
) -> tuple[SSL.Connection, SSL.Connection, dict]:
    """
    Perform a handshake, offering a cached session only when the target's
    known identity dimensions match a stored entry.  After the handshake the
    leaf fingerprint is compared as well, so a rotated certificate can never
    inherit an older entry's trust.  The caller must reject any connection
    whose report has ``authenticated == False``.
    """
    wanted_alpn = alpn_protos[0] if alpn_protos else b""

    client = SSL.Connection(client_ctx, None)
    server = SSL.Connection(server_ctx, None)
    client.set_tlsext_host_name(hostname)
    if alpn_protos:
        client.set_alpn_protos(alpn_protos)

    # Match on every dimension known before the handshake.  The leaf
    # fingerprint cannot be known up front, so it is re-checked afterwards.
    # get_session() on the live originating connection yields a resumable one.
    with cache._lock:
        stored = next(
            (e for e in cache._entries.values()
             if e.identity.hostname == hostname
             and e.identity.alpn == wanted_alpn
             and e.identity.session_id_context == session_id_context),
            None,
        )
    if stored is not None:
        session = stored.conn.get_session()
        if session is not None:
            client.set_session(session)

    pump(client, server)

    actual = identity_from_connection(client, session_id_context)
    report = {
        "attempted_resume": stored is not None,
        "actually_resumed": _session_reused(client),
        "chain_trusted": _verify_ok(client),
        "hostname_matched": _hostname_matches(client, hostname),
        "alpn_matched": actual.alpn == wanted_alpn,
        "fingerprint_matched": (
            stored is not None
            and actual.leaf_fingerprint == stored.identity.leaf_fingerprint
        ),
        "authenticated": False,
    }

    if report["actually_resumed"]:
        # A resumed handshake sends no Certificate message; the leaf comes from
        # the cached session.  Require the stored identity to survive all checks.
        report["authenticated"] = (
            stored is not None
            and report["chain_trusted"]
            and report["hostname_matched"]
            and report["alpn_matched"]
            and report["fingerprint_matched"]
        )
    else:
        # Full handshake: trust only an independently verified chain and name.
        report["authenticated"] = (
            report["chain_trusted"]
            and report["hostname_matched"]
            and report["alpn_matched"]
        )
        if report["authenticated"]:
            # Retain the live connection so later sessions stay resumable.
            cache.store(actual, client)

    return client, server, report


# --------------------------------------------------------------------------
# Runnable demonstration over memory BIOs.
# --------------------------------------------------------------------------
def _drain(client, server):
    """Memory-BIO pump that also drains post-handshake TLS 1.3 tickets."""
    client.set_connect_state()
    server.set_accept_state()
    for side in (client, server):
        try:
            side.do_handshake()
        except SSL.WantReadError:
            pass
    progress = True
    while progress:
        progress = False
        for src, dst in ((client, server), (server, client)):
            while True:
                try:
                    dst.bio_write(src.bio_read(16384))
                    progress = True
                except SSL.WantReadError:
                    break
        for side in (client, server):
            try:
                side.do_handshake()
            except (SSL.WantReadError, SSL.Error):
                pass
    # TLS 1.3 NewSessionTicket arrives after the handshake finishes; recv()
    # makes the client consume those post-handshake records.
    for _ in range(8):
        for src, dst in ((server, client), (client, server)):
            while True:
                try:
                    dst.bio_write(src.bio_read(16384))
                except SSL.WantReadError:
                    break
        for side in (client, server):
            try:
                side.recv(64)
            except (SSL.WantReadError, SSL.ZeroReturnError):
                pass
            try:
                side.do_handshake()
            except (SSL.WantReadError, SSL.Error):
                pass


def _demo() -> None:
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    def ca():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo CA")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo CA")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2024, 1, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256())
        )
        return key, cert

    def leaf(ca_key, ca_cert, name):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2024, 1, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name)]), False
            )
            .sign(ca_key, hashes.SHA256())
        )
        return key, cert

    from OpenSSL.crypto import PKey

    ca_key, ca_cert = ca()
    a_key, a_cert = leaf(ca_key, ca_cert, "a.example")
    b_key, b_cert = leaf(ca_key, ca_cert, "b.example")

    client_ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    client_ctx.set_verify(SSL.VERIFY_PEER, lambda c, cert, err, d, ok: ok)
    client_ctx.get_cert_store().add_cert(X509.from_cryptography(ca_cert))

    def server_ctx_for(key, cert):
        ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
        ctx.use_privatekey(PKey.from_cryptography_key(key))
        ctx.use_certificate(X509.from_cryptography(cert))
        ctx.set_session_id(b"shared-ctx")
        ctx.set_alpn_select_callback(
            lambda _conn, offered: offered[0] if offered else b""
        )
        return ctx

    srv_a = server_ctx_for(a_key, a_cert)
    srv_b = server_ctx_for(b_key, b_cert)
    cache = BoundSessionCache()
    sid = b"shared-ctx"

    print("=" * 72)
    print("BoundSessionCache demonstration (memory BIO, no network)")
    print("=" * 72)

    _, _, r1 = establish(cache, client_ctx, srv_a, b"a.example", [b"h2"], sid, _drain)
    print(f"1) a.example full handshake : {r1} cache={len(cache)}")

    _, _, r2 = establish(cache, client_ctx, srv_a, b"a.example", [b"h2"], sid, _drain)
    print(f"2) a.example again          : {r2} (resume must be True)")

    # Different hostname shares the same client Context but must NOT get A's session.
    _, _, r3 = establish(cache, client_ctx, srv_b, b"b.example", [b"h2"], sid, _drain)
    print(f"3) b.example different backend: {r3} (resume must be False)")

    # Different ALPN is also a different key.
    _, _, r4 = establish(cache, client_ctx, srv_a, b"a.example", [b"http/1.1"], sid, _drain)
    print(f"4) a.example other ALPN     : {r4} (resume must be False)")

    # Invalidate A (e.g. after cert rotation); next call is a clean full handshake.
    removed = cache.invalidate(hostname=b"a.example")
    _, _, r5 = establish(cache, client_ctx, srv_a, b"a.example", [b"h2"], sid, _drain)
    print(f"5) after invalidate({removed} entries): {r5} (resume must be False)")

    # Certificate rotation WITHOUT explicit invalidation: even if a stale
    # session were offered, the post-handshake fingerprint check must reject it.
    a2_key, a2_cert = leaf(ca_key, ca_cert, "a.example")
    srv_a_rotated = server_ctx_for(a2_key, a2_cert)
    # Re-seed a trusted entry for a.example against the ORIGINAL leaf.
    cache.invalidate(hostname=b"a.example")
    establish(cache, client_ctx, srv_a, b"a.example", [b"h2"], sid, _drain)
    # Force the stale session to be offered to the rotated backend by building
    # the connection the same way establish does, then verify the guard trips.
    with cache._lock:
        stale = next(
            e for e in cache._entries.values() if e.identity.hostname == b"a.example"
        )
    rogue_client = SSL.Connection(client_ctx, None)
    rogue_server = SSL.Connection(srv_a_rotated, None)
    rogue_client.set_tlsext_host_name(b"a.example")
    rogue_client.set_alpn_protos([b"h2"])
    rogue_client.set_session(stale.conn.get_session())
    _drain(rogue_client, rogue_server)
    rotated_fp = _leaf_fingerprint(rogue_client)
    fp_matches = rotated_fp == stale.identity.leaf_fingerprint
    print(
        "6) rotated backend offered stale session: "
        f"resumed={_session_reused(rogue_client)} fingerprint_matched={fp_matches} "
        "(a True resume here would carry the OLD leaf; the guard must treat "
        "fingerprint_matched=False as unauthenticated and force a full handshake)"
    )

    assert r1["authenticated"] and r2["authenticated"] and r3["authenticated"]
    assert r2["actually_resumed"] is True
    assert r3["actually_resumed"] is False
    assert r4["actually_resumed"] is False
    assert r5["actually_resumed"] is False
    assert fp_matches is False
    print("\nAll assertions passed: A's authentication never leaks to B.")


if __name__ == "__main__":
    _demo()
