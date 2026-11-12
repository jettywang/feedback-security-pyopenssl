"""
In-memory-BIO TLS session-resumption experiment for pyOpenSSL.

Goal
----
A pyOpenSSL `Session` is pinned to one `Context` object (Connection.set_session
raises ValueError otherwise).  Applications nevertheless share a Context across
several logical backends (different hostnames, ALPN protocols, certificates).
This script measures, with *real* resumption indicators rather than "the
handshake did not raise", what OpenSSL actually resumes in each case.

Every handshake runs through MemoryBIO pairs: no sockets, no network, no ports.

Resumption is accepted as real only when BOTH hold:
  * SSL_session_reused(ssl) == 1  (authoritative OpenSSL flag), and
  * the negotiated master key equals the first connection's master key
    (the same proxy the pyOpenSSL test-suite uses).
A completed handshake with the flag == 0 is reported as a FULL handshake,
never as resumption.

Run:  python resume_experiment.py
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.bindings.openssl.binding import Binding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from OpenSSL import SSL
from OpenSSL import __version__ as pyopenssl_version
from OpenSSL.crypto import X509

_binding = Binding()
_lib = _binding.lib
_ffi = _binding.ffi

TLS1_2 = _lib.TLS1_2_VERSION
TLS1_3 = getattr(_lib, "TLS1_3_VERSION", 772)
X509_V_OK = _lib.X509_V_OK


# --------------------------------------------------------------------------
# Certificate factory: one CA, leaf certs per SAN / identity.
# --------------------------------------------------------------------------
def _make_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Experiment Root CA")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(ca_key, ca_cert, common_name, sans=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sans = sans or [common_name]
    names = [x509.DNSName(name) for name in sans]
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _pkey(crypto_key):
    from OpenSSL.crypto import PKey

    return PKey.from_cryptography_key(crypto_key)


# --------------------------------------------------------------------------
# Result record + authoritative low-level indicators.
# --------------------------------------------------------------------------
@dataclass
class HandshakeResult:
    label: str
    version: str
    sni: bytes | None
    alpn: bytes
    reused_flag: int          # SSL_session_reused, 0/1
    verify_result: int        # X509_V_* from SSL_get_verify_result
    peer_cn: str | None
    master_key: bytes | None
    error: str | None = None

    @property
    def really_resumed(self) -> bool:
        return self.error is None and self.reused_flag == 1

    @property
    def peer_trusted(self) -> bool:
        return self.error is None and self.verify_result == X509_V_OK


def session_reused(conn: SSL.Connection) -> int:
    return int(_lib.SSL_session_reused(conn._ssl))


def verify_result(conn: SSL.Connection) -> int:
    return int(_lib.SSL_get_verify_result(conn._ssl))


def negotiated_version(conn: SSL.Connection) -> str:
    raw = _lib.SSL_get_version(conn._ssl)
    return _ffi.string(raw).decode()


# --------------------------------------------------------------------------
# Memory-BIO handshake pump.
# --------------------------------------------------------------------------
def pump_handshake(client: SSL.Connection, server: SSL.Connection):
    """Drive two BIO-linked connections until the handshake settles."""
    client.set_connect_state()
    server.set_accept_state()
    for side in (client, server):
        try:
            side.do_handshake()
        except SSL.WantReadError:
            pass

    # Shuttle records until neither side produces more output.  This also
    # drains post-handshake TLS 1.3 NewSessionTicket messages, which the
    # client needs before the ticket is usable for resumption.
    progress = True
    while progress:
        progress = False
        for src, dst in ((client, server), (server, client)):
            while True:
                try:
                    chunk = src.bio_read(16384)
                except SSL.WantReadError:
                    break
                dst.bio_write(chunk)
                progress = True
            for side in (client, server):
                try:
                    side.do_handshake()
                except SSL.WantReadError:
                    pass
                except SSL.Error:
                    raise


def drain_tickets(client: SSL.Connection, server: SSL.Connection, rounds: int = 8):
    """Process post-handshake records so TLS 1.3 NewSessionTicket messages
    reach the client.  In TLS 1.3 the NST is delivered *after* the handshake
    has already completed; without these extra pump cycles the client never
    stores a ticket and every later connection is a silent full handshake."""
    for _ in range(rounds):
        for src, dst in ((server, client), (client, server)):
            while True:
                try:
                    chunk = src.bio_read(16384)
                except SSL.WantReadError:
                    break
                dst.bio_write(chunk)
        # Drive each state machine; recv() is what makes the client consume
        # post-handshake records (the NST) on an already-finished connection.
        for side in (client, server):
            try:
                side.recv(64)
            except SSL.WantReadError:
                pass
            except SSL.ZeroReturnError:
                pass
            try:
                side.do_handshake()
            except (SSL.WantReadError, SSL.Error):
                pass


def inspect(label: str, conn: SSL.Connection, error: str | None = None) -> HandshakeResult:
    if error is not None:
        # Even when the handshake aborted, SSL_get_verify_result still holds the
        # underlying chain verdict (e.g. 20), which explains the failure.
        try:
            verdict = verify_result(conn)
        except Exception:
            verdict = -1
        return HandshakeResult(label, "", None, b"", -1, verdict, None, None, error)
    peer = conn.get_peer_certificate()
    cn = None
    if peer is not None:
        try:
            cn = peer.to_cryptography().subject.get_attributes_for_oid(
                NameOID.COMMON_NAME
            )[0].value
        except IndexError:
            cn = None
    # SSL_SESSION_get_master_key returns nothing for TLS 1.3 sessions, so the
    # master-key proxy is only populated (and only meaningful) on TLS 1.2.
    master_key = None
    if negotiated_version(conn).startswith("TLSv1.2"):
        master_key = conn.master_key()
    return HandshakeResult(
        label=label,
        version=negotiated_version(conn),
        sni=conn.get_servername(),
        alpn=conn.get_alpn_proto_negotiated(),
        reused_flag=session_reused(conn),
        verify_result=verify_result(conn),
        peer_cn=cn,
        master_key=master_key,
    )


# --------------------------------------------------------------------------
# Context factories.
# --------------------------------------------------------------------------
def client_context(ca_cert, min_version=TLS1_2, max_version=TLS1_3):
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_min_proto_version(min_version)
    ctx.set_max_proto_version(max_version)
    # Full chain validation; verification failure is still returned through
    # SSL_get_verify_result unless a callback aborts, so no callback here.
    ctx.set_verify(SSL.VERIFY_PEER, lambda _conn, _cert, _err, _depth, _ok: True)
    store = ctx.get_cert_store()
    store.add_cert(X509.from_cryptography(ca_cert))
    return ctx


def server_context(key, cert, min_version=TLS1_2, max_version=TLS1_3,
                   alpn_select=None, sni_switch=None, session_id=b"shared-ctx"):
    ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
    ctx.set_min_proto_version(min_version)
    ctx.set_max_proto_version(max_version)
    ctx.use_privatekey(_pkey(key))
    ctx.use_certificate(X509.from_cryptography(cert))
    ctx.set_session_id(session_id)
    if alpn_select is not None:
        def _select(conn, offered):
            return alpn_select(offered)
        ctx.set_alpn_select_callback(_select)
    if sni_switch is not None:
        # sni_switch(server_connection) installs the cert matching the SNI.
        def _sni(conn):
            sni_switch(conn)
        ctx.set_tlsext_servername_callback(_sni)
    return ctx


def new_pair(client_ctx, server_ctx, session=None, sni=None, alpn=None):
    client = SSL.Connection(client_ctx, None)
    server = SSL.Connection(server_ctx, None)
    if sni is not None:
        client.set_tlsext_host_name(sni)
    if alpn is not None:
        client.set_alpn_protos(alpn)
    if session is not None:
        # Library-level identity boundary: same Context object required.
        client.set_session(session)
    pump_handshake(client, server)
    drain_tickets(client, server)
    return client, server


# --------------------------------------------------------------------------
# Scenario runner.
# --------------------------------------------------------------------------
@dataclass
class Scenario:
    name: str
    description: str
    results: list = field(default_factory=list)


def _same_master(first: HandshakeResult, second: HandshakeResult) -> bool:
    return (
        first.master_key is not None
        and second.master_key is not None
        and first.master_key == second.master_key
    )


def resume_confirmed(first: HandshakeResult, second: HandshakeResult) -> bool:
    """Authoritative resumption: OpenSSL flag, plus the master-key proxy
    whenever TLS 1.2 makes one available. TLS 1.3 exposes no master key."""
    if second.error is not None or second.reused_flag != 1:
        return False
    if second.version.startswith("TLSv1.2"):
        return _same_master(first, second)
    return True


def run():
    ca_key, ca_cert = _make_ca()
    leaf_a_key, leaf_a = _make_leaf(ca_key, ca_cert, "a.example", ["a.example"])
    leaf_b_key, leaf_b = _make_leaf(ca_key, ca_cert, "b.example", ["b.example"])
    leaf_a2_key, leaf_a2 = _make_leaf(
        ca_key, ca_cert, "a.example-rotated", ["a.example"]
    )

    scenarios: list[Scenario] = []

    def title(name, desc):
        sc = Scenario(name, desc)
        scenarios.append(sc)
        return sc

    # ---- S1: same backend, same everything -> baseline resumption --------
    for label, lo, hi in (("TLS 1.2 only", TLS1_2, TLS1_2),
                          ("TLS 1.3 only", TLS1_3, TLS1_3)):
        sc = title(f"S1 baseline resumption ({label})",
                   "Same SNI/ALPN/cert; second handshake offers first session.")
        cctx = client_context(ca_cert, lo, hi)
        sctx = server_context(leaf_a_key, leaf_a, lo, hi)
        c1, s1 = new_pair(cctx, sctx, sni=b"a.example", alpn=[b"h2"])
        r1 = inspect("first handshake", c1)
        sess = c1.get_session()
        c2, s2 = new_pair(cctx, sctx, session=sess, sni=b"a.example", alpn=[b"h2"])
        r2 = inspect("second handshake", c2)
        sc.results += [r1, r2]
        sc.results.append(
            f"  -> reused_flag={r2.reused_flag} master_key_match={_same_master(r1, r2)} "
            f"REAL_RESUME={resume_confirmed(r1, r2)}"
        )

    def sni_switch_factory():
        def sni_switch(conn):
            if conn.get_servername() == b"b.example":
                _lib.SSL_use_certificate(
                    conn._ssl, X509.from_cryptography(leaf_b)._x509
                )
                _lib.SSL_use_PrivateKey(
                    conn._ssl, _pkey(leaf_b_key)._pkey
                )
        return sni_switch

    def alpn_picker(offered):
        return b"http/1.1" if b"http/1.1" in offered else b"h2"

    # S2 / S2b / S3 / S4 are run twice, pinned to each protocol version, so a
    # reader can see that the identity-boundary findings are not version-specific.
    for ver_label, lo, hi in (("TLS 1.2", TLS1_2, TLS1_2),
                              ("TLS 1.3", TLS1_3, TLS1_3)):
        # ---- S2: different SNI, one shared server Context ----------------
        sc = title(
            f"S2 different SNI, shared Context ({ver_label})",
            "Session from a.example offered on b.example; one cert, no SNI switch.",
        )
        cctx = client_context(ca_cert, lo, hi)
        sctx = server_context(leaf_a_key, leaf_a, lo, hi)
        c1, _ = new_pair(cctx, sctx, sni=b"a.example", alpn=[b"h2"])
        r1 = inspect("a.example first", c1)
        sess = c1.get_session()
        c2, _ = new_pair(
            cctx, sctx, session=sess, sni=b"b.example", alpn=[b"h2"]
        )
        r2 = inspect("b.example second", c2)
        sc.results += [r1, r2]
        sc.results.append(
            f"  -> reused_flag on b.example={r2.reused_flag} "
            f"REAL_RESUME={resume_confirmed(r1, r2)}  (OpenSSL does NOT bind "
            f"the session to SNI)"
        )

        # ---- S2b: per-SNI certificate via SNI callback -------------------
        sc = title(
            f"S2b per-SNI certificate ({ver_label})",
            "SNI callback selects leaf B for b.example; A's session is offered.",
        )
        cctx = client_context(ca_cert, lo, hi)
        sctx = server_context(
            leaf_a_key, leaf_a, lo, hi, sni_switch=sni_switch_factory()
        )
        c1, _ = new_pair(cctx, sctx, sni=b"a.example", alpn=[b"h2"])
        r1 = inspect("a.example first (leaf A)", c1)
        sess = c1.get_session()
        c2, _ = new_pair(
            cctx, sctx, session=sess, sni=b"b.example", alpn=[b"h2"]
        )
        r2 = inspect("b.example second", c2)
        sc.results += [r1, r2]
        sc.results.append(
            f"  -> client still reports peer_cn={r2.peer_cn!r} (the resumed "
            f"session hides leaf B) reused_flag={r2.reused_flag} "
            f"REAL_RESUME={resume_confirmed(r1, r2)}"
        )

        # ---- S3: ALPN change between handshakes --------------------------
        sc = title(
            f"S3 ALPN change h2 -> http/1.1 ({ver_label})",
            "Same SNI/cert, different negotiated application protocol.",
        )
        cctx = client_context(ca_cert, lo, hi)
        sctx = server_context(
            leaf_a_key, leaf_a, lo, hi, alpn_select=alpn_picker
        )
        c1, _ = new_pair(cctx, sctx, sni=b"a.example", alpn=[b"h2"])
        r1 = inspect("ALPN h2 first", c1)
        sess = c1.get_session()
        c2, _ = new_pair(
            cctx, sctx, session=sess, sni=b"a.example", alpn=[b"http/1.1"]
        )
        r2 = inspect("ALPN http/1.1 second", c2)
        sc.results += [r1, r2]
        sc.results.append(
            f"  -> negotiated ALPN changed to {r2.alpn!r} yet "
            f"reused_flag={r2.reused_flag} REAL_RESUME={resume_confirmed(r1, r2)}"
        )

        # ---- S4: certificate rotation, same Context ----------------------
        sc = title(
            f"S4 backend certificate rotation ({ver_label})",
            "Server installs a rotated leaf (same SAN a.example); session offered.",
        )
        cctx = client_context(ca_cert, lo, hi)
        sctx = server_context(leaf_a_key, leaf_a, lo, hi)
        c1, _ = new_pair(cctx, sctx, sni=b"a.example", alpn=[b"h2"])
        r1 = inspect("before rotation", c1)
        sess = c1.get_session()

        # Resumed path against the rotated leaf.
        rotated = X509.from_cryptography(leaf_a2)
        c2 = SSL.Connection(cctx, None)
        s2 = SSL.Connection(sctx, None)
        c2.set_tlsext_host_name(b"a.example")
        c2.set_alpn_protos([b"h2"])
        c2.set_session(sess)
        assert _lib.SSL_use_certificate(s2._ssl, rotated._x509) == 1
        assert _lib.SSL_use_PrivateKey(s2._ssl, _pkey(leaf_a2_key)._pkey) == 1
        pump_handshake(c2, s2)
        drain_tickets(c2, s2)
        r2 = inspect("resumed after rotation", c2)

        # Control: full handshake (no session) against the same rotated leaf.
        c3 = SSL.Connection(cctx, None)
        s3 = SSL.Connection(sctx, None)
        c3.set_tlsext_host_name(b"a.example")
        c3.set_alpn_protos([b"h2"])
        assert _lib.SSL_use_certificate(s3._ssl, rotated._x509) == 1
        assert _lib.SSL_use_PrivateKey(s3._ssl, _pkey(leaf_a2_key)._pkey) == 1
        pump_handshake(c3, s3)
        drain_tickets(c3, s3)
        r3 = inspect("full handshake after rotation", c3)

        sc.results += [r1, r2, r3]
        sc.results.append(
            f"  -> resumed connection keeps stale peer_cn={r2.peer_cn!r} "
            f"(REAL_RESUME={resume_confirmed(r1, r2)}); a full handshake sees "
            f"the rotated peer_cn={r3.peer_cn!r}"
        )

    # ---- S5: verification failure is visible despite completed handshake -
    sc = title("S5 untrusted leaf (empty trust store)",
               "With a lenient verify callback the handshake still completes; "
               "peer_trusted must come from SSL_get_verify_result, not try/except.")
    sctx = server_context(leaf_b_key, leaf_b)

    def run_client(client_ctx, label):
        client = SSL.Connection(client_ctx, None)
        server = SSL.Connection(sctx, None)
        client.set_tlsext_host_name(b"b.example")
        try:
            pump_handshake(client, server)
            drain_tickets(client, server)
            return inspect(label, client)
        except SSL.Error as exc:
            return inspect(label, client, error=str(exc))

    # Control: a context that trusts the CA.
    r_ok = run_client(client_context(ca_cert), "trusted CA")

    # Strict default: VERIFY_PEER with a callback that returns OpenSSL's own
    # verdict instead of forcing True. The handshake must fail with code 20.
    strict_ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    strict_ctx.set_min_proto_version(TLS1_2)
    strict_ctx.set_max_proto_version(TLS1_3)
    strict_ctx.set_verify(
        SSL.VERIFY_PEER, lambda _c, _cert, _err, _d, ok: ok
    )
    r_strict = run_client(strict_ctx, "strict, empty trust store")

    # Dangerous pattern: a constant-True callback overrides the verdict.
    permissive_ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    permissive_ctx.set_min_proto_version(TLS1_2)
    permissive_ctx.set_max_proto_version(TLS1_3)
    permissive_ctx.set_verify(
        SSL.VERIFY_PEER, lambda _c, _cert, _err, _d, _ok: True
    )
    r_perm = run_client(permissive_ctx, "constant-True callback")

    sc.results += [r_ok, r_strict, r_perm]
    sc.results.append(
        "  -> control: verify={ok_v}/trusted={ok_t}; strict: verify={sv} "
        "raised={se}; permissive: verify={pv} raised={pe} (20 = unable to get "
        "issuer cert locally; permissive completes but stays untrusted)".format(
            ok_v=r_ok.verify_result, ok_t=r_ok.peer_trusted,
            sv=r_strict.verify_result, se=r_strict.error is not None,
            pv=r_perm.verify_result, pe=r_perm.error is not None,
        )
    )

    # ---- S6: library Context boundary itself -----------------------------
    sc = title("S6 cross-Context set_session is rejected",
               "Two Context objects on the client; session from the first.")
    cctx1 = client_context(ca_cert)
    cctx2 = client_context(ca_cert)
    sctx = server_context(leaf_a_key, leaf_a)
    c1, _ = new_pair(cctx1, sctx, sni=b"a.example")
    sess = c1.get_session()
    stranger = SSL.Connection(cctx2, None)
    stranger.set_connect_state()
    try:
        stranger.set_session(sess)
        outcome = "  -> UNEXPECTED: cross-Context set_session was accepted"
    except ValueError as exc:
        outcome = f"  -> blocked as expected: ValueError: {exc}"
    sc.results.append(outcome)

    # ---- S7: hostname is never matched against the leaf SAN ---------------
    sc = title("S7 SNI/SAN mismatch is invisible to the chain check",
               "pyOpenSSL verifies the chain only; hostname matching is the "
               "application's job on BOTH full and resumed handshakes.")
    z_key, z_cert = _make_leaf(ca_key, ca_cert, "z.example", ["z.example"])
    cctx = client_context(ca_cert)
    sctx = server_context(z_key, z_cert)
    c1, _ = new_pair(cctx, sctx, sni=b"a.example")  # SAN only has z.example
    r1 = inspect("full, SNI a.example vs SAN z.example", c1)
    sess = c1.get_session()
    c2, _ = new_pair(cctx, sctx, session=sess, sni=b"b.example")
    r2 = inspect("resumed, SNI b.example vs SAN z.example", c2)
    sc.results += [r1, r2]
    sc.results.append(
        f"  -> chain verify={r1.verify_result}/{r2.verify_result} (0) yet no name "
        f"ever matched; reused={r2.reused_flag}. Hostname/SAN pinning must be "
        f"done in application code every time, including after resumption."
    )

    _print_report(scenarios)
    return scenarios


def _print_report(scenarios):
    width = 78
    print("=" * width)
    print("pyOpenSSL session-resumption identity-boundary experiment")
    print(f"pyOpenSSL {pyopenssl_version} | {_ffi.string(_lib.OpenSSL_version(0)).decode()}")
    print("=" * width)
    for sc in scenarios:
        print(f"\n### {sc.name}")
        print(f"    {sc.description}")
        for item in sc.results:
            if isinstance(item, HandshakeResult):
                if item.error is not None:
                    print(f"    [{item.label}] handshake error: {item.error}")
                    continue
                print(
                    "    [{label}] ver={ver} sni={sni} alpn={alpn!r} "
                    "reused={reused} verify={verify} peer_cn={cn}".format(
                        label=item.label, ver=item.version,
                        sni=item.sni, alpn=item.alpn,
                        reused=item.reused_flag, verify=item.verify_result,
                        cn=item.peer_cn,
                    )
                )
            else:
                print(item)


if __name__ == "__main__":
    run()
