# Copyright (c) The pyOpenSSL developers
# See LICENSE for details.

"""
Security regression tests for mutual TLS (mTLS).

These tests perform *real* handshakes over memory BIOs -- they never
assert on configuration bits alone -- to pin down how three layers
combine to decide whether a client certificate is accepted:

1. ``Context.set_verify`` -- the baseline verification policy
   (``VERIFY_PEER``, ``VERIFY_FAIL_IF_NO_PEER_CERT``, ...).
2. ``Connection.set_verify`` -- a per-connection override of the
   context policy, in either direction (weaker or stronger).
3. The verify callback -- invoked for every certificate in the chain.
   Returning ``True`` *overrides* the underlying verification error;
   returning ``False`` rejects even a perfectly valid chain.

They also keep "the certificate chain is trusted" and "the peer
identity is authorized by the application" as two separate decisions:
a cryptographically successful handshake must still not result in
application plaintext being delivered to an unauthorized peer, and a
failed handshake must never deliver plaintext at all.
"""

from __future__ import annotations

import datetime
import typing

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from OpenSSL import SSL
from OpenSSL.crypto import X509
from OpenSSL.SSL import (
    TLS1_2_VERSION,
    TLS_METHOD,
    VERIFY_CLIENT_ONCE,
    VERIFY_FAIL_IF_NO_PEER_CERT,
    VERIFY_NONE,
    VERIFY_PEER,
    Connection,
    Context,
    WantReadError,
)

#: The verify mode a strict mTLS server must use: request a client
#: certificate, require it to be present, and verify its chain.
STRICT_SERVER_VERIFY = (
    VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT | VERIFY_CLIENT_ONCE
)

#: Application-layer identities the toy server is willing to talk to.
#: Deliberately distinct from "any certificate signed by our CA".
ALLOWED_CLIENT_CNS = frozenset({"authorized-client"})

SECRET = b"application-layer secret"


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _issue_cert(
    *,
    common_name: str,
    issuer_name: x509.Name,
    issuer_key: rsa.RSAPrivateKey,
    subject_key: rsa.RSAPrivateKey,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    ca: bool,
) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=True
        )
        .serial_number(x509.random_serial_number())
        .sign(issuer_key, hashes.SHA256())
    )


class PKI(typing.NamedTuple):
    """
    A tiny local PKI: one trusted CA, one untrusted ("rogue") CA, a
    server certificate, and a collection of client credentials covering
    valid, expired, untrusted, trusted-but-unauthorized, and missing
    certificates.
    """

    ca_cert: x509.Certificate
    server_cert: x509.Certificate
    server_key: rsa.RSAPrivateKey
    clients: dict[str, tuple[x509.Certificate, rsa.RSAPrivateKey] | None]


@pytest.fixture(scope="module")
def pki() -> PKI:
    now = datetime.datetime.now()
    valid_from = now - datetime.timedelta(days=1)
    valid_until = now + datetime.timedelta(days=30)

    ca_key = _new_key()
    ca_cert = _issue_cert(
        common_name="Test Root CA",
        issuer_name=_name("Test Root CA"),
        issuer_key=ca_key,
        subject_key=ca_key,
        not_before=valid_from,
        not_after=valid_until,
        ca=True,
    )

    rogue_key = _new_key()
    rogue_cert = _issue_cert(
        common_name="Rogue CA",
        issuer_name=_name("Rogue CA"),
        issuer_key=rogue_key,
        subject_key=rogue_key,
        not_before=valid_from,
        not_after=valid_until,
        ca=True,
    )

    server_key = _new_key()
    server_cert = _issue_cert(
        common_name="server-under-test",
        issuer_name=ca_cert.subject,
        issuer_key=ca_key,
        subject_key=server_key,
        not_before=valid_from,
        not_after=valid_until,
        ca=False,
    )

    def client_cert(
        common_name: str,
        issuer: x509.Certificate,
        issuer_key: rsa.RSAPrivateKey,
        not_before: datetime.datetime = valid_from,
        not_after: datetime.datetime = valid_until,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        key = _new_key()
        cert = _issue_cert(
            common_name=common_name,
            issuer_name=issuer.subject,
            issuer_key=issuer_key,
            subject_key=key,
            not_before=not_before,
            not_after=not_after,
            ca=False,
        )
        return (cert, key)

    clients: dict[str, tuple[x509.Certificate, rsa.RSAPrivateKey] | None] = {
        # Valid chain, and the CN the application authorizes.
        "valid": client_cert("authorized-client", ca_cert, ca_key),
        # Valid chain, but a CN the application must NOT authorize.
        "trusted-but-unauthorized": client_cert(
            "rogue-employee", ca_cert, ca_key
        ),
        # Right CA, but the certificate has already expired.
        "expired": client_cert(
            "expired-client",
            ca_cert,
            ca_key,
            not_before=now - datetime.timedelta(days=30),
            not_after=now - datetime.timedelta(days=1),
        ),
        # Perfectly valid certificate, but signed by an unknown CA.
        "untrusted": client_cert("untrusted-client", rogue_cert, rogue_key),
        # No client certificate at all.
        "none": None,
    }

    return PKI(
        ca_cert=ca_cert,
        server_cert=server_cert,
        server_key=server_key,
        clients=clients,
    )


def _honest_verify_cb(
    conn: Connection, cert: X509, errnum: int, depth: int, ok: int
) -> bool:
    """
    A verify callback that propagates the underlying result instead of
    masking it.
    """
    return bool(ok)


def strict_mtls_server_context(
    pki: PKI,
    verify_callback: typing.Callable[
        [Connection, X509, int, int, int], bool
    ] = _honest_verify_cb,
) -> Context:
    """
    Reference strict-mTLS server configuration.

    - trusts exactly one CA (the local test CA);
    - ``VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT`` makes a *valid*
      client certificate mandatory -- ``VERIFY_PEER`` alone still
      admits clients that present no certificate;
    - the default verify callback honestly propagates the underlying
      verification result instead of returning ``True`` blindly;
    - TLS 1.2 or newer only.

    Note that this only establishes *chain trust*.  Whether the
    authenticated identity is allowed to use the application is a
    separate decision (see ``_is_authorized``).
    """
    ctx = Context(TLS_METHOD)
    ctx.set_min_proto_version(TLS1_2_VERSION)
    ctx.use_certificate(pki.server_cert)
    ctx.use_privatekey(pki.server_key)
    store = ctx.get_cert_store()
    assert store is not None
    store.add_cert(X509.from_cryptography(pki.ca_cert))
    ctx.set_verify(STRICT_SERVER_VERIFY, verify_callback)
    return ctx


def _server_context(
    pki: PKI,
    verify_mode: int,
    verify_callback: typing.Callable[
        [Connection, X509, int, int, int], bool
    ] = _honest_verify_cb,
) -> Context:
    ctx = Context(TLS_METHOD)
    ctx.set_min_proto_version(TLS1_2_VERSION)
    ctx.use_certificate(pki.server_cert)
    ctx.use_privatekey(pki.server_key)
    store = ctx.get_cert_store()
    assert store is not None
    store.add_cert(X509.from_cryptography(pki.ca_cert))
    ctx.set_verify(verify_mode, verify_callback)
    return ctx


def _server_connection(ctx: Context) -> Connection:
    conn = Connection(ctx, None)
    conn.set_accept_state()
    return conn


def _client_connection(pki: PKI, client_kind: str) -> Connection:
    """
    A client that verifies the server against the test CA and presents
    the credentials selected by ``client_kind`` (or none).
    """
    ctx = Context(TLS_METHOD)
    ctx.set_min_proto_version(TLS1_2_VERSION)
    store = ctx.get_cert_store()
    assert store is not None
    store.add_cert(X509.from_cryptography(pki.ca_cert))
    ctx.set_verify(VERIFY_PEER, _honest_verify_cb)
    entry = pki.clients[client_kind]
    if entry is not None:
        cert, key = entry
        ctx.use_certificate(cert)
        ctx.use_privatekey(key)
    conn = Connection(ctx, None)
    conn.set_connect_state()
    return conn


def _shuttle(sender: Connection, receiver: Connection) -> bool:
    """
    Move all pending output bytes from ``sender``'s memory BIO into
    ``receiver``'s.  Returns True if any bytes moved.
    """
    moved = False
    while True:
        try:
            data = sender.bio_read(4096)
        except WantReadError:
            break
        receiver.bio_write(data)
        moved = True
    return moved


def _drive(
    client: Connection, server: Connection
) -> tuple[dict[str, SSL.Error | None], dict[str, bool]]:
    """
    Pump bytes between two memory-BIO connections until both handshakes
    complete, one of them fails, or neither side has anything to say.

    Returns ``(errors, done)`` dicts keyed by ``"client"``/``"server"``.
    A completed handshake can still turn into an error afterwards (in
    TLS 1.3 the client's Certificate arrives after the server's
    Finished), so finished connections are probed with ``recv`` to
    surface late alerts.
    """
    conns = {"client": client, "server": server}
    errors: dict[str, SSL.Error | None] = {"client": None, "server": None}
    done = {"client": False, "server": False}

    for _ in range(100):
        moved = False
        for name, conn in conns.items():
            peer = conns["server" if name == "client" else "client"]
            if not done[name] and errors[name] is None:
                try:
                    conn.do_handshake()
                except WantReadError:
                    pass
                except SSL.Error as e:
                    errors[name] = e
                else:
                    done[name] = True
            if done[name] and errors[name] is None:
                try:
                    conn.recv(1)
                except WantReadError:
                    pass
                except SSL.Error as e:
                    errors[name] = e
            moved = _shuttle(conn, peer) or moved
        if not moved:
            break
    return errors, done


def _try_deliver(sender: Connection, receiver: Connection) -> bool:
    """
    Try to push application plaintext from ``sender`` to ``receiver``.
    Returns True only if the receiver actually got the bytes.
    """
    try:
        sender.send(SECRET)
    except SSL.Error:
        return False
    _shuttle(sender, receiver)
    try:
        return receiver.recv(4096) == SECRET
    except SSL.Error:
        return False


def _peer_common_name(peer_cert: X509) -> str | None:
    attrs = peer_cert.to_cryptography().subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )
    return attrs[0].value if attrs else None


def _is_authorized(peer_cert: X509 | None) -> bool:
    """
    The *business* authorization decision, deliberately kept separate
    from chain trust: only specific CNs may use the application.
    """
    return (
        peer_cert is not None
        and _peer_common_name(peer_cert) in ALLOWED_CLIENT_CNS
    )


class TestStrictMTLSMatrix:
    """
    The acceptance matrix for a strict mTLS server, exercised with real
    memory-BIO handshakes against every kind of client credential.
    """

    @pytest.mark.parametrize(
        "client_kind, handshake_ok",
        [
            ("valid", True),
            # Chain verifies; business authorization is a separate
            # decision tested below.
            ("trusted-but-unauthorized", True),
            ("expired", False),
            ("untrusted", False),
            ("none", False),
        ],
    )
    def test_handshake_matrix(
        self, pki: PKI, client_kind: str, handshake_ok: bool
    ) -> None:
        server = _server_connection(strict_mtls_server_context(pki))
        client = _client_connection(pki, client_kind)

        errors, done = _drive(client, server)

        if handshake_ok:
            assert done == {"client": True, "server": True}
            assert errors == {"client": None, "server": None}
            assert server.get_peer_certificate() is not None
            assert _try_deliver(server, client)
        else:
            assert errors["client"] is not None or errors["server"] is not None
            # No application plaintext is delivered in either
            # direction when no valid client certificate was presented.
            assert not _try_deliver(server, client)
            assert not _try_deliver(client, server)

    def test_verify_callback_is_told_about_underlying_errors(
        self, pki: PKI
    ) -> None:
        """
        With an honest callback, the underlying verification failure is
        observable (``ok == 0``) and the handshake fails.
        """
        observed_ok: list[int] = []

        def recording_cb(
            conn: Connection, cert: X509, errnum: int, depth: int, ok: int
        ) -> bool:
            observed_ok.append(ok)
            return bool(ok)

        server = _server_connection(
            strict_mtls_server_context(pki, recording_cb)
        )
        client = _client_connection(pki, "expired")

        errors, _done = _drive(client, server)

        assert 0 in observed_ok
        assert errors["client"] is not None or errors["server"] is not None


class TestVerifyModeBits:
    """
    The configuration bits alone decide whether a certificate is
    *requested* and *required*; these tests prove the behavioral
    difference over real handshakes.
    """

    def test_verify_peer_alone_admits_certless_client(self, pki: PKI) -> None:
        """
        ``VERIFY_PEER`` without ``VERIFY_FAIL_IF_NO_PEER_CERT`` asks for
        a client certificate but does not require one: a client
        presenting nothing still completes the handshake.
        """
        server = _server_connection(_server_context(pki, VERIFY_PEER))
        client = _client_connection(pki, "none")

        errors, done = _drive(client, server)

        assert done["server"] and errors["server"] is None
        assert server.get_peer_certificate() is None
        # The application must therefore check for a peer certificate
        # itself; nothing at the TLS layer stopped this client.
        assert not _is_authorized(server.get_peer_certificate())

    def test_verify_none_requests_no_certificate(self, pki: PKI) -> None:
        server = _server_connection(_server_context(pki, VERIFY_NONE))
        client = _client_connection(pki, "none")

        errors, done = _drive(client, server)

        assert done["server"] and errors["server"] is None
        assert server.get_peer_certificate() is None


class TestConnectionLevelOverride:
    """
    ``Connection.set_verify`` overrides the context policy for that one
    connection, in both directions.
    """

    def test_connection_can_weaken_strict_context(self, pki: PKI) -> None:
        """
        A strict context is silently neutralized by a connection-local
        ``set_verify(VERIFY_NONE)``: a client with no certificate is
        accepted and receives application plaintext.
        """
        server = _server_connection(strict_mtls_server_context(pki))
        server.set_verify(VERIFY_NONE)
        client = _client_connection(pki, "none")

        errors, done = _drive(client, server)

        assert done["server"] and errors["server"] is None
        assert server.get_peer_certificate() is None
        assert _try_deliver(server, client)

    def test_connection_can_strengthen_lenient_context(self, pki: PKI) -> None:
        """
        A ``VERIFY_NONE`` context is upgraded to strict mTLS by a
        connection-local ``set_verify``: a certificateless client is
        rejected and gets no plaintext.
        """
        server = _server_connection(_server_context(pki, VERIFY_NONE))
        server.set_verify(STRICT_SERVER_VERIFY, _honest_verify_cb)
        client = _client_connection(pki, "none")

        errors, _done = _drive(client, server)

        assert errors["client"] is not None or errors["server"] is not None
        assert not _try_deliver(server, client)


class TestVerifyCallbackSemantics:
    """
    The verify callback has the final word over the underlying chain
    verification -- for better and for worse.
    """

    @pytest.mark.parametrize("client_kind", ["expired", "untrusted"])
    def test_lax_callback_true_silently_accepts_bad_clients(
        self, pki: PKI, client_kind: str
    ) -> None:
        """
        ANTI-PATTERN (deliberately insecure, kept as a regression
        canary): a verify callback that always returns ``True``
        *overrides* the underlying chain errors.  The handshake
        completes and plaintext flows to a peer whose certificate is
        expired or issued by an unknown CA.  If pyOpenSSL ever stops
        letting ``True`` mask verification failures, this test fails
        and the insecure pattern becomes visible instead of silent.
        """
        observed_errors: list[int] = []

        def lax_callback(
            conn: Connection, cert: X509, errnum: int, depth: int, ok: int
        ) -> bool:
            if not ok:
                observed_errors.append(errnum)
            return True  # the bug this canary guards against

        server = _server_connection(
            strict_mtls_server_context(pki, lax_callback)
        )
        client = _client_connection(pki, client_kind)

        errors, done = _drive(client, server)

        # The underlying verification really did fail...
        assert observed_errors, "callback never saw a verification error"
        # ...but returning True overrode it.
        assert done == {"client": True, "server": True}
        assert errors == {"client": None, "server": None}
        peer_cert = server.get_peer_certificate()
        assert peer_cert is not None
        if client_kind == "expired":
            assert peer_cert.has_expired()
        # And the wrongly-admitted client receives plaintext.
        assert _try_deliver(server, client)

    def test_callback_false_rejects_valid_client(self, pki: PKI) -> None:
        """
        The override cuts both ways: returning ``False`` rejects a
        client whose chain is perfectly valid.
        """
        seen_ok: list[int] = []

        def paranoid_callback(
            conn: Connection, cert: X509, errnum: int, depth: int, ok: int
        ) -> bool:
            seen_ok.append(ok)
            return False

        server = _server_connection(
            strict_mtls_server_context(pki, paranoid_callback)
        )
        client = _client_connection(pki, "valid")

        errors, _done = _drive(client, server)

        assert 1 in seen_ok  # the chain itself verified fine
        assert errors["client"] is not None or errors["server"] is not None
        assert not _try_deliver(server, client)


class TestChainTrustVsBusinessAuthorization:
    """
    "The chain is trusted" and "this identity may use the application"
    are separate decisions and must not be collapsed into one flag.
    """

    @pytest.mark.parametrize(
        "client_kind, chain_trusted, authorized",
        [
            ("valid", True, True),
            # Cryptographically fine, business-wise rejected.
            ("trusted-but-unauthorized", True, False),
            # Never even gets a trusted chain.
            ("expired", False, False),
        ],
    )
    def test_authorization_is_a_separate_gate(
        self,
        pki: PKI,
        client_kind: str,
        chain_trusted: bool,
        authorized: bool,
    ) -> None:
        server = _server_connection(strict_mtls_server_context(pki))
        client = _client_connection(pki, client_kind)

        errors, done = _drive(client, server)

        tls_ok = (
            done == {"client": True, "server": True}
            and errors == {"client": None, "server": None}
            and server.get_peer_certificate() is not None
        )
        assert tls_ok == chain_trusted

        # The toy application only delivers plaintext when *both*
        # decisions pass.
        delivered = False
        if tls_ok and _is_authorized(server.get_peer_certificate()):
            delivered = _try_deliver(server, client)

        assert delivered == authorized

    def test_trusted_but_unauthorized_identity_gets_no_plaintext(
        self, pki: PKI
    ) -> None:
        """
        A client whose certificate chains to our CA but whose CN is not
        on the allow-list completes the TLS handshake yet must receive
        no application plaintext.
        """
        server = _server_connection(strict_mtls_server_context(pki))
        client = _client_connection(pki, "trusted-but-unauthorized")

        errors, done = _drive(client, server)

        assert done == {"client": True, "server": True}
        assert errors == {"client": None, "server": None}
        peer_cert = server.get_peer_certificate()
        assert peer_cert is not None
        assert _peer_common_name(peer_cert) == "rogue-employee"
        assert not _is_authorized(peer_cert)
