# Copyright (C) AB Strakt
# See LICENSE for details.

"""
Mandatory ALPN negotiation over paired in-memory BIOs.

This is a runnable demonstration of :mod:`OpenSSL.alpn`.  It builds a client
and server connected only by memory BIOs (no sockets, no network), performs
real TLS handshakes, and shows that:

* a connection negotiating an allowed protocol can carry application data;
* a client that omits the ALPN extension is rejected;
* offers with no protocol in common are rejected;
* a selection callback returning a disallowed value is rejected;
* a rejected connection can never deliver application data;
* an ordinary certificate verification failure is reported separately from
  an ALPN policy failure.

Run it with::

    python examples/mandatory_alpn.py
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from OpenSSL import SSL, alpn
from OpenSSL.crypto import FILETYPE_PEM, load_certificate, load_privatekey
from OpenSSL.SSL import VERIFY_PEER, Context, SSLv23_METHOD

ALLOWED = [b"h2", b"http/1.1"]


def make_self_signed_cert() -> tuple[bytes, bytes]:
    """Generate an ephemeral self-signed certificate and key (PEM)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "alpn.example")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1)
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


CERT_PEM, KEY_PEM = make_self_signed_cert()


def server_context() -> Context:
    context = Context(SSLv23_METHOD)
    context.use_privatekey(load_privatekey(FILETYPE_PEM, KEY_PEM))
    context.use_certificate(load_certificate(FILETYPE_PEM, CERT_PEM))
    return context


def client_context() -> Context:
    return Context(SSLv23_METHOD)


def pair(policy: alpn.ALPNPolicy):
    """Build a guarded, memory-BIO connected client/server pair."""
    cctx = client_context()
    policy.configure_client(cctx)
    sctx = server_context()
    policy.configure_server(sctx)
    raw_client, raw_server = alpn.memory_bio_pair(cctx, sctx)
    return (
        policy.wrap(raw_client, is_server=False),
        policy.wrap(raw_server, is_server=True),
    )


def pump_app_data(sender, receiver) -> None:
    while True:
        try:
            chunk = sender.connection.bio_read(4096)
        except SSL.WantReadError:
            return
        receiver.connection.bio_write(chunk)


def demo_allowed_protocol() -> None:
    print("[1] allowed protocol -> handshake succeeds, data flows")
    policy = alpn.ALPNPolicy(ALLOWED)
    client, server = pair(policy)
    alpn.handshake_in_memory(client, server)
    print("    negotiated:", client.get_alpn_proto_negotiated())

    client.send(b"hello over h2")
    pump_app_data(client, server)
    print("    server received:", server.recv(4096))


def demo_missing_extension() -> None:
    print("[2] client sends no ALPN extension -> rejected")
    policy = alpn.ALPNPolicy(ALLOWED)
    cctx = client_context()  # deliberately not configure_client()
    sctx = server_context()
    policy.configure_server(sctx)
    raw_client, raw_server = alpn.memory_bio_pair(cctx, sctx)
    client = policy.wrap(raw_client, is_server=False)
    server = policy.wrap(raw_server, is_server=True)
    try:
        alpn.handshake_in_memory(client, server)
    except alpn.ALPNError as error:
        print("   ", type(error).__name__, "-", error.reason.value)


def demo_no_intersection() -> None:
    print("[3] no protocol in common -> rejected")
    policy = alpn.ALPNPolicy(ALLOWED)
    cctx = client_context()
    cctx.set_alpn_protos([b"spdy/2"])
    sctx = server_context()
    policy.configure_server(sctx)
    raw_client, raw_server = alpn.memory_bio_pair(cctx, sctx)
    client = policy.wrap(raw_client, is_server=False)
    server = policy.wrap(raw_server, is_server=True)
    try:
        alpn.handshake_in_memory(client, server)
    except alpn.ALPNError as error:
        print("   ", type(error).__name__, "-", error.reason.value)


def demo_disallowed_callback() -> None:
    print("[4] callback selects a disallowed protocol -> rejected, no data")
    policy = alpn.ALPNPolicy(ALLOWED)
    cctx = client_context()
    cctx.set_alpn_protos([b"evil/1.0", b"h2"])
    sctx = server_context()
    # A raw callback outside the policy tries to select something forbidden.
    sctx.set_alpn_select_callback(lambda conn, offered: b"evil/1.0")
    raw_client, raw_server = alpn.memory_bio_pair(cctx, sctx)
    client = policy.wrap(raw_client, is_server=False)
    server = policy.wrap(raw_server, is_server=True)

    alpn.pump_in_memory(raw_client, raw_server)
    policy.mark_handshake_done(raw_client)
    policy.mark_handshake_done(raw_server)
    print("    raw negotiated result:", server.get_alpn_proto_negotiated())
    try:
        server.require_negotiated_protocol()
    except alpn.ALPNError as error:
        print("   ", type(error).__name__, "-", error.reason.value)
    for action in (
        lambda: server.send(b"x"),
        lambda: server.recv(10),
        lambda: client.send(b"x"),
    ):
        try:
            action()
        except alpn.ALPNError as error:
            print("    application IO blocked:", error.reason.value)


def demo_certificate_failure_is_separate() -> None:
    print("[5] certificate verification failure -> SSL.Error, not ALPNError")
    policy = alpn.ALPNPolicy(ALLOWED)
    cctx = client_context()
    policy.configure_client(cctx)
    cctx.set_verify(VERIFY_PEER, None)  # trust nothing -> verify fails
    sctx = server_context()
    policy.configure_server(sctx)
    raw_client, raw_server = alpn.memory_bio_pair(cctx, sctx)
    client = policy.wrap(raw_client, is_server=False)
    server = policy.wrap(raw_server, is_server=True)
    try:
        alpn.handshake_in_memory(client, server)
    except alpn.ALPNError as error:
        print("    UNEXPECTED policy error:", error)
    except SSL.Error as error:
        reason = error.args[0][0][2]
        print("   ", type(error).__name__, "-", reason)


def demo_legacy_optional_alpn() -> None:
    print("[6] legacy optional ALPN still works without any policy")
    cctx = client_context()
    cctx.set_alpn_protos(ALLOWED)
    sctx = server_context()  # no select callback, no policy
    raw_client, raw_server = alpn.memory_bio_pair(cctx, sctx)
    alpn.pump_in_memory(raw_client, raw_server)
    print(
        "    negotiated (empty allowed):",
        raw_client.get_alpn_proto_negotiated(),
    )
    raw_client.send(b"legacy payload")
    while True:
        try:
            chunk = raw_client.bio_read(4096)
        except SSL.WantReadError:
            break
        raw_server.bio_write(chunk)
    print("    server received:", raw_server.recv(4096))


if __name__ == "__main__":
    demo_allowed_protocol()
    demo_missing_extension()
    demo_no_intersection()
    demo_disallowed_callback()
    demo_certificate_failure_is_separate()
    demo_legacy_optional_alpn()
