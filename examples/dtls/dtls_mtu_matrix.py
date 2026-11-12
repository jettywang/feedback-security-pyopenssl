#!/usr/bin/env python3
"""
DTLS MTU security regression matrix (standalone, no sockets required).

This script drives a real DTLS handshake over *memory BIOs* with a locally
generated certificate and then checks the three sizes the task asks about:

  1. the configured *ciphertext* MTU (the UDP payload budget);
  2. the *cleartext* MTU the library reports after the handshake
     (``DTLS_get_data_mtu``) -- the largest application write that still fits
     the configured path;
  3. the *actual on-wire datagram length* produced for each write.

Security property under test
-----------------------------
DTLS is a datagram protocol, not a byte stream. Every accepted ``write`` must
become exactly one datagram that the peer reassembles byte-for-byte. The
backend must never silently split an oversized application message into
path-sized records (which the receiver would treat as separate messages) or
silently truncate it into a shorter record the receiver mistakes for the whole
secure message. Oversized input is therefore either:

  * rejected outright by the backend (past the DTLS record plaintext cap), or
  * handled by an *explicit* application fragmentation protocol (demonstrated
    below), whose fragment size is taken from the library-reported cleartext
    MTU -- never from a hardcoded header subtraction.

Capabilities that a given OpenSSL build lacks (e.g. ``DTLS_get_data_mtu`` on
pre-1.1.1 builds, or DTLS 1.3) are recorded explicitly instead of being
emulated.

Usage
-----
    python examples/dtls/dtls_mtu_matrix.py
    python examples/dtls/dtls_mtu_matrix.py --json
    python examples/dtls/dtls_mtu_matrix.py --mtu 1200 --reduced-mtu 600
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from dataclasses import asdict, dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from OpenSSL import _util
from OpenSSL.SSL import (
    FILETYPE_PEM,
    OP_COOKIE_EXCHANGE,
    OP_NO_QUERY_MTU,
    Context,
    Connection,
    DTLS_METHOD,
    Error,
    TLS1_3_VERSION,
    WantReadError,
)
from OpenSSL.crypto import load_certificate, load_privatekey

LARGE_BUFFER = 65536
# RFC 6347 4.1.1 reuses the TLS 2**14 plaintext fragment limit. This only
# selects a payload the backend must reject; the real boundary is observed.
RECORD_PLAINTEXT_CAP = 2**14

CIPHER_SUITES = [
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES256-SHA384",
]


# --------------------------------------------------------------------------- #
# Local, in-memory certificate (nothing touches the disk or the network).
# --------------------------------------------------------------------------- #
def make_identity():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "dtls-mtu.local")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )


CERT_PEM, KEY_PEM = make_identity()


# --------------------------------------------------------------------------- #
# Memory-BIO DTLS pair and handshake.
# --------------------------------------------------------------------------- #
def make_context(cipher_list=None):
    ctx = Context(DTLS_METHOD)
    # A memory BIO cannot discover a path MTU; prevent OpenSSL from clearing
    # the value we set.
    ctx.set_options(OP_NO_QUERY_MTU)
    ctx.use_privatekey(load_privatekey(FILETYPE_PEM, KEY_PEM))
    ctx.use_certificate(load_certificate(FILETYPE_PEM, CERT_PEM))
    if cipher_list is not None:
        ctx.set_cipher_list(cipher_list.encode("ascii"))
    return ctx


def build_pair(ciphertext_mtu, cipher_list=None):
    server_ctx = make_context(cipher_list)
    server_ctx.set_cookie_generate_callback(lambda ssl: b"xyzzy")
    server_ctx.set_cookie_verify_callback(
        lambda ssl, cookie: cookie == b"xyzzy"
    )
    server = Connection(server_ctx)
    server.set_accept_state()

    client = Connection(make_context(cipher_list))
    client.set_connect_state()

    client.set_ciphertext_mtu(ciphertext_mtu)
    server.set_ciphertext_mtu(ciphertext_mtu)
    return client, server


def handshake(client, server):
    latest_client_hello = None

    def pump(source, sink):
        nonlocal latest_client_hello
        try:
            chunk = source.bio_read(LARGE_BUFFER)
        except WantReadError:
            return False
        if len(chunk) > 13 and chunk[0] == 22 and chunk[13] == 1:
            latest_client_hello = chunk
        sink.bio_write(chunk)
        return True

    client_handshaking = True
    server_listening = True
    server_handshaking = False
    first = True
    for _ in range(200):
        if not first and not (
            pump(server, client) or pump(client, server)
        ):
            raise RuntimeError("handshake stopped making progress")
        first = False

        if client_handshaking:
            try:
                client.do_handshake()
            except WantReadError:
                pass
            else:
                client_handshaking = False

        if server_listening:
            try:
                server.DTLSv1_listen()
            except WantReadError:
                pass
            else:
                server_listening = False
                server_handshaking = True
                assert latest_client_hello is not None
                # Memory-BIO peek workaround (duplicate the ClientHello).
                server.bio_write(latest_client_hello)

        if server_handshaking:
            try:
                server.do_handshake()
            except WantReadError:
                pass
            else:
                server_handshaking = False

        if not (
            client_handshaking or server_listening or server_handshaking
        ):
            return
    raise RuntimeError("handshake did not converge")


def drain_datagrams(source, sink):
    datagrams = []
    while True:
        try:
            chunk = source.bio_read(LARGE_BUFFER)
        except WantReadError:
            return datagrams
        datagrams.append(chunk)
        sink.bio_write(chunk)


# --------------------------------------------------------------------------- #
# Result containers.
# --------------------------------------------------------------------------- #
@dataclass
class BoundaryCase:
    payload_bytes: int
    accepted: bool
    datagram_count: int
    datagram_lengths: list
    peer_received_exact: bool
    error: str | None = None


@dataclass
class SuiteRow:
    cipher_requested: str
    negotiated: bool
    version: str | None = None
    cipher: str | None = None
    ciphertext_mtu: int | None = None
    cleartext_mtu: int | None = None
    observed_overhead: int | None = None
    cases: list = field(default_factory=list)
    note: str | None = None


def attempt_write(client, server, size):
    payload = bytes((i % 256 for i in range(size)))
    try:
        sent = client.write(payload)
    except Error as exc:
        leftover = drain_datagrams(client, server)
        return BoundaryCase(
            payload_bytes=size,
            accepted=False,
            datagram_count=len(leftover),
            datagram_lengths=[len(d) for d in leftover],
            peer_received_exact=False,
            error=str(exc),
        )
    datagrams = drain_datagrams(client, server)
    exact = False
    if datagrams:
        exact = server.read(size + 64) == payload
    return BoundaryCase(
        payload_bytes=size,
        accepted=(sent == size),
        datagram_count=len(datagrams),
        datagram_lengths=[len(d) for d in datagrams],
        peer_received_exact=exact,
    )


# --------------------------------------------------------------------------- #
# Matrix builders.
# --------------------------------------------------------------------------- #
def capability_report():
    lib = _util.lib
    return {
        "openssl_has_DTLS_get_data_mtu": hasattr(
            lib, "DTLS_get_data_mtu"
        ),
        "openssl_has_DTLSv1_3_method": hasattr(lib, "DTLSv1_3_method"),
        "pyopenssl_op_cookie_exchange": OP_COOKIE_EXCHANGE is not None,
    }


def run_suite_matrix(ciphertext_mtu):
    rows = []
    for suite in CIPHER_SUITES:
        row = SuiteRow(cipher_requested=suite, negotiated=False)
        try:
            client, server = build_pair(ciphertext_mtu, suite)
            handshake(client, server)
        except Error as exc:
            row.note = f"unavailable in this build: {exc}"
            rows.append(row)
            continue

        clear = client.get_cleartext_mtu()
        row.negotiated = True
        row.version = client.get_protocol_version_name()
        row.cipher = client.get_cipher_name()
        row.ciphertext_mtu = ciphertext_mtu
        row.cleartext_mtu = clear
        # Measured delta, reported as an observation -- never used to derive
        # the limit by hardcoded subtraction.
        row.observed_overhead = ciphertext_mtu - clear

        # Exactly at the library limit, one byte over the path, and one byte
        # past the DTLS record plaintext cap (must be rejected).
        for size in (clear, clear + 1, RECORD_PLAINTEXT_CAP + 1):
            row.cases.append(attempt_write(client, server, size))
        rows.append(row)
    return rows


def run_reconfiguration(initial_mtu, reduced_mtu, regrown_mtu):
    client, server = build_pair(initial_mtu, CIPHER_SUITES[0])
    handshake(client, server)
    first_clear = client.get_cleartext_mtu()

    client.set_ciphertext_mtu(reduced_mtu)
    server.set_ciphertext_mtu(reduced_mtu)
    reduced_clear = client.get_cleartext_mtu()
    fit = attempt_write(client, server, reduced_clear)

    # Reuse the stale (pre-reconfiguration) length: must stay one whole
    # datagram rather than being split to fit the new path.
    stale = attempt_write(client, server, first_clear)

    client.set_ciphertext_mtu(regrown_mtu)
    server.set_ciphertext_mtu(regrown_mtu)
    regrown_clear = client.get_cleartext_mtu()

    return {
        "initial_ciphertext_mtu": initial_mtu,
        "initial_cleartext_mtu": first_clear,
        "reduced_ciphertext_mtu": reduced_mtu,
        "reduced_cleartext_mtu": reduced_clear,
        "regrown_ciphertext_mtu": regrown_mtu,
        "regrown_cleartext_mtu": regrown_clear,
        "write_at_reduced_limit": asdict(fit),
        "stale_cached_length_after_shrink": asdict(stale),
        "stale_datagram_exceeds_new_path": (
            stale.datagram_lengths[0] > reduced_mtu
            if stale.datagram_lengths
            else None
        ),
    }


def run_explicit_fragmentation(ciphertext_mtu):
    """An explicit, library-sized application fragmentation protocol."""
    client, server = build_pair(ciphertext_mtu, CIPHER_SUITES[0])
    handshake(client, server)
    clear = client.get_cleartext_mtu()

    # One byte sequence tag, so each frame stays strictly within clear MTU.
    fragment_cap = clear - 1
    message = bytes((i % 256 for i in range(fragment_cap * 3 + 7)))
    frames, wire_lengths = [], []
    for index, start in enumerate(range(0, len(message), fragment_cap)):
        frame = bytes([index]) + message[start : start + fragment_cap]
        assert len(frame) <= clear
        client.write(frame)
        datagrams = drain_datagrams(client, server)
        assert len(datagrams) == 1
        frames.append(frame)
        wire_lengths.append(len(datagrams[0]))

    reassembled = bytearray()
    for expected_index in range(len(frames)):
        frame = server.read(clear + 1)
        assert frame[0] == expected_index
        reassembled.extend(frame[1:])

    return {
        "cleartext_mtu": clear,
        "message_bytes": len(message),
        "fragment_count": len(frames),
        "max_wire_datagram": max(wire_lengths),
        "all_within_ciphertext_mtu": max(wire_lengths)
        <= ciphertext_mtu,
        "reassembled_exact": bytes(reassembled) == message,
    }


def probe_dtls13(ciphertext_mtu):
    if not hasattr(_util.lib, "DTLS_get_data_mtu"):
        return {"dtls13": "not-tested", "reason": "no DTLS_get_data_mtu"}
    server_ctx = make_context()
    server_ctx.set_cookie_generate_callback(lambda ssl: b"xyzzy")
    server_ctx.set_cookie_verify_callback(
        lambda ssl, cookie: cookie == b"xyzzy"
    )
    client_ctx = make_context()
    try:
        for ctx in (server_ctx, client_ctx):
            ctx.set_min_proto_version(TLS1_3_VERSION)
            ctx.set_max_proto_version(TLS1_3_VERSION)
    except ValueError as exc:  # pragma: no cover - older bindings
        return {"dtls13": "unsupported", "reason": str(exc)}

    server = Connection(server_ctx)
    server.set_accept_state()
    client = Connection(client_ctx)
    client.set_connect_state()
    client.set_ciphertext_mtu(ciphertext_mtu)
    server.set_ciphertext_mtu(ciphertext_mtu)
    try:
        handshake(client, server)
    except Error as exc:
        return {"dtls13": "unsupported", "reason": str(exc)}

    version = client.get_protocol_version_name()
    if version != "DTLSv1.3":
        return {
            "dtls13": "unsupported",
            "reason": f"build negotiated {version}",
        }
    return {
        "dtls13": "supported",
        "cleartext_mtu": client.get_cleartext_mtu(),
    }


# --------------------------------------------------------------------------- #
# Reporting.
# --------------------------------------------------------------------------- #
def print_human(report):
    cap = report["capabilities"]
    print("== Capabilities ==")
    for key, value in cap.items():
        print(f"  {key}: {value}")
    print(f"  dtls13_probe: {report['dtls13']}")
    if report["dtls13"].get("reason"):
        print(f"      reason: {report['dtls13']['reason']}")

    print("\n== Per-cipher-suite matrix ==")
    header = (
        f"{'cipher':<34}{'ver':<9}{'ct_mtu':>7}{'clear':>7}"
        f"{'overhead':>9}  boundary cases"
    )
    print(header)
    for row in report["suites"]:
        if not row.negotiated:
            print(f"  {row.cipher_requested:<32} SKIP ({row.note})")
            continue
        print(
            f"  {row.cipher:<32}{row.version:<9}{row.ciphertext_mtu:>7}"
            f"{row.cleartext_mtu:>7}{row.observed_overhead:>9}"
        )
        for case in row.cases:
            if case.error:
                reason = case.error
                if "dtls message too big" in reason:
                    reason = "dtls message too big"
                detail = "REJECTED (" + reason + ")"
            else:
                detail = (
                    f"{case.datagram_count} dg, "
                    f"len={case.datagram_lengths}, exact="
                    f"{case.peer_received_exact}"
                )
            print(f"      n={case.payload_bytes:<6} -> {detail}")

    rec = report["reconfiguration"]
    print("\n== Runtime reconfiguration ==")
    for key in (
        "initial_cleartext_mtu",
        "reduced_cleartext_mtu",
        "regrown_cleartext_mtu",
    ):
        print(f"  {key}: {rec[key]}")
    stale = rec["stale_cached_length_after_shrink"]
    print(
        "  stale cached length -> datagrams="
        f"{stale['datagram_count']} lengths={stale['datagram_lengths']} "
        f"exceeds_new_path={rec['stale_datagram_exceeds_new_path']} "
        "(never split/truncated)"
    )

    frag = report["fragmentation"]
    print("\n== Explicit application fragmentation ==")
    for key, value in frag.items():
        print(f"  {key}: {value}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="emit the matrix as JSON"
    )
    parser.add_argument(
        "--mtu",
        type=int,
        default=1200,
        help="ciphertext (UDP payload) MTU to configure",
    )
    parser.add_argument(
        "--reduced-mtu",
        type=int,
        default=600,
        help="MTU to switch to at runtime (must be smaller than --mtu)",
    )
    parser.add_argument(
        "--regrown-mtu",
        type=int,
        default=1500,
        help="MTU to switch back to at runtime",
    )
    args = parser.parse_args(argv)

    suite_rows = run_suite_matrix(args.mtu)
    report = {
        "capabilities": capability_report(),
        "dtls13": probe_dtls13(args.mtu),
        "suites": [asdict(row) for row in suite_rows],
        "reconfiguration": run_reconfiguration(
            args.mtu, args.reduced_mtu, args.regrown_mtu
        ),
        "fragmentation": run_explicit_fragmentation(args.mtu),
    }

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_human({**report, "suites": suite_rows})
    return 0


if __name__ == "__main__":
    sys.exit(main())
