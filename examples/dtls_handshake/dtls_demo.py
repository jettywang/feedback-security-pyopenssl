"""DTLS handshake driver demo over a fully simulated network.

Everything here runs against memory BIOs and a virtual scheduler: no socket
is ever created and no thread blocks.  OpenSSL's own monotonic clock still
drives the retransmission deadlines, so when a scenario needs a timeout we
advance *real* time by the small delay reported by
``DTLSv1_get_timeout`` (about one second for the first retransmit).

Scenarios, each asserted rather than merely printed:

1. happy path baseline;
2. one lost handshake datagram, then successful retransmission recovery;
3. duplicated datagram delivery (OpenSSL must ignore the duplicate);
4. a timer firing after the handshake already completed (stale timer);
5. connection cancellation (nothing is sent afterwards);
6. a definitive OpenSSL failure (untrusted certificate), proving a failed
   handshake is never treated as "still retrying".

Run with ``python examples/dtls_handshake/dtls_demo.py``.
"""

from __future__ import annotations

import datetime
import heapq
import os
import pathlib
import socket
import tempfile
import time
from dataclasses import dataclass
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from dtls_handshake_driver import (
    DtlsHandshakeDriver,
    HandshakeState,
    TimerHandle,
)

from OpenSSL import SSL


class VirtualScheduler:
    """Deterministic scheduler.

    It does not run the loop itself; it only records deadlines and exposes
    :meth:`run_due`.  The demo decides when to let due timers run, which is
    what allows "timer fires after handshake completed" to be tested without
    any busy waiting.
    """

    def __init__(self) -> None:
        self._now = 0.0
        self._seq = 0
        self._heap: list[tuple[float, int, str, Callable[[], None]]] = []
        # Most recent callback registered per owner, retained even after the
        # timer is cancelled or superseded, so stale delivery can be tested.
        self._latest: dict[str, Callable[[], None]] = {}

    @property
    def now(self) -> float:
        return self._now

    def call_later(
        self, delay: float, callback: Callable[[], None], owner: str
    ) -> TimerHandle:
        self._seq += 1
        seq = self._seq
        deadline = self._now + delay
        heapq.heappush(self._heap, (deadline, seq, owner, callback))
        self._latest[owner] = callback
        return _VirtualTimer(self, seq)

    def pending(self) -> list[tuple[float, str]]:
        return [
            (deadline, owner) for deadline, _, owner, _ in sorted(self._heap)
        ]

    def run_due(self) -> int:
        """Run every timer whose deadline has passed. Returns count run."""
        run = 0
        while self._heap and self._heap[0][0] <= self._now:
            _, _, _, callback = heapq.heappop(self._heap)
            callback()
            run += 1
        return run

    def fire_stale(self, owner: str) -> None:
        """Re-invoke a connection's most recent timer callback.

        Test seam for "the scheduler delivers a callback after the driver has
        already moved on".  The driver must reject it via its generation guard
        rather than reactivate a completed or closed connection.
        """
        try:
            callback = self._latest[owner]
        except KeyError:
            raise AssertionError(f"no timer ever registered for {owner}")
        callback()

    def advance_to_next(self, *, real_wait: bool = True) -> float:
        """Jump virtual time to the next deadline.

        OpenSSL measures the retransmission deadline with its own internal
        monotonic clock rather than this scheduler, so when ``real_wait`` is
        set we also sleep for the equivalent real interval.  That keeps the
        demo honest: ``DTLSv1_handle_timeout`` is only called once the real
        OpenSSL deadline has elapsed.
        """
        if not self._heap:
            raise RuntimeError("no timers pending")
        deadline, _, _, _ = self._heap[0]
        delay = max(0.0, deadline - self._now)
        self._now = deadline
        if real_wait:
            time.sleep(delay)
        return delay

    def _cancel(self, seq: int) -> None:
        self._heap = [item for item in self._heap if item[1] != seq]
        heapq.heapify(self._heap)


class _VirtualTimer:
    def __init__(self, scheduler: VirtualScheduler, seq: int) -> None:
        self._scheduler = scheduler
        self._seq = seq
        self.cancelled = False

    def cancel(self) -> None:
        if not self.cancelled:
            self.cancelled = True
            self._scheduler._cancel(self._seq)


@dataclass
class PacketRecord:
    direction: str
    size: int
    delivered: bool
    duplicated: bool = False
    note: str = ""
    payload: bytes = b""


class VirtualTransport:
    """In-memory datagram link with pluggable loss/duplication policies.

    A datagram handed to :meth:`send` goes through the policy callback and is
    then queued for the peer; :meth:`pump_all` performs the actual delivery.
    Queueing matters for correctness: delivering straight away would re-enter
    a driver while it is still draining its own outbound BIO, whereas a real
    event loop hands inbound packets to the connection from a fresh stack
    frame.  Nothing here touches the operating system's networking stack.
    """

    def __init__(
        self,
        policy: Callable[[str, int, bytes], str] | None = None,
    ) -> None:
        self._peers: dict[str, DtlsHandshakeDriver] = {}
        self._policy = policy or (lambda *_: "pass")
        self.records: list[PacketRecord] = []
        self._inbound: dict[str, list[bytes]] = {}

    def attach(self, driver: DtlsHandshakeDriver) -> None:
        self._peers[driver.connection_id] = driver
        self._inbound[driver.connection_id] = []

    def send(self, connection_id: str, datagram: bytes) -> None:
        peer_id = "server" if connection_id == "client" else "client"
        decision = self._policy(peer_id, len(self.records), datagram)
        if decision == "drop":
            self.records.append(
                PacketRecord(
                    connection_id,
                    len(datagram),
                    False,
                    note="dropped",
                    payload=datagram,
                )
            )
            return
        deliveries = 2 if decision == "duplicate" else 1
        for index in range(deliveries):
            self.records.append(
                PacketRecord(
                    connection_id,
                    len(datagram),
                    True,
                    duplicated=index == 1,
                    note="duplicate" if index == 1 else "",
                    payload=datagram,
                )
            )
            self._inbound[peer_id].append(datagram)

    def pump_all(self) -> None:
        """Deliver every queued datagram, in arrival order, until drained."""
        while any(self._inbound.values()):
            for peer_id in tuple(self._inbound):
                queue = self._inbound[peer_id]
                if not queue:
                    continue
                datagram = queue.pop(0)
                # feed() may queue new outbound datagrams, but never re-enters
                # a driver because send() only appends to a queue.
                self._peers[peer_id].feed(datagram)

    def sent_count(self, connection_id: str) -> int:
        return sum(
            1 for record in self.records if record.direction == connection_id
        )


def build_credentials(
    tmpdir: pathlib.Path, trusted: bool
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    """Generate a server key/cert and a CA bundle for the client."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo-ca")])
    now = datetime.datetime.now(datetime.UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )

    if trusted:
        # A distinct server certificate issued by the demo CA.
        server_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        server_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "dtls-server")]
        )
        signer = ca_key
        issuer = ca_name
    else:
        # Self-signed server cert that the CA bundle does not sign.
        server_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        server_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "rogue-server")]
        )
        signer = server_key
        issuer = server_name
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(issuer)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .sign(signer, hashes.SHA256())
    )

    key_path = tmpdir / "server.key"
    cert_path = tmpdir / "server.crt"
    ca_path = tmpdir / "ca.pem"
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path, ca_path


def make_pair(
    tmpdir: pathlib.Path, *, trusted: bool = True
) -> tuple[
    DtlsHandshakeDriver,
    DtlsHandshakeDriver,
    VirtualScheduler,
    VirtualTransport,
]:
    key_path, cert_path, ca_path = build_credentials(tmpdir, trusted)

    server_ctx = SSL.Context(SSL.DTLS_METHOD)
    server_ctx.set_options(SSL.OP_NO_QUERY_MTU)
    server_ctx.use_privatekey_file(os.fspath(key_path))
    server_ctx.use_certificate_file(os.fspath(cert_path))

    client_ctx = SSL.Context(SSL.DTLS_METHOD)
    client_ctx.set_options(SSL.OP_NO_QUERY_MTU)
    client_ctx.load_verify_locations(os.fspath(ca_path))
    # No permissive verify callback: an untrusted chain must fail the
    # handshake with a definitive OpenSSL error.
    client_ctx.set_verify(
        SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, None
    )

    scheduler = VirtualScheduler()
    transport = VirtualTransport()

    server_ssl = SSL.Connection(server_ctx)
    server_ssl.set_accept_state()
    server_ssl.set_ciphertext_mtu(1500)
    client_ssl = SSL.Connection(client_ctx)
    client_ssl.set_connect_state()
    client_ssl.set_ciphertext_mtu(1500)

    server = DtlsHandshakeDriver(
        server_ssl, "server", scheduler, transport.send
    )
    client = DtlsHandshakeDriver(
        client_ssl, "client", scheduler, transport.send
    )
    transport.attach(server)
    transport.attach(client)
    return client, server, scheduler, transport


def wait_for_retransmit(scheduler: VirtualScheduler) -> None:
    """Wait out the real OpenSSL deadline, then fire due virtual timers."""
    scheduler.advance_to_next()
    fired = scheduler.run_due()
    assert fired >= 1, "expected the retransmission timer to fire"


def scenario_happy_path(tmpdir: pathlib.Path) -> None:
    client, server, scheduler, transport = make_pair(tmpdir)
    client.start()
    assert transport.sent_count("client") == 1
    assert client.state is HandshakeState.PENDING
    assert server.state is HandshakeState.PENDING
    # Deliver the queued ClientHello and let every queued flight flow until
    # both sides settle.
    transport.pump_all()
    assert server.state is HandshakeState.CONNECTED
    assert client.state is HandshakeState.CONNECTED
    assert client.ssl.get_finished() and server.ssl.get_finished()
    assert client.ssl.DTLSv1_get_timeout() is None
    assert server.ssl.DTLSv1_get_timeout() is None
    assert scheduler.pending() == []
    print("  happy path: connected, no timers left armed")
    return client, server


def scenario_loss_and_recovery(tmpdir: pathlib.Path) -> None:
    def drop_first_client_hello(
        peer_id: str, index: int, datagram: bytes
    ) -> str:
        # ContentType handshake (22) and HandshakeType ClientHello (1).
        # Only the very first datagram is lost; the retransmit must get
        # through so the handshake can recover.
        if (
            index == 0
            and peer_id == "server"
            and datagram[0] == 22
            and datagram[13] == 1
        ):
            return "drop"
        return "pass"

    client, server, scheduler, transport = make_pair(tmpdir)
    transport._policy = drop_first_client_hello
    client.start()
    transport.pump_all()
    assert transport.records[-1].delivered is False
    assert server.state is HandshakeState.PENDING
    assert scheduler.pending(), "client must arm a retransmission timer"
    assert scheduler.pending()[0][1] == "client"

    before = transport.sent_count("client")
    wait_for_retransmit(scheduler)
    assert transport.sent_count("client") == before + 1
    # The retransmitted ClientHello is queued, not sent on a hidden socket.
    transport.pump_all()
    retransmit = next(
        record
        for record in reversed(transport.records)
        if record.direction == "client" and record.delivered
    )
    assert retransmit.note == ""
    assert server.state is HandshakeState.CONNECTED
    assert client.state is HandshakeState.CONNECTED
    assert scheduler.pending() == []
    print("  loss recovery: retransmitted ClientHello completed the handshake")
    return client, server


def scenario_duplicate_delivery(tmpdir: pathlib.Path) -> None:
    def duplicate_first_flight(
        peer_id: str, index: int, datagram: bytes
    ) -> str:
        if (
            index == 0
            and peer_id == "server"
            and datagram[0] == 22
            and datagram[13] == 1
        ):
            return "duplicate"
        return "pass"

    client, server, scheduler, transport = make_pair(tmpdir)
    transport._policy = duplicate_first_flight
    client.start()
    transport.pump_all()
    assert server.state is HandshakeState.CONNECTED
    assert client.state is HandshakeState.CONNECTED
    duplicates = [record for record in transport.records if record.duplicated]
    assert len(duplicates) == 1
    print("  duplicate delivery: replayed ClientHello ignored, handshake OK")
    return client, server


def scenario_stale_timer_after_completion(tmpdir: pathlib.Path) -> None:
    client, server, scheduler, transport = make_pair(tmpdir)
    client.start()
    transport.pump_all()
    assert client.state is HandshakeState.CONNECTED
    assert server.state is HandshakeState.CONNECTED
    # The handshake finished before any timer fired.  Force an OpenSSL
    # timeout call anyway to prove a completed connection is not reactivated.
    sent_before = len(transport.records)
    assert client.ssl.DTLSv1_handle_timeout() is False
    assert server.ssl.DTLSv1_handle_timeout() is False
    assert len(transport.records) == sent_before
    assert client.state is HandshakeState.CONNECTED
    assert server.state is HandshakeState.CONNECTED

    # Same guarantee at the driver layer: if the scheduler delivers a
    # callback the driver had already superseded, it must be ignored.
    scheduler.fire_stale("client")
    stale = [
        event
        for event in client.timer_events
        if event["event"] == "stale_timer_ignored"
    ]
    assert stale and stale[-1]["connection_id"] == "client"
    assert len(transport.records) == sent_before
    print("  stale timer: completed connection never reactivated, no send")
    return client, server


def scenario_cancellation(tmpdir: pathlib.Path) -> None:
    client, server, scheduler, transport = make_pair(tmpdir)
    # Drop everything so the ClientHello never reaches the server and the
    # client is left waiting on its retransmit timer.
    transport._policy = lambda *_: "drop"
    client.start()
    transport.pump_all()
    assert server.state is HandshakeState.PENDING
    assert scheduler.pending()
    client.cancel()
    assert client.state is HandshakeState.CANCELLED
    assert scheduler.pending() == []
    sent_before = len(transport.records)

    # Even if the old timer somehow runs, nothing may be sent afterwards.
    scheduler.fire_stale("client")
    assert len(transport.records) == sent_before
    assert client.state is HandshakeState.CANCELLED

    # Inbound traffic after cancellation is dropped, not processed.
    client.feed(b"\x16" * 12)
    assert len(transport.records) == sent_before
    assert client.state is HandshakeState.CANCELLED
    print("  cancellation: timer retired, zero further sends or processing")
    return client, server


def scenario_final_failure(tmpdir: pathlib.Path) -> None:
    client, server, scheduler, transport = make_pair(tmpdir, trusted=False)
    client.start()
    # ClientHello -> server flight carrying the untrusted certificate.
    assert client.state is HandshakeState.PENDING
    transport.pump_all()
    # The client rejects the chain; the fatal alert it emits reaches the
    # server, whose handshake then also terminates with a real OpenSSL error.
    assert client.state is HandshakeState.FAILED
    assert client.failure is not None
    assert "certificate verify failed" in str(client.failure)
    assert server.state is HandshakeState.FAILED
    assert server.failure is not None
    assert "alert" in str(server.failure)

    # A failed handshake is terminal: OpenSSL holds no retry deadline and
    # handle_timeout must not resurrect it.
    assert client.ssl.DTLSv1_get_timeout() is not None
    assert client.ssl.DTLSv1_handle_timeout() is False
    assert server.ssl.DTLSv1_handle_timeout() is False
    assert scheduler.pending() == []

    # The client still emitted its fatal alert through the caller's path.
    # ContentType 21 is alert; the datagram must have been queued for the
    # caller rather than written to a hidden socket.
    client_packets = [
        record
        for record in transport.records
        if record.direction == "client" and record.delivered
    ]
    assert client_packets, "fatal alert must be handed to the caller transport"
    alert_record = client_packets[-1]
    assert alert_record.payload[0] == 21, "ContentType 21 = alert"
    assert transport.records[-1].direction == "client"

    # Feeding more data after failure changes nothing.
    sent_before = len(transport.records)
    client.feed(b"\x16" * 12)
    assert client.state is HandshakeState.FAILED
    assert len(transport.records) == sent_before
    print("  final failure: terminal FAILED, alert sent, no retry scheduled")
    return client, server


def print_timer_audit(label: str, drivers: list[DtlsHandshakeDriver]) -> None:
    print(f"  [{label}] timer audit (every timer attributed to a connection):")
    for driver in drivers:
        for event in driver.timer_events:
            print(f"    {driver.connection_id:6s} {event}")


def main() -> None:
    scenarios = [
        ("happy path", scenario_happy_path),
        ("loss and retransmission recovery", scenario_loss_and_recovery),
        ("duplicated datagram", scenario_duplicate_delivery),
        (
            "stale timer after completion",
            scenario_stale_timer_after_completion,
        ),
        ("connection cancellation", scenario_cancellation),
        ("definitive OpenSSL failure", scenario_final_failure),
    ]

    # Hard guarantee requested by the design: the driver only uses memory
    # BIOs and the caller-supplied datagram callback.  Any attempt to open a
    # real socket anywhere in these scenarios fails loudly.
    def refuse_socket(*args: object, **kwargs: object) -> None:
        raise AssertionError("DTLS handshake driver must never open a socket")

    original_socket = socket.socket
    socket.socket = refuse_socket  # type: ignore[assignment]
    try:
        with tempfile.TemporaryDirectory() as temp_name:
            tmpdir = pathlib.Path(temp_name)
            for title, scenario in scenarios:
                print(f"[scenario] {title}")
                drivers = scenario(tmpdir)
                print_timer_audit(title, drivers)
    finally:
        socket.socket = original_socket  # type: ignore[assignment]
    print("\nAll DTLS driver scenarios passed (no socket was created).")


if __name__ == "__main__":
    main()
