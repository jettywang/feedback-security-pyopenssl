"""Structured certificate-chain verification reports on top of pyOpenSSL.

The module keeps two things deliberately separate:

1. **Peer message** — the certificates the remote party actually sent, in the
   exact order received, with duplicates and embedded self-signed roots
   preserved.  Nothing in the peer message is ever treated as a trust anchor.
2. **Verified result** — what the local :class:`OpenSSL.X509Store` actually
   adopts.  On success the adopted chain comes exclusively from
   :meth:`OpenSSL.X509StoreContext.get_verified_chain`; alternative
   cross-signed branches that were *not* adopted are reported as such and can
   never masquerade as the final chain.  On failure the verdict is simply
   ``"untrusted"``: diagnostics are kept, but no "partially trusted" state is
   ever emitted.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable

from cryptography import x509 as _x509
from OpenSSL import crypto
from OpenSSL._util import lib as _openssl_lib

# ---------------------------------------------------------------------------
# OpenSSL numeric verify-code -> symbolic name (resolved at import time, so
# the mapping tracks whichever OpenSSL build is loaded).
# ---------------------------------------------------------------------------
_VERIFY_CODE_NAMES: dict[int, str] = {
    value: name
    for name, value in vars(_openssl_lib).items()
    if name.startswith("X509_V_") and isinstance(value, int)
}


def code_name(code: int) -> str:
    """Return the symbolic OpenSSL name for a numeric verify result."""
    return _VERIFY_CODE_NAMES.get(code, f"X509_V_UNKNOWN_{code}")


# ---------------------------------------------------------------------------
# Small certificate helpers (pyOpenSSL X509 -> plain Python descriptors)
# ---------------------------------------------------------------------------
def fingerprint(cert: crypto.X509) -> str:
    """SHA-256 fingerprint, hex — the stable identity of a certificate."""
    return cert.digest("sha256").decode("ascii").replace(":", "").lower()


def _native(cert: crypto.X509) -> _x509.Certificate:
    """cryptography representation, cached on the pyOpenSSL wrapper."""
    cached = getattr(cert, "_diag_native", None)
    if cached is None:
        cached = cert.to_cryptography()
        setattr(cert, "_diag_native", cached)
    return cached


def _subject_der(cert: crypto.X509) -> bytes:
    return _native(cert).subject.public_bytes()


def _issuer_der(cert: crypto.X509) -> bytes:
    return _native(cert).issuer.public_bytes()


def _dn_string(cert: crypto.X509, *, issuer: bool = False) -> str:
    """RFC 4514 rendering of a subject or issuer distinguished name."""
    native = _native(cert)
    name = native.issuer if issuer else native.subject
    return name.rfc4514_string()


def common_name(cert: crypto.X509) -> str:
    attributes = _native(cert).subject.get_attributes_for_oid(
        _x509.NameOID.COMMON_NAME
    )
    return attributes[0].value if attributes else ""


def is_self_signed(cert: crypto.X509) -> bool:
    """A certificate is self-signed when subject and issuer DNs match."""
    native = _native(cert)
    return native.subject.public_bytes() == native.issuer.public_bytes()


def is_ca(cert: crypto.X509) -> bool:
    # Bridge to cryptography for extension parsing (pyOpenSSL offers no
    # direct BasicConstraints accessor on X509).
    try:
        constraints = _native(cert).extensions.get_extension_for_class(
            _x509.BasicConstraints
        )
    except _x509.ExtensionNotFound:
        return False
    return bool(constraints.value.ca)


def role_of(cert: crypto.X509) -> str:
    """Coarse role used purely for labelling the peer message."""
    if is_self_signed(cert) and is_ca(cert):
        return "self-signed-root"
    if is_ca(cert):
        return "intermediate-ca"
    return "end-entity"


@dataclass(frozen=True)
class CertDescriptor:
    """What the report says about a single certificate instance."""

    fingerprint: str
    common_name: str
    subject: str
    issuer: str
    role: str
    self_signed: bool
    is_ca: bool


def describe(cert: crypto.X509) -> CertDescriptor:
    return CertDescriptor(
        fingerprint=fingerprint(cert),
        common_name=common_name(cert),
        subject=_dn_string(cert),
        issuer=_dn_string(cert, issuer=True),
        role=role_of(cert),
        self_signed=is_self_signed(cert),
        is_ca=is_ca(cert),
    )


# ---------------------------------------------------------------------------
# Peer message analysis (input side — never a source of trust)
# ---------------------------------------------------------------------------
@dataclass
class PeerCertRecord:
    """One entry of the wire message, indexed by its position on the wire."""

    wire_index: int
    descriptor: CertDescriptor
    duplicate_of: int | None = None
    issuer_dn: str = ""
    subject_dn: str = ""


@dataclass
class PeerMessageAnalysis:
    """Structured view of exactly what the peer sent."""

    ordered: list[PeerCertRecord]
    leaf_fingerprint: str | None
    duplicate_fingerprints: list[str]
    embedded_self_signed_roots: list[str]
    order_matches_chain: bool
    order_notes: list[str]


def analyze_peer_message(peer_certs: list[crypto.X509]) -> PeerMessageAnalysis:
    """Preserve wire order while flagging duplicates and embedded roots."""
    seen: dict[str, int] = {}
    records: list[PeerCertRecord] = []
    duplicates: list[str] = []
    embedded_roots: list[str] = []

    for index, cert in enumerate(peer_certs):
        fp = fingerprint(cert)
        duplicate_of = seen.get(fp)
        if duplicate_of is None:
            seen[fp] = index
        elif fp not in duplicates:
            duplicates.append(fp)
        if is_self_signed(cert):
            embedded_roots.append(fp)
        records.append(
            PeerCertRecord(
                wire_index=index,
                descriptor=describe(cert),
                duplicate_of=duplicate_of,
                issuer_dn=_dn_string(cert, issuer=True),
                subject_dn=_dn_string(cert),
            )
        )

    leaf_cert = find_leaf(peer_certs)
    order_ok, notes = _check_order(peer_certs)
    return PeerMessageAnalysis(
        ordered=records,
        leaf_fingerprint=fingerprint(leaf_cert) if leaf_cert else None,
        duplicate_fingerprints=duplicates,
        embedded_self_signed_roots=embedded_roots,
        order_matches_chain=order_ok,
        order_notes=notes,
    )


def find_leaf(peer_certs: Iterable[crypto.X509]) -> crypto.X509 | None:
    """The leaf is the only cert whose subject never issues another one."""
    peer_certs = list(peer_certs)
    issuer_dns = {
        _issuer_der(cert): None for cert in peer_certs
    }
    candidates = [
        cert
        for cert in peer_certs
        if _subject_der(cert) not in issuer_dns
    ]
    if len(candidates) == 1:
        return candidates[0]
    # Fallback: first end-entity on the wire.
    for cert in peer_certs:
        if not is_ca(cert):
            return cert
    return peer_certs[0] if peer_certs else None


def _check_order(
    peer_certs: list[crypto.X509],
) -> tuple[bool, list[str]]:
    """Greedily walk leaf -> issuer and compare against the wire order."""
    if not peer_certs:
        return True, ["empty peer message"]
    leaf = find_leaf(peer_certs)
    if leaf is None:
        return False, ["no leaf certificate found"]

    by_subject: dict[bytes, list[crypto.X509]] = {}
    for cert in peer_certs:
        by_subject.setdefault(_subject_der(cert), []).append(cert)

    chain_order: list[str] = [fingerprint(leaf)]
    current = leaf
    visited = {fingerprint(leaf)}
    while not is_self_signed(current):
        issuers = by_subject.get(_issuer_der(current), [])
        issuers = [c for c in issuers if fingerprint(c) not in visited]
        if not issuers:
            break
        nxt = issuers[0]
        chain_order.append(fingerprint(nxt))
        visited.add(fingerprint(nxt))
        current = nxt

    wire_order = [fingerprint(c) for c in peer_certs]
    filtered_wire = [fp for fp in wire_order if fp in chain_order]
    notes: list[str] = []
    if filtered_wire != chain_order:
        notes.append(
            "wire order does not follow leaf -> issuer; OpenSSL re-sorts "
            "the untrusted stack itself, but senders should emit leaf first"
        )
    extras = [fp for fp in wire_order if fp not in chain_order]
    if extras:
        notes.append(
            f"{len(extras)} extra certificate(s) not needed for the "
            "issuer walk (cross-signed alternatives, duplicates or roots)"
        )
    return filtered_wire == chain_order, notes


# ---------------------------------------------------------------------------
# Local trust store (anchors come only from here)
# ---------------------------------------------------------------------------
@dataclass
class TrustStore:
    """A named set of explicit trust anchors."""

    name: str
    anchors: list[crypto.X509]
    partial_chain_enabled: bool = False

    def build(self) -> crypto.X509Store:
        store = crypto.X509Store()
        # Default flags leave PARTIAL_CHAIN *off*: a self-signed certificate
        # presented by the peer can never become an anchor by being sent.
        store.set_flags(0)
        for anchor in self.anchors:
            store.add_cert(anchor)
        return store

    @property
    def anchor_fingerprints(self) -> set[str]:
        return {fingerprint(c) for c in self.anchors}


# ---------------------------------------------------------------------------
# Verification report model
# ---------------------------------------------------------------------------
@dataclass
class ChainEntry:
    """One certificate of the *adopted* chain."""

    depth: int
    source: str  # "local-trust-anchor" | "peer-supplied"
    descriptor: CertDescriptor


@dataclass
class FailureDiagnosis:
    """Authoritative OpenSSL failure plus topology-only diagnostics."""

    error_code: int
    error_code_name: str
    depth: int
    message: str
    failing_cert: CertDescriptor | None
    missing_issuer_for_subject: str | None
    terminates_at_untrusted_self_signed: bool
    note: str


@dataclass
class VerificationReport:
    """The full structured verdict. ``status`` is binary, never partial."""

    trust_store_name: str
    status: str  # "trusted" | "untrusted" — there is no third value
    partial_chain_enabled: bool
    peer_message: dict
    trust_anchors: list[CertDescriptor]
    verified_chain: list[ChainEntry] = field(default_factory=list)
    alternative_branches_not_adopted: list[CertDescriptor] = field(
        default_factory=list
    )
    failure: FailureDiagnosis | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _topology_diagnosis(
    peer_certs: list[crypto.X509],
    store: TrustStore,
) -> tuple[str | None, bool]:
    """Walk issuer links across peer certs + anchors (no crypto, topology)."""
    pool = list(peer_certs) + list(store.anchors)
    by_subject: dict[bytes, list[crypto.X509]] = {}
    for cert in pool:
        by_subject.setdefault(_subject_der(cert), []).append(cert)

    leaf = find_leaf(peer_certs)
    if leaf is None:
        return None, False
    current = leaf
    visited = {fingerprint(current)}
    while not is_self_signed(current):
        issuers = [
            c
            for c in by_subject.get(_issuer_der(current), [])
            if fingerprint(c) not in visited
        ]
        if not issuers:
            return _dn_string(current, issuer=True), False
        current = issuers[0]
        visited.add(fingerprint(current))

    untrusted = is_self_signed(current) and (
        fingerprint(current) not in store.anchor_fingerprints
    )
    return None, untrusted


def verify_chain(
    peer_certs: list[crypto.X509],
    store: TrustStore,
) -> VerificationReport:
    """Verify one peer message against one trust store and report fully."""
    peer_analysis = analyze_peer_message(peer_certs)
    peer_by_fp = {fingerprint(c): c for c in peer_certs}
    leaf = find_leaf(peer_certs)

    anchors = [describe(anchor) for anchor in store.anchors]
    report = VerificationReport(
        trust_store_name=store.name,
        status="untrusted",
        partial_chain_enabled=store.partial_chain_enabled,
        peer_message=asdict(peer_analysis),
        trust_anchors=anchors,
    )

    for fp in peer_analysis.embedded_self_signed_roots:
        if fp in store.anchor_fingerprints:
            report.warnings.append(
                "peer re-sent a trust anchor; the local copy, not the "
                "wire copy, remains the authority"
            )
        else:
            report.warnings.append(
                "peer sent a self-signed root that is NOT in the trust "
                "store; it is treated as ordinary untrusted input"
            )

    if leaf is None:
        report.failure = FailureDiagnosis(
            error_code=-1,
            error_code_name="LOCAL_EMPTY_INPUT",
            depth=-1,
            message="no certificates in peer message",
            failing_cert=describe(peer_certs[0]) if peer_certs else None,
            missing_issuer_for_subject=None,
            terminates_at_untrusted_self_signed=False,
            note="nothing to verify",
        )
        return report

    # Everything except the leaf is passed as an untrusted building set.
    untrusted = [c for c in peer_certs if fingerprint(c) != fingerprint(leaf)]
    context = crypto.X509StoreContext(store.build(), leaf, untrusted)

    try:
        adopted = context.get_verified_chain()
    except crypto.X509StoreContextError as exc:
        code, depth, message = exc.errors
        missing_subject, untrusted_root_end = _topology_diagnosis(
            peer_certs, store
        )
        report.failure = FailureDiagnosis(
            error_code=code,
            error_code_name=code_name(code),
            depth=depth,
            message=message,
            failing_cert=describe(exc.certificate),
            missing_issuer_for_subject=missing_subject,
            terminates_at_untrusted_self_signed=untrusted_root_end,
            note=(
                "diagnostic only; no chain is marked trusted and no "
                "partial-trust state is produced"
            ),
        )
        return report

    # Success: report *only* the chain OpenSSL actually validated.
    adopted_fps: set[str] = set()
    for depth, cert in enumerate(adopted):
        fp = fingerprint(cert)
        adopted_fps.add(fp)
        if fp in store.anchor_fingerprints:
            source = "local-trust-anchor"
        elif fp in peer_by_fp:
            source = "peer-supplied"
        else:
            source = "resolved-locally"
        report.verified_chain.append(
            ChainEntry(depth=depth, source=source, descriptor=describe(cert))
        )
    report.status = "trusted"

    # Cross-signed alternatives present on the wire but not in the adopted
    # chain are listed explicitly so they can never be confused with it.
    for cert in peer_certs:
        fp = fingerprint(cert)
        if fp not in adopted_fps and is_ca(cert):
            report.alternative_branches_not_adopted.append(describe(cert))

    return report
