"""Build a small local PKI with a cross-signing branch, entirely offline.

Topology
--------
Two independent self-signed roots (two *trust stores* will pick one each)::

    root-A (self-signed, CN=Root A)          root-B (self-signed, CN=Root B)
        |                                        |
        | signs                                  | cross-signs the SAME
        v                                        v intermediate key/name
    inter-X (CN=Intermediate X, key Kx) -------+
        |
        | signs
        v
      leaf (CN=example.test)

``inter-X`` exists as two distinct certificates that share one subject name
and one public key (Kx):

* ``inter_x_by_a`` is signed by Root A (AKI points at Root A).
* ``inter_x_by_b`` is signed by Root B (AKI points at Root B).

This is the classic cross-sign / alternative-issuer setup.  A verifier can
reach the leaf through either certificate, but the *adopted* branch depends
solely on which root the local trust store contains.  An extra untrusted
root (``rogue-root``) and an expired leaf are generated for the negative
cases.

Only the public material matters for chain building; the private keys are
kept here so the demo can sign new test fixtures without a network.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from OpenSSL import crypto

_ONE_DAY = _dt.timedelta(days=1)


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def generate_key() -> ec.EllipticCurvePrivateKey:
    """Return a fresh P-256 private key."""
    return ec.generate_private_key(ec.SECP256R1())


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _ski(extension: x509.ExtensionType | None) -> x509.SubjectKeyIdentifier:
    if isinstance(extension, x509.SubjectKeyIdentifier):
        return extension
    raise ValueError("issuer certificate lacks a subjectKeyIdentifier")


def _build_certificate(
    *,
    subject_name: x509.Name,
    subject_key,
    issuer_name: x509.Name,
    issuer_key,
    issuer_ski: bytes,
    is_ca: bool,
    path_length: int | None,
    not_before: _dt.datetime,
    not_after: _dt.datetime,
    san: str | None = None,
) -> x509.Certificate:
    """Sign a certificate; centralises every extension the demo relies on."""
    subject_ski = x509.SubjectKeyIdentifier.from_public_key(
        subject_key.public_key()
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(subject_ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier(issuer_ski)
            ),
            critical=False,
        )
    )

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(
                ca=True, path_length=path_length
            ),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        if san is not None:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(san)]),
                critical=False,
            )

    return builder.sign(issuer_key, hashes.SHA256())


def create_root(common_name: str) -> x509.Certificate:
    """Create a self-signed root CA (key lives in the returned bundle)."""
    key = generate_key()
    now = _now()
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _ONE_DAY)
        .not_valid_after(now + 3650 * _ONE_DAY)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ski
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def create_intermediate(
    common_name: str,
    issuer: x509.Certificate,
    issuer_key,
    *,
    path_length: int = 0,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Create a fresh intermediate CA signed by ``issuer``."""
    key = generate_key()
    now = _now()
    cert = _build_certificate(
        subject_name=_name(common_name),
        subject_key=key,
        issuer_name=issuer.subject,
        issuer_key=issuer_key,
        issuer_ski=_ski(issuer.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value).digest,
        is_ca=True,
        path_length=path_length,
        not_before=now - _ONE_DAY,
        not_after=now + 1825 * _ONE_DAY,
    )
    return cert, key


def cross_sign(
    subject: x509.Certificate,
    subject_key,
    new_issuer: x509.Certificate,
    new_issuer_key,
) -> x509.Certificate:
    """Re-issue ``subject`` under ``new_issuer``, reusing name + public key.

    The returned certificate has a new serial, validity window and
    authorityKeyIdentifier (pointing at the new issuer) but the same subject
    name and subject public key, so it can impersonate no other entity while
    offering an alternative path to the same key.
    """
    now = _now()
    return _build_certificate(
        subject_name=subject.subject,
        subject_key=subject_key,
        issuer_name=new_issuer.subject,
        issuer_key=new_issuer_key,
        issuer_ski=_ski(new_issuer.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value).digest,
        is_ca=True,
        path_length=0,
        not_before=now - _ONE_DAY,
        not_after=now + 1825 * _ONE_DAY,
    )


def create_leaf(
    common_name: str,
    issuer: x509.Certificate,
    issuer_key,
    *,
    san: str | None = None,
    expired: bool = False,
    not_yet_valid: bool = False,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Create an end-entity certificate."""
    key = generate_key()
    now = _now()
    if expired:
        not_before, not_after = now - 60 * _ONE_DAY, now - _ONE_DAY
    elif not_yet_valid:
        not_before, not_after = now + 30 * _ONE_DAY, now + 365 * _ONE_DAY
    else:
        not_before, not_after = now - _ONE_DAY, now + 365 * _ONE_DAY
    cert = _build_certificate(
        subject_name=_name(common_name),
        subject_key=key,
        issuer_name=issuer.subject,
        issuer_key=issuer_key,
        issuer_ski=_ski(issuer.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value).digest,
        is_ca=False,
        path_length=None,
        not_before=not_before,
        not_after=not_after,
        san=san or common_name,
    )
    return cert, key


def to_openssl(cert: x509.Certificate) -> crypto.X509:
    """Bridge a cryptography certificate to a pyOpenSSL X509."""
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return crypto.load_certificate(crypto.FILETYPE_PEM, pem)


@dataclass(frozen=True)
class PKI:
    """Every certificate the scenarios need, grouped by role."""

    root_a: x509.Certificate
    root_a_key: ec.EllipticCurvePrivateKey
    root_b: x509.Certificate
    root_b_key: ec.EllipticCurvePrivateKey
    rogue_root: x509.Certificate
    rogue_root_key: ec.EllipticCurvePrivateKey
    inter_x_by_a: x509.Certificate
    inter_x_by_b: x509.Certificate
    inter_x_key: ec.EllipticCurvePrivateKey
    leaf: x509.Certificate
    leaf_key: ec.EllipticCurvePrivateKey
    expired_leaf: x509.Certificate
    expired_leaf_key: ec.EllipticCurvePrivateKey


def build_pki() -> PKI:
    """Generate the complete cross-signed PKI from scratch."""
    root_a, root_a_key = create_root("Root A")
    root_b, root_b_key = create_root("Root B")
    rogue_root, rogue_root_key = create_root("Rogue Root (untrusted)")

    inter_x_by_a, inter_x_key = create_intermediate(
        "Intermediate X", root_a, root_a_key
    )
    # Same subject name and key Kx, but issued by Root B.
    inter_x_by_b = cross_sign(
        inter_x_by_a, inter_x_key, root_b, root_b_key
    )

    leaf, leaf_key = create_leaf(
        "example.test", inter_x_by_a, inter_x_key, san="example.test"
    )
    expired_leaf, expired_leaf_key = create_leaf(
        "expired.example.test",
        inter_x_by_a,
        inter_x_key,
        san="expired.example.test",
        expired=True,
    )
    return PKI(
        root_a=root_a,
        root_a_key=root_a_key,
        root_b=root_b,
        root_b_key=root_b_key,
        rogue_root=rogue_root,
        rogue_root_key=rogue_root_key,
        inter_x_by_a=inter_x_by_a,
        inter_x_by_b=inter_x_by_b,
        inter_x_key=inter_x_key,
        leaf=leaf,
        leaf_key=leaf_key,
        expired_leaf=expired_leaf,
        expired_leaf_key=expired_leaf_key,
    )
