"""Tests for the chain-verification diagnostic example.

These pin down the security-relevant invariants rather than implementation
details:

* a self-signed root supplied by the peer can never become a trust anchor;
* the verdict is binary (trusted/untrusted), never "partially trusted";
* on success only the actually-adopted chain is reported, while unused
  cross-signed branches stay clearly labelled as not adopted;
* one identical wire message yields two distinct, individually-verified
  paths under two different trust stores.
"""

from __future__ import annotations

import os
import sys

import pytest
from cryptography import x509

sys.path.insert(0, os.path.dirname(__file__))

from chain_diagnostic import (  # noqa: E402
    TrustStore,
    analyze_peer_message,
    fingerprint,
    is_self_signed,
    verify_chain,
)
from pki_factory import build_pki, to_openssl  # noqa: E402
from run_scenarios import assert_scenario, build_scenarios  # noqa: E402


@pytest.fixture(scope="module")
def pki():
    return build_pki()


@pytest.fixture(scope="module")
def certs(pki):
    return {
        "leaf": to_openssl(pki.leaf),
        "expired_leaf": to_openssl(pki.expired_leaf),
        "ix_a": to_openssl(pki.inter_x_by_a),
        "ix_b": to_openssl(pki.inter_x_by_b),
        "root_a": to_openssl(pki.root_a),
        "root_b": to_openssl(pki.root_b),
        "rogue": to_openssl(pki.rogue_root),
    }


def test_cross_signed_inters_share_subject_and_key(pki):
    a = pki.inter_x_by_a
    b = pki.inter_x_by_b
    assert a.subject == b.subject
    assert a.public_key().public_numbers() == b.public_key().public_numbers()
    assert a.issuer == pki.root_a.subject
    assert b.issuer == pki.root_b.subject
    # Distinct certificates: serial and authority key identifier differ.
    assert a.serial_number != b.serial_number
    aki_a = a.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier
    ).value.key_identifier
    aki_b = b.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier
    ).value.key_identifier
    assert aki_a != aki_b


def test_roots_are_self_signed(certs):
    for name in ("root_a", "root_b", "rogue"):
        assert is_self_signed(certs[name])


def test_peer_analysis_flags_duplicates_and_order(certs):
    analysis = analyze_peer_message(
        [certs["leaf"], certs["ix_a"], certs["ix_a"]]
    )
    assert analysis.duplicate_fingerprints == [fingerprint(certs["ix_a"])]
    assert analysis.leaf_fingerprint == fingerprint(certs["leaf"])
    assert [r.wire_index for r in analysis.ordered] == [0, 1, 2]
    assert analysis.ordered[2].duplicate_of == 1

    shuffled = analyze_peer_message([certs["ix_a"], certs["leaf"]])
    assert shuffled.order_matches_chain is False


def test_peer_self_signed_root_is_not_an_anchor(certs):
    empty_store = TrustStore("empty", [])
    report = verify_chain(
        [certs["leaf"], certs["ix_a"], certs["root_a"]], empty_store
    )
    assert report.status == "untrusted"
    assert report.verified_chain == []
    assert report.failure is not None
    assert (
        report.failure.error_code_name
        == "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN"
    )
    assert report.failure.depth == 2
    assert report.failure.terminates_at_untrusted_self_signed is True


def test_rogue_root_does_not_change_trusted_path(certs):
    store = TrustStore("a", [certs["root_a"]])
    report = verify_chain(
        [certs["leaf"], certs["ix_a"], certs["rogue"]], store
    )
    assert report.status == "trusted"
    assert report.verified_chain[-1].descriptor.fingerprint == fingerprint(
        certs["root_a"]
    )
    alt_fps = {a.fingerprint for a in report.alternative_branches_not_adopted}
    assert fingerprint(certs["rogue"]) in alt_fps


def test_missing_intermediate_is_untrusted_without_partial_state(certs):
    store = TrustStore("a", [certs["root_a"]])
    report = verify_chain([certs["leaf"]], store)
    assert report.status == "untrusted"
    assert report.verified_chain == []
    assert report.failure.depth == 0
    assert (
        report.failure.error_code_name
        == "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY"
    )
    assert report.failure.missing_issuer_for_subject == "CN=Intermediate X"


def test_expired_leaf_fails_at_depth_zero(certs):
    store = TrustStore("a", [certs["root_a"]])
    report = verify_chain([certs["expired_leaf"], certs["ix_a"]], store)
    assert report.status == "untrusted"
    assert report.failure.depth == 0
    assert report.failure.error_code_name == "X509_V_ERR_CERT_HAS_EXPIRED"


def test_same_input_two_stores_two_verified_paths(certs):
    same_message = [certs["leaf"], certs["ix_a"], certs["ix_b"]]
    store_a = TrustStore("A", [certs["root_a"]])
    store_b = TrustStore("B", [certs["ix_b"], certs["root_b"]])

    report_a = verify_chain(same_message, store_a)
    report_b = verify_chain(same_message, store_b)

    assert report_a.status == report_b.status == "trusted"
    assert (
        report_a.peer_message["ordered"] == report_b.peer_message["ordered"]
    )

    root_a = report_a.verified_chain[-1]
    root_b = report_b.verified_chain[-1]
    assert root_a.descriptor.fingerprint == fingerprint(certs["root_a"])
    assert root_b.descriptor.fingerprint == fingerprint(certs["root_b"])
    assert (
        root_a.descriptor.fingerprint != root_b.descriptor.fingerprint
    )

    inter_a = report_a.verified_chain[1]
    inter_b = report_b.verified_chain[1]
    assert inter_a.source == "peer-supplied"
    assert inter_b.source == "local-trust-anchor"
    assert (
        inter_a.descriptor.fingerprint != inter_b.descriptor.fingerprint
    )

    # The branch not adopted must never be presented as the final chain.
    adopted_a = {e.descriptor.fingerprint for e in report_a.verified_chain}
    assert fingerprint(certs["ix_b"]) not in adopted_a
    adopted_b = {e.descriptor.fingerprint for e in report_b.verified_chain}
    assert fingerprint(certs["ix_a"]) not in adopted_b
    alt_a = {a.fingerprint for a in report_a.alternative_branches_not_adopted}
    alt_b = {a.fingerprint for a in report_b.alternative_branches_not_adopted}
    assert fingerprint(certs["ix_b"]) in alt_a
    assert fingerprint(certs["ix_a"]) in alt_b


def test_root_only_store_no_backtracking_is_diagnostic_only(certs):
    store = TrustStore("root-b-only", [certs["root_b"]])
    report = verify_chain(
        [certs["leaf"], certs["ix_a"], certs["ix_b"]], store
    )
    assert report.status == "untrusted"
    assert report.verified_chain == []
    assert report.failure.depth == 1
    assert (
        report.failure.error_code_name
        == "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY"
    )


def test_every_documented_scenario_matches_its_assertions(pki):
    for scenario in build_scenarios(pki):
        report = verify_chain(scenario.peer, scenario.store)
        assert assert_scenario(scenario, report) == []
