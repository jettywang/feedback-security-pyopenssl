"""Exercise every diagnostic scenario against the generated cross-signed PKI.

Run with::

    python examples/chain_verification_diagnostic/run_scenarios.py

Each scenario states its expected verdict up front and asserts against the
real pyOpenSSL result, so the output cannot drift into a misleading
"partially trusted" report.

The headline demonstration is scenarios 4 and 5: one identical wire message
is fed to two different trust stores and yields two different adopted paths,
each backed by an actual successful pyOpenSSL verification.  Real-world
trust stores often ship cross-signed intermediates alongside their roots, so
store B is modelled with its own cross-certificate installed locally; the
verifier then prefers its trusted copy (trusted-first) regardless of the
order in which the peer lists the alternatives.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

import pki_factory
from chain_diagnostic import TrustStore, fingerprint, verify_chain
from pki_factory import build_pki, to_openssl


@dataclass
class Scenario:
    name: str
    peer: object  # list of pyOpenSSL X509
    store: TrustStore
    expect_status: str
    expect_root_fp: str | None = None
    expect_error_name: str | None = None
    expect_error_depth: int | None = None
    expect_adopted_inter_source: str | None = None


def _x(cert):
    return to_openssl(cert)


def build_scenarios(pki: pki_factory.PKI):
    leaf = _x(pki.leaf)
    expired_leaf = _x(pki.expired_leaf)
    ix_a = _x(pki.inter_x_by_a)
    ix_b = _x(pki.inter_x_by_b)
    root_a = _x(pki.root_a)
    root_b = _x(pki.root_b)
    rogue = _x(pki.rogue_root)

    # Trust stores: anchors are the ONLY source of trust.
    store_a = TrustStore("store-A {Root A}", [root_a])
    # Realistic store: ships the Root B cross-certificate plus Root B.
    store_b = TrustStore("store-B {Inter X(B) + Root B}", [ix_b, root_b])
    store_root_b_only = TrustStore("store-B-root-only {Root B}", [root_b])
    store_empty = TrustStore("store-empty {no anchors}", [])
    store_ab = TrustStore("store-AB {Root A + Root B}", [root_a, root_b])

    # One identical wire message for the two-store divergence proof.
    same_message = [leaf, ix_a, ix_b]

    return [
        Scenario(
            "1. canonical order leaf -> intermediate, anchor present",
            [leaf, ix_a],
            store_a,
            "trusted",
            expect_root_fp=fingerprint(root_a),
        ),
        Scenario(
            "2. shuffled order (intermediate before leaf) still verifies",
            [ix_a, leaf],
            store_a,
            "trusted",
            expect_root_fp=fingerprint(root_a),
        ),
        Scenario(
            "3. duplicated intermediate (identical certificate twice)",
            [leaf, ix_a, ix_a],
            store_a,
            "trusted",
            expect_root_fp=fingerprint(root_a),
        ),
        Scenario(
            "4. SAME input under store-A -> Root A path, inter from peer",
            same_message,
            store_a,
            "trusted",
            expect_root_fp=fingerprint(root_a),
            expect_adopted_inter_source="peer-supplied",
        ),
        Scenario(
            "5. SAME input under store-B -> Root B path, inter from store",
            same_message,
            store_b,
            "trusted",
            expect_root_fp=fingerprint(root_b),
            expect_adopted_inter_source="local-trust-anchor",
        ),
        Scenario(
            "6. missing intermediate, leaf only -> untrusted at depth 0",
            [leaf],
            store_a,
            "untrusted",
            expect_error_name="X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
            expect_error_depth=0,
        ),
        Scenario(
            "7. peer self-signed root, empty store -> never an anchor",
            [leaf, ix_a, root_a],
            store_empty,
            "untrusted",
            expect_error_name="X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN",
            expect_error_depth=2,
        ),
        Scenario(
            "8. rogue self-signed root mixed into a chain that still "
            "verifies",
            [leaf, ix_a, rogue],
            store_a,
            "trusted",
            expect_root_fp=fingerprint(root_a),
        ),
        Scenario(
            "9. expired leaf -> untrusted, failure at depth 0",
            [expired_leaf, ix_a],
            store_a,
            "untrusted",
            expect_error_name="X509_V_ERR_CERT_HAS_EXPIRED",
            expect_error_depth=0,
        ),
        Scenario(
            "10. root-only store, cross branch not locally resolvable -> "
            "diagnostic only, no backtracking, no partial trust",
            same_message,
            store_root_b_only,
            "untrusted",
            expect_error_name="X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
            expect_error_depth=1,
        ),
        Scenario(
            "11. both roots trusted: one adopted chain, other branch listed "
            "as not adopted",
            same_message,
            store_ab,
            "trusted",
            expect_root_fp=fingerprint(root_a),
        ),
    ]


def _adopted_root(report):
    if not report.verified_chain:
        return None
    return report.verified_chain[-1].descriptor.fingerprint


def _adopted_inter_source(report):
    if len(report.verified_chain) < 2:
        return None
    return report.verified_chain[1].source


def assert_scenario(scenario, report):
    errors = []
    if report.status != scenario.expect_status:
        errors.append(
            f"status {report.status!r} != expected "
            f"{scenario.expect_status!r}"
        )
    if scenario.expect_root_fp is not None and (
        _adopted_root(report) != scenario.expect_root_fp
    ):
        errors.append("adopted root does not match expected trust anchor")
    if (
        scenario.expect_adopted_inter_source is not None
        and _adopted_inter_source(report)
        != scenario.expect_adopted_inter_source
    ):
        errors.append(
            f"intermediate source "
            f"{_adopted_inter_source(report)!r} != expected "
            f"{scenario.expect_adopted_inter_source!r}"
        )
    if scenario.expect_error_name is not None:
        if report.failure is None:
            errors.append("expected a failure diagnosis but none was produced")
        else:
            if report.failure.error_code_name != scenario.expect_error_name:
                errors.append(
                    f"error {report.failure.error_code_name!r} != "
                    f"expected {scenario.expect_error_name!r}"
                )
            if (
                scenario.expect_error_depth is not None
                and report.failure.depth != scenario.expect_error_depth
            ):
                errors.append(
                    f"depth {report.failure.depth} != "
                    f"expected {scenario.expect_error_depth}"
                )
    if report.status == "untrusted" and report.verified_chain:
        errors.append("untrusted verdict must not carry an adopted chain")
    if report.status not in {"trusted", "untrusted"}:
        errors.append("only binary trusted/untrusted verdicts are allowed")
    return errors


def main():
    pki = build_pki()
    scenarios = build_scenarios(pki)
    all_reports = []
    print("=" * 78)
    for scenario in scenarios:
        report = verify_chain(scenario.peer, scenario.store)
        all_reports.append(
            {"scenario": scenario.name, "report": report.to_dict()}
        )
        problems = assert_scenario(scenario, report)
        print(f"[{'PASS' if not problems else 'FAIL'}] {scenario.name}")
        print(
            f"       verdict={report.status} "
            f"store={report.trust_store_name}"
        )
        if report.verified_chain:
            chain = " -> ".join(
                f"{entry.descriptor.common_name}"
                f"[{entry.source.split('-')[0]}]"
                for entry in report.verified_chain
            )
            print(f"       adopted: {chain}")
        for alt in report.alternative_branches_not_adopted:
            print(
                f"       alternative NOT adopted: {alt.common_name} "
                f"issued-by {alt.issuer}"
            )
        if report.failure:
            failure = report.failure
            print(
                f"       failure depth={failure.depth} "
                f"{failure.error_code_name}: {failure.message}"
            )
            print(
                f"       topology: missing_issuer="
                f"{failure.missing_issuer_for_subject} "
                f"untrusted_self_signed_end="
                f"{failure.terminates_at_untrusted_self_signed}"
            )
        for warning in report.warnings:
            print(f"       warning: {warning}")
        for problem in problems:
            print(f"       ASSERTION: {problem}")
        print("-" * 78)

    # Scenarios 4 & 5 must prove two distinct adopted paths from one input.
    r4 = all_reports[3]["report"]
    r5 = all_reports[4]["report"]
    root4 = r4["verified_chain"][-1]["descriptor"]["fingerprint"]
    root5 = r5["verified_chain"][-1]["descriptor"]["fingerprint"]
    inter4 = r4["verified_chain"][1]
    inter5 = r5["verified_chain"][1]
    same_input = (
        r4["peer_message"]["ordered"] == r5["peer_message"]["ordered"]
    )
    print("Same wire input for scenarios 4 & 5:", same_input)
    print(
        "store-A path: inter",
        inter4["descriptor"]["fingerprint"][:12],
        f"({inter4['source']}) -> root",
        root4[:12],
    )
    print(
        "store-B path: inter",
        inter5["descriptor"]["fingerprint"][:12],
        f"({inter5['source']}) -> root",
        root5[:12],
    )
    assert same_input, "the divergence demonstration must share one input"
    assert root4 != root5, "expected two different adopted roots"
    assert (
        inter4["descriptor"]["fingerprint"]
        != inter5["descriptor"]["fingerprint"]
    ), "expected two different cross-signed intermediate certificates"
    assert all(
        assert_scenario(s, verify_chain(s.peer, s.store)) == []
        for s in scenarios
    ), "one or more scenario assertions failed"

    out_path = os.path.join(os.path.dirname(__file__),
                            "chain_verification_reports.json")
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(all_reports, handle, indent=2, ensure_ascii=False)
    print("All scenario assertions passed. JSON report ->", out_path)


if __name__ == "__main__":
    main()
