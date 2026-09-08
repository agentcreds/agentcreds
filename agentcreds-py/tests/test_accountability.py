"""Accountability across the Python binding: who answers for what an agent does.

The organization is always accountable - its anchor signed the credential, and that is
enforced cryptographically. These cover the layer below it: the responsible party
*within* the organization, and which kind of principal was behind the agent.

Checked here, not only in the Rust core, because a Python relying party sees the
credential through this binding and nothing else. A field that exists in core but stops
at the FFI boundary is, to that party, a field that does not exist.

Run:  pytest tests/test_accountability.py
"""

import datetime as dt

import agentcreds as ac


def _claims(**kw):
    return ac.CapabilityClaims(
        tools=["tool:pay"], max_delegation_depth=1, valid_for_secs=3600, **kw
    )


def _principal(kind=None):
    kwargs = {} if kind is None else {"kind": kind}
    return ac.HumanAuthorization(
        principal_did="did:web:acme.example:w:abc",
        issuer="acme.example",
        subject="spiffe://acme.example/payments",
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1),
        **kwargs,
    )


def test_accountable_party_crosses_the_binding():
    assert _claims(accountable_party="team:settlement").accountable_party == "team:settlement"


def test_absent_accountable_party_is_representable():
    # Absence means "issued before accountability was recorded", never "no one is
    # responsible" - the issuing organization is accountable either way. It has to be
    # distinguishable from a named party, or a reader cannot tell those two apart.
    assert _claims().accountable_party is None


def test_accountable_party_survives_signing_and_verification():
    # The claim has to reach a *verifier*, not just a constructor. Signing canonicalizes
    # the claims, so a field the serialiser drops would still pass an in-memory check.
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    vc = ac.CapabilityCredential.issue(
        anchor, agent.did, _claims(accountable_party="team:settlement")
    )
    vc.verify(anchor)
    assert vc.claims().accountable_party == "team:settlement"

    parsed = ac.CapabilityCredential.from_json(vc.to_json())
    parsed.verify(anchor)
    assert parsed.claims().accountable_party == "team:settlement", "lost in the wire format"


def test_a_workload_principal_stays_a_workload():
    # The two populations must remain distinguishable. Were the kind dropped here, a
    # Python verifier would read every service-initiated agent as human-delegated -
    # the exact confusion the kind exists to prevent.
    assert _principal("workload").kind == "workload"
    # Omitted means human, so credentials written before workloads could be principals
    # read back unchanged.
    assert _principal().kind == "human"


def test_an_unknown_principal_kind_is_refused_not_defaulted():
    # Defaulting would report an unrecognised kind as human - a silent misattribution
    # of which root attested the binding.
    try:
        _principal("Workload")  # wrong case: the wire token is lowercase
    except ValueError as e:
        assert "unknown principal kind" in str(e), e
    else:
        raise AssertionError("an unknown principal kind was accepted")
    assert _principal("workload").kind == "workload", "control"


def test_the_decision_record_answers_who_is_answerable():
    # The ADR is what a SIEM sink forwards. Reconstructing accountability used to mean
    # joining back to the credential; the point of the field is that it no longer does.
    d = ac.AuthzDecision.allow("verify_rooted", "did:key:zA")
    assert d.accountable_party is None
    assert d.principal_did is None
    assert "accountable_party" not in d.to_json(), "absent fields must not be emitted"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all accountability binding tests passed")


# -- Provenance: how firmly each bound is known --------------------------------
#
# `AuthoritySource` is one vocabulary used wherever the question "where did this come
# from?" arises - on the principal's entitlements and on the accountable party. It exists
# because the weight an auditor gives a claim depends entirely on its origin, and that
# origin is otherwise invisible.


def test_the_entitlement_source_crosses_the_binding():
    # The label is why the second axis can be trusted at all. Read the entitlements
    # without their source and a verifier must assume the strongest reading - while
    # "asserted", the weakest, is the case worth noticing.
    assert _principal("workload").entitlement_source == "asserted", "unstated means weakest"

    p = ac.HumanAuthorization(
        principal_did="did:web:acme.example:w:abc",
        issuer="acme.example",
        subject="spiffe://acme.example/payments",
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1),
        kind="workload",
        entitlement_source="policy",
    )
    assert p.entitlement_source == "policy"


def test_an_unknown_authority_source_is_refused_not_defaulted():
    # Defaulting would silently downgrade a source this build does not understand, and an
    # auditor would see evidence weaken for no reason.
    try:
        ac.HumanAuthorization(
            principal_did="did:web:acme.example:w:abc",
            issuer="acme.example",
            subject="spiffe://acme.example/payments",
            expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1),
            entitlement_source="Attested",  # wrong case: the wire token is lowercase
        )
    except ValueError as e:
        assert "unknown authority source" in str(e), e
    else:
        raise AssertionError("an unknown authority source was accepted")


def test_claims_report_how_firmly_the_party_is_known():
    # Who answers and on what basis are one question in an audit; splitting them across
    # two artifacts invites reading the first without the second.
    assert _claims(accountable_party="team:settlement").accountability_source == "asserted"


def test_an_identity_can_state_its_entitlement_source():
    ident = ac.HumanIdentity.from_spiffe("spiffe://acme.example/payments/settlement")
    auth = ident.authorize(
        dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1),
        ["tool:pay"],
        ["ledger:payments/*"],
        "policy",
    )
    assert auth.entitlement_source == "policy"
    assert auth.kind == "workload"
