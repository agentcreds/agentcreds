# Mirrors QUICKSTART.md - run in CI as a smoke test so the doc can't drift
# from the actual API.
import agentcreds as ac

# This is your sandbox key - generated locally, instantly.
# No signup, no dashboard, no network call.
anchor = ac.TrustAnchor.generate()

# 1. Create an agent identity
agent = ac.AgentIdentity.create_did_key()

# 2. Issue it a credential: what it can do, and for how long
claims = ac.CapabilityClaims(
    tools=["tool:search", "tool:email"],
    max_delegation_depth=3,
    valid_for_secs=3600,  # 1 hour
)
vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)

# 3. Mint a short-lived runtime token the agent carries
scope = ac.Scope(tools=["tool:search"], budget_usd=100, max_depth=2)
token = ac.DelegationToken.mint(vc, scope, 300, agent)  # valid 5 minutes

# 4. Verify before every tool call (chain authenticity + scope)
token.verify(ac.Action("tool:search", "q=agentcreds"))

# 4b. A relying party that holds the credential should use the complete,
# anchor-rooted check - it also proves the authority traces to the anchor.
token.verify_rooted(ac.Action("tool:search", "q=agentcreds"), vc, anchor)

print("Agent issued:", agent.did)
print("tool:search - allowed")

# 5. Delegate to a sub-agent - scope can only narrow, never widen
sub_agent = ac.AgentIdentity.create_did_key()
narrow = ac.Scope(tools=["tool:search"], budget_usd=10, max_depth=1)
child_token = token.attenuate(narrow, 60, sub_agent)
child_token.verify(ac.Action("tool:search", "q=delegated"))
print("sub-agent delegation - allowed")

# 6. Proof of possession - the presenter proves it holds the leaf key.
# The verifier issues a challenge; the holder signs it; the verifier runs the
# complete presentation check (anchor-rooted + possession).
challenge = ac.PopChallenge("mcp://orders")
proof = child_token.prove_possession(challenge, sub_agent)
child_token.verify_presentation(
    ac.Action("tool:search", "q=delegated"), vc, anchor, proof, challenge, 60
)
print("proof of possession - verified")

# A stranger that does not hold the leaf key cannot present the token.
try:
    stranger = ac.AgentIdentity.create_did_key()
    child_token.prove_possession(challenge, stranger)
    raise SystemExit("ERROR: non-holder produced a proof")
except ac.ProofOfPossessionError:
    print("possession by non-holder - rejected (as designed)")

# Widening is structurally impossible
try:
    token.attenuate(ac.Scope(tools=["tool:email", "tool:search"]), 60, sub_agent)
    raise SystemExit("ERROR: scope widening was not rejected")
except ac.ScopeWideningError:
    print("scope widening - rejected (as designed)")
