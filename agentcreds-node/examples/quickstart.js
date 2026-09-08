// Mirrors QUICKSTART.md - run in CI as a smoke test so the doc can't drift
// from the actual API. Plain CommonJS so it runs with `node` directly.
const ac = require("../index.js");

// This is your sandbox key - generated locally, instantly.
// No signup, no dashboard, no network call.
const anchor = ac.TrustAnchor.generate();

// 1. Create an agent identity
const agent = ac.AgentIdentity.createDidKey();

// 2. Issue it a credential: what it can do, and for how long
const claims = new ac.CapabilityClaims({
  tools: ["tool:search", "tool:email"],
  maxDelegationDepth: 3,
  validForSecs: 3600, // 1 hour
});
const vc = ac.CapabilityCredential.issue(anchor, agent.did, claims);

// 3. Mint a short-lived runtime token the agent carries
const scope = new ac.Scope({ tools: ["tool:search"], budgetUsd: 100, maxDepth: 2 });
const token = ac.DelegationToken.mint(vc, scope, 300, agent); // valid 5 minutes

// 4. Verify before every tool call (chain authenticity + scope)
token.verify(new ac.Action("tool:search", "q=agentcreds"));

// 4b. A relying party that holds the credential should use the complete,
// anchor-rooted check - it also proves the authority traces to the anchor.
token.verifyRooted(new ac.Action("tool:search", "q=agentcreds"), vc, anchor);

console.log("Agent issued:", agent.did);
console.log("tool:search - allowed");

// 5. Delegate to a sub-agent - scope can only narrow, never widen
const subAgent = ac.AgentIdentity.createDidKey();
const narrow = new ac.Scope({ tools: ["tool:search"], budgetUsd: 10, maxDepth: 1 });
const childToken = token.attenuate(narrow, 60, subAgent);
childToken.verify(new ac.Action("tool:search", "q=delegated"));
console.log("sub-agent delegation - allowed");

// 6. Proof of possession - the presenter proves it holds the leaf key.
// The verifier issues a challenge; the holder signs it; the verifier runs
// the complete presentation check (anchor-rooted + possession).
const challenge = new ac.PopChallenge("mcp://orders");
const proof = childToken.provePossession(challenge, subAgent);
childToken.verifyPresentation(
  new ac.Action("tool:search", "q=delegated"),
  vc, anchor, proof, challenge, 60,
);
console.log("proof of possession - verified");

// A stranger that does not hold the leaf key cannot present the token.
let forgedAccepted = false;
try {
  const stranger = ac.AgentIdentity.createDidKey();
  childToken.provePossession(challenge, stranger);
  forgedAccepted = true;
} catch (e) {
  console.log("possession by non-holder - rejected (as designed)");
}
if (forgedAccepted) {
  console.error("ERROR: non-holder produced a proof");
  process.exit(1);
}

// Widening is structurally impossible
let widened = false;
try {
  token.attenuate(new ac.Scope({ tools: ["tool:email", "tool:search"] }), 60, subAgent);
  widened = true;
} catch (e) {
  console.log("scope widening - rejected (as designed)");
}
if (widened) {
  console.error("ERROR: scope widening was not rejected");
  process.exit(1);
}
