'use strict';

// Runtime AgentCreds agent-identity enforcement for Node - the agent-to-agent
// (A2A, no MCP server) counterpart to the Python `agentcreds_runtime.A2AVerifier`.
// Wraps the @agentcreds/sdk native bindings; every verification decision (audience,
// anchor-rooting, proof-of-possession, revocation, multi-issuer, argument binding,
// on-behalf-of, single-use replay) runs in the offline core.

const crypto = require('crypto');
const ac = require('@agentcreds/sdk');

// -- Denial codes (mirror agentcreds_runtime.errors) -----------------------------

const CODES = Object.freeze({
  MALFORMED: 'malformed_presentation',
  POSSESSION: 'possession_failed',
  NOT_AUTHORIZED: 'not_authorized',
  CREDENTIAL: 'credential_invalid',
  REVOKED: 'credential_revoked',
  PRINCIPAL: 'principal_mismatch',
  UNBOUND: 'argument_binding_required',
  UNTRUSTED_ISSUER: 'untrusted_issuer',
  REPLAY: 'replayed_presentation',
  // The holder and this verifier computed the binding over two different
  // representations. Split from POSSESSION so an operator can tell an interop defect
  // from an attack - the MCP transport has had this since -02 §1.3; A2A did not.
  CANON_PROFILE: 'canonicalization_profile_mismatch',
  // `agentcreds-octets-v1` only. Split from POSSESSION deliberately: with the holder's
  // own bytes in hand and verified, a mismatch has exactly one meaning - the arguments
  // changed in transit - where a canonicalizing profile cannot tell that from two
  // implementations disagreeing about how to write a float.
  ARGS_MISMATCH: 'argument_mismatch',
  BOUND_ARGS: 'bound_arguments_invalid',
  DENIED: 'access_denied',
});

// Node maps core errors to `Error` whose message is "<Kind>: <detail>" - classify
// on that prefix (more specific kinds first).
function classifyError(err) {
  const m = String((err && err.message) || '');
  if (m.includes('ProofOfPossessionError')) return CODES.POSSESSION;
  if (m.includes('PrincipalMismatchError')) return CODES.PRINCIPAL;
  if (m.includes('ActionDeniedError') || m.includes('ScopeWideningError')) return CODES.NOT_AUTHORIZED;
  if (
    m.includes('TokenExpiredError') || m.includes('CredentialExpiredError') ||
    m.includes('CredentialRevokedError') || m.includes('CredentialError') ||
    m.includes('DelegationError')
  ) return CODES.CREDENTIAL;
  return CODES.DENIED;
}


// -- RFC 8785 (JSON Canonicalization Scheme) ---------------------------------
//
// Argument binding hashes a STRING, so holder and verifier must produce byte-identical
// text or a legitimate call is refused. `agentcreds-json-sorted-v1` was two independent
// readings of "sorted JSON" and they disagreed on ordinary traffic:
//
//     {"q":"café"}     Node -> {"q":"café"}   Python -> {"q":"caf\u00e9"}
//     {"amount":1.0}   Node -> {"amount":1}   Python -> {"amount":1.0}
//
// JCS is a specification rather than a convention, so a fourth language can reach for a
// conformant library instead of reverse-engineering ours.
//
// JavaScript is most of the way there already, which is worth stating so nobody
// "improves" it later: `JSON.stringify` on a string emits literal UTF-8 with exactly the
// escapes RFC 8785 wants (and, since ES2019, well-formed output for lone surrogates);
// on a number it IS ECMAScript Number::toString, which is what RFC 8785 specifies; and
// `Array.prototype.sort()` on strings compares UTF-16 code units, which is the ordering
// RFC 8785 requires. The additions here are the parts it does not handle: rejecting
// values JSON cannot represent instead of silently emitting `null`, and folding `-0`.
const JCS_PROFILE = 'agentcreds-jcs-v1';

// At most one warning per top-level canonicalization: bounded (no set of seen values
// growing on the authorization path) and deterministic (no cross-call state, so a test
// can assert it without depending on what ran first). A call site that trips this on
// every request stays noisy on purpose - the hazard is present on every request, and
// the fix is to carry the identifier as a string.
let warnedThisCall = false;
function warnUnsafeInteger(v) {
  if (warnedThisCall) return;
  warnedThisCall = true;
  const message =
    `integer ${v} is outside the safe range (2^53-1), so JSON.parse already lost its ` +
    'low bits: argument binding cannot distinguish it from an adjacent value, and a ' +
    'holder in a language with exact integers will canonicalize a different number ' +
    'and be refused. Carry large identifiers as strings.';
  if (typeof process !== 'undefined' && process.emitWarning) {
    process.emitWarning(message, 'AgentCredsJcsPrecisionWarning');
  } else {
    console.warn(message); // eslint-disable-line no-console
  }
}

function jcsValue(v) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'string') return JSON.stringify(v);
  if (t === 'number') {
    if (!Number.isFinite(v)) throw new TypeError(`${v} has no JSON representation`);
    // Integral but unsafe: the value arrived already damaged, so this cannot be
    // corrected here - only reported.
    //
    // This over-approximates, unavoidably. JavaScript cannot tell the float 1e20 from
    // the exact integer 10^20, so a legitimate large float warns too even though it is
    // exactly representable and both ends agree on it. Python and Rust flag only true
    // integers and so stay quieter. Warning anyway is the point: JS-to-JS is the one
    // pairing where nothing else can notice that the binding has stopped
    // distinguishing a value from its neighbour.
    if (Number.isInteger(v) && !Number.isSafeInteger(v)) warnUnsafeInteger(v);
    return Object.is(v, -0) ? '0' : String(v);
  }
  if (Array.isArray(v)) return '[' + v.map(jcsValue).join(',') + ']';
  if (t === 'object') {
    // Default sort() is UTF-16 code-unit order - exactly RFC 8785 §3.2.3.
    const keys = Object.keys(v).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcsValue(v[k])).join(',') + '}';
  }
  // undefined, function, symbol, bigint: JSON.stringify would drop or throw
  // inconsistently. Failing here is deliberate - a canonicalizer that guesses emits a
  // string the other side cannot reproduce, which presents as tampering on a request
  // that was never tampered with.
  throw new TypeError(`${t} has no JSON representation`);
}

/**
 * The RFC 8785 canonical form of any JSON value.
 *
 * Exported because the shared fixture in `conformance/jcs_vectors.json` has scalar and
 * array cases at the top level, and all three runtimes assert against the same file -
 * Rust's `jcs::canonicalize` and Python's `jcs.canonicalize` both take any value, so
 * Node needs the same entry point or it silently checks a subset.
 */
function jcsCanonicalize(v) {
  warnedThisCall = false;
  return jcsValue(v);
}

/** Canonicalize arguments per RFC 8785. Prefer this across language boundaries. */
function jcsCanonicalizeArgs(args) {
  warnedThisCall = false;
  if (args === null || args === undefined) return '';
  if (typeof args === 'string') return args;
  return jcsValue(args);
}

// -- The carry-the-octets profile (agentcreds-octets-v1) ------------------------
//
// Canonicalization is a workaround for not having the original octets. Here the holder
// serializes however it likes, signs THOSE bytes, and carries them; the verifier checks
// the proof over the carried bytes and then compares them to what the transport
// delivered by MEANING rather than by spelling. No two implementations ever have to
// agree on how to write a float - only on what a float is, which their JSON parsers
// already do.
//
// The costs are real and deliberate: the arguments travel twice, and the second copy
// lands in a header that is often logged more casually than a body.
const OCTETS_PROFILE = 'agentcreds-octets-v1';

//: Ceiling on the carried copy. It is attacker-controlled text that has to be parsed
//: before anything is authenticated, so it cannot be unbounded.
const MAX_BOUND_ARGS_BYTES = 64 * 1024;

/** Serialize arguments on the HOLDER side, for both signing and carrying. */
function octetsBindArgs(args) {
  return JSON.stringify(args === undefined ? null : args);
}

/**
 * Parse carried octets on the VERIFIER side. Throws - this runs before anything has
 * been authenticated, so every failure has to be a refusal.
 */
function parseBoundArgs(text) {
  if (text === null || text === undefined || text === '') {
    throw new Error('no bound arguments were carried');
  }
  if (typeof text !== 'string') throw new Error(`bound arguments must be text, got ${typeof text}`);
  const size = Buffer.byteLength(text, 'utf8');
  if (size > MAX_BOUND_ARGS_BYTES) {
    throw new Error(`bound arguments are ${size} bytes, over the ${MAX_BOUND_ARGS_BYTES}-byte limit`);
  }
  // JSON.parse already rejects NaN/Infinity, so unlike Python there is nothing extra
  // to guard here.
  return JSON.parse(text);
}

/**
 * Structural equality over two parsed JSON values.
 *
 * Comparing is forgiving where emitting is not: nothing here decides how many digits a
 * float gets or which characters to escape, only whether two parsed values mean the
 * same thing. Objects compare as unordered key sets; arrays keep their order, because
 * order is meaning in JSON.
 */
function semanticEq(a, b) {
  if (a === null || b === null) return a === null && b === null;
  const ta = typeof a;
  const tb = typeof b;
  if (ta !== tb) return false;
  if (ta === 'number') return a === b;         // JSON.parse yields doubles on both sides
  if (ta === 'boolean' || ta === 'string') return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((x, i) => semanticEq(x, b[i]));
  }
  if (ta === 'object') {
    // Snapshot both sides through ONE access protocol. `Object.entries` reads each own
    // enumerable property exactly once; reading `Object.keys` and then indexing would
    // invoke a getter a second time, and an accessor that returns different values on
    // successive reads could pass this comparison and then hand the tool something else.
    const ea = Object.entries(a);
    const eb = Object.entries(b);
    if (ea.length !== eb.length) return false;
    const mb = new Map(eb);
    return ea.every(([k, v]) => mb.has(k) && semanticEq(v, mb.get(k)));
  }
  return false;
}

function deny(code, reason, tool) {
  return { allowed: false, code, reason, tool, chain: null, boundArguments: null };
}

// -- Wire envelope --------------------------------------------------------------

const A2A_HEADER_NAME = 'AgentCreds-A2A';
const A2A_PRINCIPAL_HEADER_NAME = 'AgentCreds-A2A-Principal';
const A2A_PRINCIPAL_SCHEME = 'AgentCreds-A2A-Principal/1.';
// Carries the holder's literal serialized arguments under `agentcreds-octets-v1`.
// Base64url like the principal header, so arbitrary argument text cannot inject header
// syntax. Absent under every other profile.
const A2A_BOUND_ARGS_HEADER_NAME = 'AgentCreds-A2A-Bound-Args';
// Declares the canonicalization profile the sender computed the binding under. The MCP
// transport has carried this since -02 §1.3; A2A did not, so a profile disagreement
// surfaced as possession_failed with no diagnosis.
const A2A_CANON_PROFILE_HEADER_NAME = 'AgentCreds-A2A-Canon-Profile';

function makeA2AHeader(token, credential, leafAgent, { audience, action = null } = {}) {
  let challenge = new ac.PopChallenge(audience);
  if (action) challenge = challenge.withRequestBinding(action.requestBinding());
  return ac.Presentation.create(token, credential, challenge, leafAgent).toA2AHeader();
}

function makeA2APrincipalHeader(principalToken) {
  return A2A_PRINCIPAL_SCHEME + Buffer.from(principalToken, 'utf8').toString('base64url');
}

function parseA2APrincipalHeader(value) {
  if (!value.startsWith(A2A_PRINCIPAL_SCHEME)) throw new Error('missing principal header scheme prefix');
  return Buffer.from(value.slice(A2A_PRINCIPAL_SCHEME.length), 'base64url').toString('utf8');
}

function makeA2ABoundArgsHeader(boundArguments) {
  return Buffer.from(boundArguments, 'utf8').toString('base64url');
}

function parseA2ABoundArgsHeader(value) {
  return Buffer.from(value, 'base64url').toString('utf8');
}

function makeA2AEnvelope(token, credential, leafAgent, { audience, action = null, principalToken = null, boundArguments = null, canonicalizationProfile = null } = {}) {
  const envelope = { [A2A_HEADER_NAME]: makeA2AHeader(token, credential, leafAgent, { audience, action }) };
  if (canonicalizationProfile != null) envelope[A2A_CANON_PROFILE_HEADER_NAME] = canonicalizationProfile;
  if (boundArguments != null) envelope[A2A_BOUND_ARGS_HEADER_NAME] = makeA2ABoundArgsHeader(boundArguments);
  if (principalToken != null) envelope[A2A_PRINCIPAL_HEADER_NAME] = makeA2APrincipalHeader(principalToken);
  return envelope;
}

// -- Policy helpers -------------------------------------------------------------

function anchorResolverFromRegistry(registry) {
  return (credential) => {
    try {
      registry.verifyCredential(credential);
    } catch (e) {
      return null; // unregistered, below minimum level, or bad signature
    }
    const issuer = credential.issuer;
    if (!issuer.startsWith('did:key:')) return null; // only did:key anchors here
    return ac.TrustAnchor.fromDidKey(issuer);
  };
}

function revocationCheckFromList(revList, anchor) {
  return (credential) => {
    const status = credential.credentialStatus;
    if (status == null) return false;
    revList.verify(anchor);
    return revList.isRevoked(status.statusListIndex);
  };
}

function principalResolverFromOidc(provider, { expectedAgentDid = null } = {}) {
  return (principalToken) => {
    let human;
    try {
      human = provider.validateIdToken(principalToken, expectedAgentDid);
    } catch (e) {
      return null;
    }
    return human.humanIdentity().did;
  };
}

// -- Replay guard ---------------------------------------------------------------

class InMemoryReplayGuard {
  constructor({ ttlSecs = 300 } = {}) {
    this._ttl = ttlSecs * 1000;
    this._seen = new Map();
  }
  recordIfNew(key) {
    const now = Date.now();
    if (this._seen.size > 4096) {
      for (const [k, exp] of this._seen) if (exp <= now) this._seen.delete(k);
    }
    const exp = this._seen.get(key);
    if (exp !== undefined && exp > now) return false; // still within TTL -> replay
    this._seen.set(key, now + this._ttl);
    return true;
  }
}

class RedisReplayGuard {
  // `client` exposes set(key, value, { NX, EX }) (node-redis v4) or a callable
  // compatible shim returning truthy when the key was created.
  constructor(client, { ttlSecs = 300, namespace = 'agentcreds:replay' } = {}) {
    this._r = client;
    this._ttl = ttlSecs;
    this._ns = namespace;
  }
  async recordIfNew(key) {
    const created = await this._r.set(`${this._ns}:${key}`, '1', { NX: true, EX: this._ttl });
    return Boolean(created);
  }
}

// -- A2A verifier ---------------------------------------------------------------

class A2AVerifier {
  constructor({
    audience,
    anchor = null,
    anchorFor = null,
    maxAgeSecs = 60,
    // No default, and none is possible: a revocation source cannot be invented the way
    // an in-process approval ledger can. Supply a check, or pass `false` to declare that
    // this verifier deliberately performs none. Leaving it unset throws - silence used to
    // mean "accept every revoked credential", which is not a posture anyone chose.
    revocationCheck = null,
    failOpenOnRevocationError = false,
    // On by default, matching `PolicyConfig.require_argument_binding` in Python. This
    // default was missed when `revocationCheck` and `requireCanonicalizationProfile`
    // were aligned across the runtimes, so a Node verifier accepted unbound
    // presentations while the Python one refused them - and an unbound proof says
    // "this holder is here now" and nothing about what it asked for, so a presentation
    // captured from one call replays against different arguments. Pass `false` only to
    // interoperate with a holder that does not yet bind.
    requireArgumentBinding = true,
    principalResolver = null,
    replayGuard = undefined,
    enableReplayProtection = true,
    // RFC 8785. `canonicalizeArgs` and `canonicalizationProfile` must always describe
    // the same algorithm - a canonicalizer and a profile id that disagree refuse every
    // bound call as tampering.
    canonicalizeArgs = jcsCanonicalizeArgs,
    // Set to OCTETS_PROFILE to stop canonicalizing entirely: the binding string then
    // comes from the holder (see `boundArguments` on authorize) and `canonicalizeArgs`
    // is never consulted.
    canonicalizationProfile = JCS_PROFILE,
    // On by default, matching the Python verifier. Only applies to presentations that
    // are actually action-bound - an unbound one computed no binding and has nothing to
    // declare, and refusing those is `requireArgumentBinding`'s job.
    requireCanonicalizationProfile = true,
  } = {}) {
    if (!anchor && !anchorFor) throw new Error('provide either `anchor` (single issuer) or `anchorFor` (multi-issuer)');
    if (!audience) throw new Error('A2AVerifier requires an `audience` (this receiver\'s identity)');
    this._audience = audience;
    this._anchor = anchor;
    this._anchorFor = anchorFor;
    this._maxAge = maxAgeSecs;
    // Test with `=== false` rather than truthiness, so a caller's callable object that
    // happens to be falsy is not silently read as the opt-out.
    if (revocationCheck === null || revocationCheck === undefined) {
      throw new Error(
        'A2AVerifier requires `revocationCheck`: supply a check (see '
        + '`revocationCheckFromList`), or pass `revocationCheck: false` to declare that '
        + 'this verifier deliberately performs no revocation checking. It has no default '
        + 'because a revocation source cannot be invented, and silently having none '
        + 'accepts every revoked credential.',
      );
    }
    this._revocationCheck = revocationCheck === false ? null : revocationCheck;
    this._revFailOpen = failOpenOnRevocationError;
    this._requireArgBinding = requireArgumentBinding;
    this._principalResolver = principalResolver;
    this._canon = canonicalizeArgs;
    this._canonProfile = canonicalizationProfile;
    this._requireCanonProfile = requireCanonicalizationProfile;
    if (replayGuard != null) this._replayGuard = replayGuard;
    else if (enableReplayProtection) this._replayGuard = new InMemoryReplayGuard({ ttlSecs: Math.max(maxAgeSecs + 60, 120) });
    else this._replayGuard = null;
  }

  // Async so revocation / anchor / principal hooks (and a Redis replay guard) may
  // be async - they commonly hit the network in Node.
  // A binding computed under a different profile is a PROFILE failure, not a possession
  // failure. `declared` is holder-supplied and unauthenticated, which is sound because
  // both paths refuse - it can only change which refusal is reported, never whether the
  // call is admitted. What it buys is a diagnosis.
  _denyIfCanonMismatch(presentation, tool, declared) {
    if (!presentation.isActionBound) return null;   // nothing was bound, nothing to declare
    if (declared == null) {
      if (!this._requireCanonProfile) return null;
      return deny(CODES.CANON_PROFILE,
        `no canonicalization profile declared; this verifier computes bindings under '${this._canonProfile}'`, tool);
    }
    if (declared !== this._canonProfile) {
      return deny(CODES.CANON_PROFILE,
        `holder canonicalized under '${declared}', this verifier under '${this._canonProfile}'`
        + ' - the exact-action binding was computed over two different representations', tool);
    }
    return null;
  }

  async authorize(header, tool, args, { resource = null, actingFor = null, boundArguments = null, canonicalizationProfile = null } = {}) {
    const octets = this._canonProfile === OCTETS_PROFILE;
    // Under the octets profile the verifier must not canonicalize at all - the binding
    // string is the holder's. Doing it anyway would be wasted work on the authorization
    // path and would throw for values this profile represents but JCS cannot.
    let argsStr = octets ? '' : this._canon(args);

    let presentation;
    try {
      presentation = ac.Presentation.fromA2AHeader(header);
    } catch (e) {
      return deny(CODES.MALFORMED, `could not parse A2A header: ${e.message}`, tool);
    }

    const profileDenial = this._denyIfCanonMismatch(presentation, tool, canonicalizationProfile);
    if (profileDenial) return profileDenial;

    let signedArguments = null;
    if (octets) {
      let bound;
      try {
        bound = parseBoundArgs(boundArguments);
      } catch (e) {
        return deny(CODES.BOUND_ARGS,
          `${OCTETS_PROFILE} is in force but the carried arguments are unusable: ${e.message}`, tool);
      }
      // Both checks must pass and neither can be traded for the other: altering the
      // delivered arguments fails here, altering the carried octets fails the proof
      // below. The cheap comparison runs first so an unauthenticated caller cannot
      // spend a signature verification per request.
      if (!semanticEq(bound, args)) {
        return deny(CODES.ARGS_MISMATCH,
          'the arguments delivered by the transport are not the ones the holder signed', tool);
      }
      argsStr = boundArguments;   // the holder's own bytes; nothing is re-serialized
      // The only object in this flow that is identical to what was signed rather than
      // merely equivalent to it. Surfaced, never substituted - see Docs/pep-argument-rewrite.md.
      signedArguments = bound;
    }

    if (this._requireArgBinding && !presentation.isActionBound) {
      return deny(CODES.UNBOUND, 'request binding required but the presentation is unbound', tool);
    }

    let anchor = this._anchor;
    if (this._anchorFor) {
      try {
        anchor = await this._anchorFor(presentation.credential);
      } catch (e) {
        anchor = null;
      }
      if (!anchor) return deny(CODES.UNTRUSTED_ISSUER, 'no trusted anchor for the credential issuer', tool);
    }

    let action = new ac.Action(tool, argsStr);
    if (resource != null) action = action.withResource(resource);
    if (actingFor != null) action = action.withActingFor(actingFor);
    try {
      // verifyA2A also requires the embedded audience === this._audience.
      presentation.verifyA2A(action, anchor, this._audience, this._maxAge);
    } catch (e) {
      return deny(classifyError(e), String(e.message), tool);
    }

    if (this._replayGuard) {
      const key = crypto.createHash('sha256').update(header).digest('hex');
      if (!(await this._replayGuard.recordIfNew(key))) {
        return deny(CODES.REPLAY, 'this A2A header has already been used', tool);
      }
    }

    if (this._revocationCheck) {
      let revoked;
      try {
        revoked = await this._revocationCheck(presentation.credential);
      } catch (e) {
        if (!this._revFailOpen) return deny(CODES.REVOKED, `revocation status unavailable: ${e.message}`, tool);
        revoked = false;
      }
      if (revoked) return deny(CODES.REVOKED, 'credential has been revoked', tool);
    }

    const chain = presentation.token.chain().entries.map((e) => ({
      depth: e.depth,
      agentDid: e.agentDid,
      tools: e.tools,
      budgetUsd: e.budgetUsd,
    }));
    return { allowed: true, code: null, reason: null, tool, chain, boundArguments: signedArguments };
  }

  async authorizeObo(header, principalToken, tool, args, { resource = null, boundArguments = null, canonicalizationProfile = null } = {}) {
    if (!this._principalResolver) throw new Error('authorizeObo requires a `principalResolver` on the verifier');
    const actingFor = await this._principalResolver(principalToken);
    if (actingFor == null) return deny(CODES.PRINCIPAL, 'could not verify the on-behalf-of principal', tool);
    return this.authorize(header, tool, args, { resource, actingFor, boundArguments, canonicalizationProfile });
  }

  async authorizeEnvelope(headers, tool, args, { resource = null } = {}) {
    const lookup = {};
    for (const k of Object.keys(headers)) lookup[k.toLowerCase()] = headers[k];
    const capability = lookup[A2A_HEADER_NAME.toLowerCase()];
    if (capability == null) return deny(CODES.MALFORMED, `envelope missing the '${A2A_HEADER_NAME}' header`, tool);

    let boundArguments = null;
    const boundHeader = lookup[A2A_BOUND_ARGS_HEADER_NAME.toLowerCase()];
    if (boundHeader != null) {
      try {
        boundArguments = parseA2ABoundArgsHeader(boundHeader);
      } catch (e) {
        return deny(CODES.MALFORMED, `bad ${A2A_BOUND_ARGS_HEADER_NAME} header: ${e.message}`, tool);
      }
    }

    const canonicalizationProfile = lookup[A2A_CANON_PROFILE_HEADER_NAME.toLowerCase()] ?? null;

    const principalHeader = lookup[A2A_PRINCIPAL_HEADER_NAME.toLowerCase()];
    if (principalHeader == null) return this.authorize(capability, tool, args, { resource, boundArguments, canonicalizationProfile });
    let principalToken;
    try {
      principalToken = parseA2APrincipalHeader(principalHeader);
    } catch (e) {
      return deny(CODES.MALFORMED, `bad principal header: ${e.message}`, tool);
    }
    return this.authorizeObo(capability, principalToken, tool, args, { resource, boundArguments, canonicalizationProfile });
  }
}

module.exports = {
  CODES,
  A2AVerifier,
  makeA2AHeader,
  makeA2AEnvelope,
  makeA2APrincipalHeader,
  parseA2APrincipalHeader,
  anchorResolverFromRegistry,
  revocationCheckFromList,
  principalResolverFromOidc,
  InMemoryReplayGuard,
  RedisReplayGuard,
  A2A_CANON_PROFILE_HEADER_NAME,
  jcsCanonicalize,
  jcsCanonicalizeArgs,
  JCS_PROFILE,
  OCTETS_PROFILE,
  MAX_BOUND_ARGS_BYTES,
  octetsBindArgs,
  parseBoundArgs,
  semanticEq,
  makeA2ABoundArgsHeader,
  parseA2ABoundArgsHeader,
  A2A_BOUND_ARGS_HEADER_NAME,
  classifyError,
  A2A_HEADER_NAME,
  A2A_PRINCIPAL_HEADER_NAME,
  A2A_PRINCIPAL_SCHEME,
};
