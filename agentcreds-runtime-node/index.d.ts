/**
 * Type declarations for `@agentcreds/runtime`.
 *
 * `package.json` has always pointed `types` here, but the file did not exist, so
 * TypeScript consumers silently got `any` for the whole runtime and a published
 * package would have shipped a dangling pointer.
 *
 * Core types (`DelegationToken`, `CapabilityCredential`, `TrustAnchor`, `Action`, ...)
 * come from `@agentcreds/sdk`, which ships its own declarations; they are referenced
 * here by import rather than restated, so the two cannot drift.
 */

import type {
  Action,
  AgentIdentity,
  CapabilityCredential,
  DelegationToken,
  OidcProvider,
  RevocationList,
  TrustAnchor,
  TrustRegistry,
} from '@agentcreds/sdk';

/** Denial codes. A decision's `code` is one of these, or `null` when allowed. */
export declare const CODES: Readonly<{
  MALFORMED: 'malformed_presentation';
  POSSESSION: 'possession_failed';
  NOT_AUTHORIZED: 'not_authorized';
  CREDENTIAL: 'credential_invalid';
  REVOKED: 'credential_revoked';
  PRINCIPAL: 'principal_mismatch';
  UNBOUND: 'argument_binding_required';
  UNTRUSTED_ISSUER: 'untrusted_issuer';
  REPLAY: 'replayed_presentation';
  /** The holder and this verifier computed the binding over different representations. */
  CANON_PROFILE: 'canonicalization_profile_mismatch';
  /** `agentcreds-octets-v1` only: the arguments changed in transit. */
  ARGS_MISMATCH: 'argument_mismatch';
  BOUND_ARGS: 'bound_arguments_invalid';
  DENIED: 'access_denied';
}>;

export type DenialCode = (typeof CODES)[keyof typeof CODES];

/** One hop of the verified delegation chain. */
export interface ChainEntry {
  depth: number;
  agentDid: string;
  tools: string[];
  budgetUsd: number | null;
}

/**
 * The verifier's answer. `allowed` is the only field to branch on; `code` and
 * `reason` explain a denial and are `null` on an allow.
 */
export interface Decision {
  allowed: boolean;
  code: DenialCode | null;
  reason: string | null;
  tool: string;
  /** The verified chain on an allow; `null` on a denial. */
  chain: ChainEntry[] | null;
  /**
   * Under `agentcreds-octets-v1`, the arguments the holder actually signed, parsed.
   * `null` under a canonicalizing profile (nothing was carried) and on any denial.
   */
  boundArguments: unknown | null;
}

/** Returns `true` if the credential is revoked. May be async. */
export type RevocationCheck = (
  credential: CapabilityCredential,
) => boolean | Promise<boolean>;

/** Resolves the anchor to verify a credential against, or `null` to refuse it. */
export type AnchorResolver = (
  credential: CapabilityCredential,
) => TrustAnchor | null | Promise<TrustAnchor | null>;

/** Resolves a principal token to the DID it authenticates. */
export type PrincipalResolver = (
  principalToken: string,
) => string | null | Promise<string | null>;

/** Returns `true` if this presentation has not been seen inside the TTL. */
export interface ReplayGuard {
  recordIfNew(key: string): boolean | Promise<boolean>;
}

export interface A2AVerifierOptions {
  /** This receiver's identity. Required - a proof is bound to its audience. */
  audience: string;
  /** Single-issuer anchor. Provide this or `anchorFor`. */
  anchor?: TrustAnchor | null;
  /** Multi-issuer resolver. Provide this or `anchor`. */
  anchorFor?: AnchorResolver | null;
  /** Freshness window for a presentation, in seconds. Default 60. */
  maxAgeSecs?: number;
  /**
   * **Required, with no default.** Supply a check, or pass `false` to declare that
   * this verifier deliberately performs none. A revocation source cannot be
   * invented, and silence would mean accepting every revoked credential.
   */
  revocationCheck: RevocationCheck | false;
  /** Treat a revocation-check error as "not revoked". Default `false` (fail closed). */
  failOpenOnRevocationError?: boolean;
  /**
   * Refuse presentations that are not bound to the request. Default `true`,
   * matching Python: an unbound proof replays against different arguments.
   */
  requireArgumentBinding?: boolean;
  principalResolver?: PrincipalResolver | null;
  replayGuard?: ReplayGuard;
  /** Default `true`. */
  enableReplayProtection?: boolean;
  /** Default `jcsCanonicalizeArgs`. Never consulted under `OCTETS_PROFILE`. */
  canonicalizeArgs?: (args: Record<string, unknown>) => string;
  /** Default `JCS_PROFILE`. */
  canonicalizationProfile?: string;
  /**
   * Require a bound presentation to declare its profile. Default `true`. Applies
   * only to bound presentations - an unbound one has no profile to declare.
   */
  requireCanonicalizationProfile?: boolean;
}

export interface AuthorizeOptions {
  /** The resource this call touches. Part of the binding digest. */
  resource?: string | null;
  actingFor?: string | null;
  /** The holder's signed argument octets (`agentcreds-octets-v1` only). */
  boundArguments?: string | null;
  /** The profile the holder computed its binding under. */
  canonicalizationProfile?: string | null;
}

/** Verifies A2A presentations offline, against public keys only. */
export declare class A2AVerifier {
  constructor(options: A2AVerifierOptions);
  authorize(
    header: string,
    tool: string,
    args: Record<string, unknown>,
    options?: AuthorizeOptions,
  ): Promise<Decision>;
  /** On-behalf-of: also binds the human principal. Needs a `principalResolver`. */
  authorizeObo(
    header: string,
    principalToken: string,
    tool: string,
    args: Record<string, unknown>,
    options?: Omit<AuthorizeOptions, 'actingFor'>,
  ): Promise<Decision>;
  /** Reads the presentation, principal and profile from a header map. */
  authorizeEnvelope(
    headers: Record<string, string>,
    tool: string,
    args: Record<string, unknown>,
    options?: Pick<AuthorizeOptions, 'resource'>,
  ): Promise<Decision>;
}

export interface MakeHeaderOptions {
  audience: string;
  /** Bind the proof to this exact request. Verifiers require it by default. */
  action?: Action | null;
}

export interface MakeEnvelopeOptions extends MakeHeaderOptions {
  principalToken?: string | null;
  boundArguments?: string | null;
  canonicalizationProfile?: string | null;
}

export declare function makeA2AHeader(
  token: DelegationToken,
  credential: CapabilityCredential,
  leafAgent: AgentIdentity,
  options: MakeHeaderOptions,
): string;

/** Builds the full header map: presentation, plus principal/profile/octets if given. */
export declare function makeA2AEnvelope(
  token: DelegationToken,
  credential: CapabilityCredential,
  leafAgent: AgentIdentity,
  options: MakeEnvelopeOptions,
): Record<string, string>;

export declare function makeA2APrincipalHeader(principalToken: string): string;
export declare function parseA2APrincipalHeader(value: string): string;
export declare function makeA2ABoundArgsHeader(boundArguments: string): string;
export declare function parseA2ABoundArgsHeader(value: string): string;

export declare function anchorResolverFromRegistry(
  registry: TrustRegistry,
): AnchorResolver;
export declare function revocationCheckFromList(
  revList: RevocationList,
  anchor: TrustAnchor,
): RevocationCheck;
export declare function principalResolverFromOidc(
  provider: OidcProvider,
  options?: { expectedAgentDid?: string | null },
): PrincipalResolver;

export declare class InMemoryReplayGuard implements ReplayGuard {
  constructor(options?: { ttlSecs?: number });
  recordIfNew(key: string): boolean;
}

export declare class RedisReplayGuard implements ReplayGuard {
  constructor(client: unknown, options?: { ttlSecs?: number; namespace?: string });
  recordIfNew(key: string): Promise<boolean>;
}

/** RFC 8785 (JCS) serialization of an arbitrary value. */
export declare function jcsCanonicalize(value: unknown): string;
/** RFC 8785 serialization of a tool's arguments - the binding string. */
export declare function jcsCanonicalizeArgs(args: Record<string, unknown>): string;

/** `agentcreds-jcs-v1` - both sides reconstruct the bytes. The default. */
export declare const JCS_PROFILE: string;
/** `agentcreds-octets-v1` - the holder carries the bytes it signed. */
export declare const OCTETS_PROFILE: string;
/** Cap on the carried copy: it is attacker-controlled text, parsed before auth. */
export declare const MAX_BOUND_ARGS_BYTES: number;
/** The on-behalf-of principal header's scheme prefix (`AgentCreds-A2A-Principal/1.`). Wire-visible. */
export declare const A2A_PRINCIPAL_SCHEME: string;

/** Serialize arguments for `OCTETS_PROFILE`; these exact bytes are signed and carried. */
export declare function octetsBindArgs(args: Record<string, unknown>): string;
/** Parse carried octets. Throws if malformed or over `MAX_BOUND_ARGS_BYTES`. */
export declare function parseBoundArgs(text: string): unknown;
/** Structural equality - compares what a value *is*, not how it was written. */
export declare function semanticEq(a: unknown, b: unknown): boolean;

/** Map a thrown core error to a denial code by its message prefix. */
export declare function classifyError(err: unknown): DenialCode;

export declare const A2A_HEADER_NAME: string;
export declare const A2A_PRINCIPAL_HEADER_NAME: string;
export declare const A2A_CANON_PROFILE_HEADER_NAME: string;
export declare const A2A_BOUND_ARGS_HEADER_NAME: string;
