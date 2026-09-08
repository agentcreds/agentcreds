"""AgentCreds runtime identity enforcement.

Drop-in agent-identity enforcement built on the AgentCreds proof-of-possession
presentation check. Two transports share one policy core:

- **MCP** (interactive, sessionful): `IdentityEnforcer` + the FastMCP adapter in
  `agentcreds_runtime.fastmcp`.
- **A2A** (agent-to-agent, no MCP server): `A2AVerifier` + `make_a2a_header`.

Both enforce the same guarantees - anchor-rooted authority, proof-of-possession,
revocation, on-behalf-of principal binding, argument binding, and multi-issuer
trust - and emit the same audit / ADR records.
"""

from .a2a import (
    A2A_BOUND_ARGS_HEADER_NAME,
    A2A_CANON_PROFILE_HEADER_NAME,
    A2A_HEADER_NAME,
    A2A_PRINCIPAL_HEADER_NAME,
    A2AVerifier,
    PrincipalResolver,
    make_a2a_bound_args_header,
    make_a2a_envelope,
    make_a2a_header,
    make_a2a_principal_header,
    parse_a2a_bound_args_header,
    parse_a2a_principal_header,
    principal_resolver_from_oidc,
)
from .approval import (
    ApprovalClient,
    ApprovalDenied,
    ApprovalPolicy,
    ApprovalRequest,
    HttpApprovalClient,
    InMemoryApprovalClient,
)
from .cedar import cedar_policy_hook
from .client import present
from .enforcer import IdentityEnforcer
from .gates import (
    APPROVAL,
    APPROVAL_KEY,
    ConsumedApprovalsStore,
    GateDenied,
    InMemoryConsumedApprovals,
    RedisConsumedApprovals,
    enforce_gates,
)
from .errors import (
    CODE_APPROVAL,
    CODE_ARGS_MISMATCH,
    CODE_BOUND_ARGS,
    CODE_CANON_PROFILE,
    CODE_POLICY,
    CODE_QUOTA,
    AccessDenied,
    ChainHop,
    Decision,
)
from . import octets
from .approverdir import ApproverDirectoryCache
from .fetchcache import FetchedStatus
from .trustregistry import (
    TrustRegistryCache,
    anchor_resolver_from_registry_cache,
)
from .keyhistory import (
    KeyHistoryCache,
    KeyHistoryStatus,
    anchor_resolver_from_key_history_cache,
)
from .policy import (
    AuditRecord,
    PolicyConfig,
    PolicyHook,
    PolicyInput,
    anchor_resolver_from_key_history,
    anchor_resolver_from_registry,
    CANON_PROFILE_JCS,
    CANON_PROFILE_OCTETS,
    jcs_canonicalize_args,
    octets_bind_args,
    predicate_policy,
    revocation_check_from_list,
)
from .idempotency import (
    IdempotencyConflict,
    IdempotencyStore,
    InMemoryIdempotencyStore,
    RedisIdempotencyStore,
    idempotent,
)
from .replay import InMemoryReplayGuard, RedisReplayGuard, ReplayGuard
from .reporter import DecisionReporter
from .session import InMemorySessionStore, RedisSessionStore, SessionStore
from .usage import (
    InMemoryUsageStore,
    RedisUsageStore,
    UsageStore,
    leaf_agent_key,
    rate_limit,
    spend_limit,
    usage_gate,
)

__all__ = [
    # MCP transport
    "IdentityEnforcer",
    "present",
    # A2A transport
    "A2AVerifier",
    "make_a2a_header",
    "make_a2a_envelope",
    "make_a2a_principal_header",
    "parse_a2a_principal_header",
    "A2A_HEADER_NAME",
    "A2A_PRINCIPAL_HEADER_NAME",
    "A2A_BOUND_ARGS_HEADER_NAME",
    "A2A_CANON_PROFILE_HEADER_NAME",
    "make_a2a_bound_args_header",
    "parse_a2a_bound_args_header",
    "principal_resolver_from_oidc",
    "PrincipalResolver",
    # results
    "Decision",
    "AccessDenied",
    "ChainHop",
    "AuditRecord",
    "CODE_POLICY",
    "CODE_QUOTA",
    "CODE_APPROVAL",
    # human-in-the-loop step-up approval
    "ApprovalClient",
    "InMemoryApprovalClient",
    "HttpApprovalClient",
    "ApprovalRequest",
    "ApprovalDenied",
    "ApprovalPolicy",
    # policy hooks / helpers
    "PolicyConfig",
    "CANON_PROFILE_JCS",
    "CANON_PROFILE_OCTETS",
    "jcs_canonicalize_args",
    "octets",
    "octets_bind_args",
    "CODE_CANON_PROFILE",
    "CODE_ARGS_MISMATCH",
    "CODE_BOUND_ARGS",
    "revocation_check_from_list",
    "ApproverDirectoryCache",
    "FetchedStatus",
    "KeyHistoryCache",
    "TrustRegistryCache",
    "anchor_resolver_from_registry_cache",
    "KeyHistoryStatus",
    "anchor_resolver_from_key_history_cache",
    "anchor_resolver_from_key_history",
    "anchor_resolver_from_registry",
    "enforce_gates",
    "GateDenied",
    "APPROVAL",
    "APPROVAL_KEY",
    "ConsumedApprovalsStore",
    "InMemoryConsumedApprovals",
    "RedisConsumedApprovals",
    "predicate_policy",
    "cedar_policy_hook",
    "PolicyHook",
    "PolicyInput",
    # usage governance (rate/quota + spend)
    "usage_gate",
    "rate_limit",
    "spend_limit",
    "leaf_agent_key",
    "UsageStore",
    "InMemoryUsageStore",
    "RedisUsageStore",
    # session stores (MCP)
    "SessionStore",
    "InMemorySessionStore",
    "RedisSessionStore",
    # replay guards (A2A)
    "IdempotencyConflict",
    "IdempotencyStore",
    "InMemoryIdempotencyStore",
    "RedisIdempotencyStore",
    "idempotent",
    "ReplayGuard",
    "InMemoryReplayGuard",
    "RedisReplayGuard",
    # best-effort decision reporting to the control plane (Decisions view / audit / SIEM)
    "DecisionReporter",
]

__version__ = "0.1.0"
