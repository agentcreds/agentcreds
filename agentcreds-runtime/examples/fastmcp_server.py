"""Sketch: a FastMCP server with AgentCreds identity enforcement.

Requires the optional MCP SDK:  pip install "agentcreds-runtime[mcp]"

This shows the wiring shape. The challenge handshake (delivering the per-session
challenge to the client and receiving the presentation) is shown via the reserved
`agentcreds_presentation` tool argument; in production move it to request `_meta`
once pinned to an MCP SDK version and pass a custom `presentation_getter`.
"""

import os

import agentcreds as ac
from mcp.server.fastmcp import Context, FastMCP

from agentcreds_runtime import IdentityEnforcer, PolicyConfig
from agentcreds_runtime.fastmcp import guard_tool

# In production the anchor's public DID is loaded from config; its private key
# lives in an HSM and is never needed here (verification is public-key only).
ANCHOR = ac.TrustAnchor.generate()

mcp = FastMCP("search-server")
enforcer = IdentityEnforcer(
    ANCHOR, config=PolicyConfig(max_age_secs=60, audit=print, audit_denied=True, revocation_check=False)
)


@mcp.tool()
async def issue_challenge(ctx: Context) -> str:
    """Clients call this first to obtain a per-session proof-of-possession
    challenge (base64-CBOR), sign it, and attach the resulting presentation to
    subsequent calls."""
    import base64

    from agentcreds_runtime.fastmcp import default_session_id

    return base64.b64encode(enforcer.issue_challenge(default_session_id(ctx))).decode()


@mcp.tool()
@guard_tool(enforcer, "tool:search")
async def search(q: str, ctx: Context, agentcreds_presentation: str,
                 agentcreds_chain=None) -> str:
    """Reached only after identity enforcement passes. `agentcreds_chain` holds
    the verified delegation chain for audit/logging."""
    depth = len(agentcreds_chain)
    return f"results for {q!r} (delegation depth {depth})"


if __name__ == "__main__":
    mcp.run(transport=os.environ.get("MCP_TRANSPORT", "stdio"))
