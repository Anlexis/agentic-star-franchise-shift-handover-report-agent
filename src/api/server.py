"""AgentCore Platform v1.0"""

# Standalone HTTP entry point for the agent.
# Entry points are adapters only — no business logic here. When the agent runs
# behind the platform gateway instead, the gateway calls agent.invoke() directly
# and this module is not in the path, which is why every guarantee below is also
# enforced by the nodes that own the caller contract.

import os
import secrets
from typing import Any, Dict, Optional
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.context import bound_secrets
from shared.secrets import factory as secrets_factory
from src.graph.graph import RetailFranchiseShiftHandoverReportAgent
from src.services import input_guard as guard
from src.services.input_guard import validate_context
from src.services.runtime_config import agent_config

app = FastAPI(title="Agent")

# The declared runtime values reach the backbone here. Constructing the graph with
# no config would leave every value in config/config.yaml unread, with the
# framework quietly substituting its own built-in defaults — max_retry included,
# which is the value its routing decision reads.
agent = RetailFranchiseShiftHandoverReportAgent(config=agent_config())
agent.compile()

# The secret provider is scoped by the identity the manifest declares, so a secret
# resolves from the same place here and under the registry. The provider reads
# `env/namespaces/{namespace}/…` and `env/agents/{namespace}/{name}/…`, so a
# namespace that disagrees with `config/agent.yaml` silently splits one agent's
# secrets across two stores — nothing fails at boot, because a missing tier file
# is ignored by design, and nothing fails until a secret is declared, and then
# only in one of the two deployments.
# `namespace` is lower(industry) — "ret" — not the lowercased template id.
# tests/integration/test_manifest_identity_alignment.py holds both values to the
# manifest by reading each side rather than restating either.
agent.provision_secrets(secrets_factory(namespace="ret", agent_name="RetailFranchiseShiftHandoverReportAgent"))

# Upper bound on the serialised shift payload (bytes). The graph enforces
# per-field bounds — entry caps, inert alphabets, finite numeric ranges — and this
# is the single ceiling in front of all of them, so a multi-megabyte body is
# refused before it is parsed rather than after.
MAX_INPUT_BYTES = 256 * 1024


class InvokeRequest(BaseModel):
    input: str
    session_id: str = ""
    # Optional request context. Supported key: `channel`. Anything else is dropped
    # before the graph runs — see the note in the handler.
    input_context: Optional[Dict[str, Any]] = None


@app.post("/invoke")
async def invoke(req: InvokeRequest, request: Request) -> Dict[str, Any]:
    trust = getattr(request.state, "trust_level", TrustLevel.ANONYMOUS)
    # Caller authentication for the standalone deployment. The manifest declares
    # required_trust_level: VERIFIED_EXTERNAL and PreProcessNode enforces it, so
    # without this the adapter hands every request to the graph as ANONYMOUS and
    # the trust gate refuses before any node runs — a deployed agent that cannot
    # serve a single request, with nothing in the failure pointing at the cause.
    # When INVOKE_AUTH_TOKEN is set on the server environment, a caller no upstream
    # middleware vouched for must present it as a Bearer token and then runs as
    # VERIFIED_EXTERNAL. Trust established by middleware is never demoted.
    # This is a deployment-level caller credential rather than an agent secret, so
    # the secrets provider does not apply: no invocation context exists yet.
    expected = os.environ.get("INVOKE_AUTH_TOKEN")
    if expected and trust is TrustLevel.ANONYMOUS:
        supplied = request.headers.get("authorization", "")
        # Compare bytes: compare_digest raises TypeError on non-ASCII str input
        # (headers decode as latin-1), which would 500 instead of the generic 401.
        if not secrets.compare_digest(supplied.encode(), f"Bearer {expected}".encode()):
            # Generic body on purpose — do not leak whether the token was absent,
            # malformed, or wrong.
            raise HTTPException(status_code=401, detail="Token is invalid or expired.")
        trust = TrustLevel.VERIFIED_EXTERNAL

    # 400 rather than 422 throughout: the validation layer owns 422 and answers
    # there with a list of error objects, so reusing it makes client handling
    # ambiguous.
    if len(req.input.encode("utf-8")) > MAX_INPUT_BYTES:
        raise HTTPException(status_code=400, detail=f"Rejected input: {guard.REASON_TOO_LONG}")

    # Screen the request text here as well as in the entry node, because the
    # framework's own input gate runs BEFORE any template code and refuses on its
    # own terms: it returns a bare error partial from inside the node wrapper, the
    # backbone routes straight to finalize, and the caller receives an envelope
    # with no reason in it at all. Measured on this agent: "ignore all previous
    # instructions" came back as `status: error, output: null`.
    #
    # The request cannot succeed either way, so the useful thing this adapter can
    # do is turn an opaque failure into one the caller can act on. It is NOT a
    # replacement for PreProcessNode's screen — when the platform gateway calls
    # agent.invoke() directly this module is not in the path at all, and that is
    # the case the node's screen exists for.
    refusal = guard.screen_request(req.input)
    if refusal:
        reason, location = refusal
        raise HTTPException(status_code=400, detail=f"Rejected input.{location}: {reason}")

    # Reduce the request context to the supported, inert subset BEFORE the graph is
    # invoked. An unsupported key is not merely ignored downstream: it stays on the
    # context channel, the framework's first node returns that channel verbatim
    # inside its own result, and the framework's output scan then fails the whole
    # run with an error the caller cannot act on. A credential-shaped value fails
    # the same way. The request cannot succeed either way, so refuse it here with
    # the field named — the name is echoed only when it is itself inert, and the
    # value never is.
    accepted_context, refusals = validate_context(req.input_context)
    if refusals:
        reason, field = refusals[0]
        raise HTTPException(status_code=400, detail=f"Rejected input_context.{field}: {reason}")

    with bound_secrets(agent._secrets_provider):
        ctx = InvocationContext(
            session_id=req.session_id or str(uuid4()),
            caller_trust_level=trust,
            caller_id=getattr(request.state, "caller_id", ""),
        )
        envelope: Dict[str, Any] = agent.invoke(req.input, ctx=ctx, input_context=accepted_context)
        return envelope


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "agent": "RetailFranchiseShiftHandoverReportAgent"}
