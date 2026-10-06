"""AgentCore Platform v1.0"""

# RET-C2-256 — outer graph (AgentBaseGraph; Cat 2 two-layer nested architecture)
#
# Architecture (Cat 2 document generation):
#
#   Outer backbone (fixed — do NOT override add_edges()):
#     START → initialize → pre_process → main → {route} → post_process → finalize → END
#                                             ↓ (RETRY, bounded by max_retry)
#                                          pre_process
#
#   The `main` slot is a GraphNode subclass (ShiftHandoverGraphNode) that delegates
#   the whole domain workflow to DomainWorkflowGraph (inner BaseGraph).
#
# Directory layout:
#   src/graph/graph.py                 ← outer graph (this file)
#   src/graph/domain_workflow_graph.py ← inner graph (6-step domain topology)
#
# Rules enforced here:
#   RetailFranchiseShiftHandoverReportAgent inherits AgentBaseGraph (L1 Base)
#   super().register_nodes() is called first (fills initialize + finalize)
#   ShiftHandoverGraphNode is assigned to self._nodes["main"]
#   merge_output() returns only changed keys
#   config/agent.yaml class: == this class name == the name src/api/server.py imports
#   add_edges() is NOT overridden — backbone wiring belongs to the framework
#   No platform SDK imports

import json
from typing import Any, ClassVar, Dict

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.graph.base_graph import BaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import State
from src.services import input_guard as guard
from src.services.report_format import contained_refusal


class ShiftHandoverGraphNode(GraphNode):
    """The `main` slot of RetailFranchiseShiftHandoverReportAgent.

    Wraps DomainWorkflowGraph (the inner 6-node domain pipeline) and owns the
    caller-visible envelope for every way that pipeline can fail.

    Contracts:
      get_subgraph()       instantiate and return DomainWorkflowGraph
      extract_input()      pass the validated payload into the inner graph
      merge_output()       map a SUCCESSFUL sub_result into the outer state delta
      on_subgraph_error()  map any failure into a contained refusal
    """

    # "contain", not "propagate". The distinction is not stylistic: with
    # "propagate" the framework raises SubgraphError before merge_output() is
    # reached, the node wrapper catches it and returns a bare ERROR partial, and
    # the caller's envelope comes out as `output: None` with no reason anywhere —
    # measured on this repo before the change. Containing routes BOTH failure
    # paths (an inner ERROR status and an inner exception) through
    # on_subgraph_error below, which is the only place this agent can state a
    # reason the caller can act on.
    error_strategy: ClassVar[str] = "contain"

    # HITL interrupts are handled inside the inner graph only.
    propagate_hitl: ClassVar[bool] = False

    def get_subgraph(self) -> BaseGraph:
        """Instantiate and return DomainWorkflowGraph.

        Imported lazily to avoid a circular import at module load time. Called on
        every execute(); the inner graph does no I/O on construction.
        """
        from src.graph.domain_workflow_graph import DomainWorkflowGraph

        return DomainWorkflowGraph()

    def extract_input(self, state: AgentState) -> str:
        """Return the payload string passed into inner_graph.invoke().

        PreProcessNode has already screened and committed `validated_input`; it is
        passed as a JSON string so InputParseNode receives a consistently typed
        payload. The fallback to raw user_input keeps the inner graph usable when
        it is invoked on its own, where InputParseNode applies the same contract.
        """
        validated = state.get("validated_input")
        if validated is not None:
            if isinstance(validated, str):
                return validated
            try:
                return json.dumps(validated, ensure_ascii=False)
            except (TypeError, ValueError):
                return str(validated)
        return str(state.get("user_input", ""))

    def merge_output(self, state: AgentState, sub_result: Dict[str, Any]) -> Dict[str, Any]:
        """Map a successful inner result into the outer state delta.

        Only reached when the inner graph returned a non-error status — the
        framework diverts every error to on_subgraph_error(). The guard below is
        therefore belt-and-braces rather than the primary path, and it is here
        because `result` is the field `AgentBaseGraph.get_output` falls back to
        when `formatted_output` is falsy: a truthy `result` on a non-success run is
        exactly the leak that fallback exists to produce.

        Key coupling, designed together with DomainWorkflowGraph.get_output():
          inner get_output() emits: validated_output, status, trace_id,
                                    correlation_id, node_history
          this method reads:        validated_output, status
        """
        status = sub_result.get("status")
        if status not in (AgentStatus.SUCCESS, AgentStatus.SUCCESS.value):
            return self._contain(sub_result.get("error_log"))
        return {
            "result": sub_result.get("validated_output"),
            "status": status,
        }

    def on_subgraph_error(self, state: AgentState, error: Exception) -> Dict[str, Any]:
        """Turn any inner failure into a contained, closed-set refusal.

        Overrides the framework default, which formats the exception into
        `error_log` as free text. The caller-visible error contract for this agent
        is labels only: a reason code from the closed set and, when it is inert, a
        field location. Nothing node-authored and no upstream message body is
        re-emitted.
        """
        return self._contain(getattr(error, "error_log", None))

    @staticmethod
    def _contain(error_log: Any) -> Dict[str, Any]:
        """The refusal delta: a truthy closed-set notice, and nothing to fall back on."""
        reason, location = guard.project_refusal(error_log)
        delta: Dict[str, Any] = contained_refusal(reason, location)
        delta["status"] = AgentStatus.ERROR
        delta["error_log"] = [f"ShiftHandoverGraphNode: {reason} ({location or 'value'})"]
        return delta


class RetailFranchiseShiftHandoverReportAgent(AgentBaseGraph):
    """Outer graph for RET-C2-256 (Cat 2 document generation).

    Inherits AgentBaseGraph directly (L1 Base). Domain logic is fully encapsulated
    in ShiftHandoverGraphNode (the main slot), which delegates to
    DomainWorkflowGraph (inner BaseGraph — 6 domain nodes).

    Backbone (fixed — identical to Cat 1):
        START → initialize → pre_process → main → post_process → finalize → END

    register_nodes() is the only override:
      - super().register_nodes() fills initialize and finalize (framework defaults)
      - pre_process: PreProcessNode (the VERIFIED_EXTERNAL caller gate)
      - main:        ShiftHandoverGraphNode (delegates to DomainWorkflowGraph)
      - post_process: PostProcessNode (output formatting, ANONYMOUS)

    The class name matches config/agent.yaml `class:` and the name src/api/server.py
    imports. add_edges() is NOT overridden.
    """

    @property
    def name(self) -> str:
        """Agent identifier registered with AgentRegistry."""
        return "ret_c2_256"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        """Fill all 5 backbone slots.

        super().register_nodes() MUST be called first — it injects the framework's
        default InitializeNode (schema_version, session_id, trust_level) and
        FinalizeNode (response_metadata, total_time_ms).
        """
        super().register_nodes()  # fills: initialize, finalize

        self._nodes["pre_process"] = PreProcessNode()
        self._nodes["main"] = ShiftHandoverGraphNode()
        self._nodes["post_process"] = PostProcessNode()

    # add_edges() is NOT overridden — backbone wiring belongs to the framework.


# Back-compat alias — the class name is the canonical identifier.
Graph = RetailFranchiseShiftHandoverReportAgent
