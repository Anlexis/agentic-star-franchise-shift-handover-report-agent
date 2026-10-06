"""Declared runtime values, and proof that they reach the backbone.

A configuration file nobody reads does not fail: the reader finds no key, falls
back to its own default, and every declared value is dead while the suite stays
green. The migration to the flat manifest makes that failure one edit away —
there is no `agent.config` block to read any more — so these tests check the
whole path rather than the loader in isolation.

`test_declared_max_retry_changes_the_backbone_decision` is the one that matters:
it drives the framework's own routing with two different configurations and
asserts the destination moves. A test that only asserted `agent.config["max_retry"]
== 3` would pass on a graph that never consults it.
"""

import pytest

from framework.schemas.agent_status import AgentStatus
from src.graph.graph import RetailFranchiseShiftHandoverReportAgent
from src.services.runtime_config import (
    FALLBACK_AGENT,
    agent_config,
    load_runtime_config,
)


def test_the_shipped_config_file_is_readable() -> None:
    """If this returns {} the file moved and every value below is a default."""
    assert load_runtime_config(), "config/config.yaml is unreadable or empty"


def test_declared_values_are_loaded() -> None:
    declared = load_runtime_config()
    resolved = agent_config()
    assert resolved["max_retry"] == declared["max_retry"]
    assert resolved["timeout_s"] == declared["timeout_s"]


def test_declared_max_retry_changes_the_backbone_decision() -> None:
    """The end-to-end proof that the declaration is load-bearing.

    `AgentBaseGraph.route` reads `self.config["max_retry"]`, so the same RETRY
    state routes to a different node depending on what was declared. Building the
    graph with no config leaves the framework's own default in place.
    """
    retry_state = {"status": AgentStatus.RETRY.value, "retry_count": 1}

    exhausted = RetailFranchiseShiftHandoverReportAgent(config={"max_retry": 0})
    generous = RetailFranchiseShiftHandoverReportAgent(config={"max_retry": 5})

    assert exhausted.route(retry_state) == "finalize"
    assert generous.route(retry_state) == "pre_process"


def test_the_entry_point_builds_the_graph_with_the_declared_config() -> None:
    """Read from the module the deployment actually runs, not re-derived here."""
    from src.api.server import agent

    assert agent.config.get("max_retry") == agent_config()["max_retry"]
    assert agent.config.get("timeout_s") == agent_config()["timeout_s"]


@pytest.mark.parametrize(
    "declared", [{"max_retry": float("nan")}, {"max_retry": "abc"}, {"max_retry": 99}, {"max_retry": -1}]
)
def test_an_unusable_declaration_degrades_to_the_documented_default(monkeypatch, declared) -> None:
    """A NaN max_retry compares False against every retry count.

    An out-of-range or non-finite value is a deployment mistake, so the loader
    substitutes the documented default rather than letting it reach the backbone.
    """
    monkeypatch.setattr("src.services.runtime_config.load_runtime_config", lambda: declared)
    assert agent_config()["max_retry"] == FALLBACK_AGENT["max_retry"]


def test_an_unreadable_config_degrades_rather_than_raising(monkeypatch) -> None:
    monkeypatch.setattr("src.services.runtime_config.load_runtime_config", lambda: {})
    assert agent_config()["max_retry"] == FALLBACK_AGENT["max_retry"]
    assert agent_config()["timeout_s"] == FALLBACK_AGENT["timeout_s"]
