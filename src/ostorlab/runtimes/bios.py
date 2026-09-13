"""Scan BIOS verification engine.

Performs pre-scan hardware/software checks, matching target assets against agent selectors,
validating schemas, and checking for routing dead-ends and unreachable inputs before infrastructure launch.
"""

import logging
from typing import Any

from ostorlab import exceptions
from ostorlab.assets import asset as base_asset
from ostorlab.runtimes import definitions

logger = logging.getLogger(__name__)


class BiosCheckError(exceptions.OstorlabError):
    """Scan BIOS sanity check failed."""


class BiosWarning:
    """Represents a non-fatal warning generated during the BIOS check."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message

    def __repr__(self) -> str:
        return f"BiosWarning(code='{self.code}', message='{self.message}')"


class ScanBios:
    """Pre-scan verification engine (BIOS POST for scans)."""

    def __init__(
        self,
        agent_group_definition: definitions.AgentGroupDefinition,
        assets: list[base_asset.Asset] | None,
        fail_on_warnings: bool = False,
    ) -> None:
        self.agent_group_definition = agent_group_definition
        self.assets = assets or []
        self.fail_on_warnings = fail_on_warnings
        self.warnings: list[BiosWarning] = []

    def check(self) -> None:
        """Runs complete pre-scan diagnostic checks."""
        self._check_agent_group_not_empty()
        self._check_target_asset_consumers()
        self._check_asset_schemas()
        self._check_selector_connectivity()

    def _check_agent_group_not_empty(self) -> None:
        """Verifies agent group has agents."""
        if not self.agent_group_definition.agents:
            raise BiosCheckError(
                "[BIOS POST FAILED] Agent group contains no agents. Cannot start scan."
            )

    def _check_target_asset_consumers(self) -> None:
        """Verifies that every target asset has at least one matching consumer agent."""
        if not self.assets:
            return

        all_in_selectors: set[str] = set()
        for agent in self.agent_group_definition.agents:
            if agent.in_selectors:
                all_in_selectors.update(agent.in_selectors)

        # If agents in the group don't declare in_selectors (e.g. ad-hoc CLI runs without manifest),
        # allow through for full backward compatibility.
        if not all_in_selectors:
            return

        unmatched_assets: list[base_asset.Asset] = []
        for target in self.assets:
            selector = getattr(target, "selector", None)
            if not selector:
                continue

            matched = any(
                self.selector_matches(target_selector=selector, pattern=pattern)
                for pattern in all_in_selectors
            )
            if not matched:
                unmatched_assets.append(target)

        if unmatched_assets:
            unmatched_str = ", ".join(
                f"'{a.selector}'" for a in unmatched_assets if hasattr(a, "selector")
            )
            available_str = (
                ", ".join(f"'{s}'" for s in sorted(all_in_selectors))
                if all_in_selectors
                else "None"
            )
            raise BiosCheckError(
                f"[BIOS POST FAILED] Unhandled Target Asset(s): No agent in the agent group listens to "
                f"[{unmatched_str}]. Available agent in_selectors: [{available_str}]."
            )

    def _check_asset_schemas(self) -> None:
        """If target asset contains payload data and agent specifies schema, validate it."""
        for target in self.assets:
            selector = getattr(target, "selector", None)
            data = getattr(target, "data", None)
            if not selector or data is None or not isinstance(data, dict):
                continue

            for agent in self.agent_group_definition.agents:
                schema = agent.asset_schemas.get(selector)
                if schema:
                    self._validate_schema(selector, data, schema)

    def _validate_schema(
        self, selector: str, data: dict[str, Any], schema: dict[str, Any]
    ) -> None:
        """Validates payload dictionary against JSON schema."""
        try:
            import jsonschema

            jsonschema.validate(instance=data, schema=schema)
        except ImportError:
            logger.debug("jsonschema not installed, skipping schema validation.")
        except Exception as e:
            raise BiosCheckError(
                f"[BIOS POST FAILED] Asset schema validation error for selector '{selector}': {e}"
            ) from e

    def _check_selector_connectivity(self) -> None:
        """Checks for orphan outputs or unconsumed agent in_selectors."""
        all_in_selectors: set[str] = set()
        all_out_selectors: set[str] = set()

        for agent in self.agent_group_definition.agents:
            if agent.in_selectors:
                all_in_selectors.update(agent.in_selectors)
            if agent.out_selectors:
                all_out_selectors.update(agent.out_selectors)

        target_selectors = {
            a.selector for a in self.assets if getattr(a, "selector", None)
        }
        available_inputs = target_selectors | all_out_selectors

        for in_sel in all_in_selectors:
            # Check if any available input satisfies this in_selector
            matched = any(
                self.selector_matches(target_selector=avail, pattern=in_sel)
                for avail in available_inputs
            )
            if not matched:
                warning = BiosWarning(
                    code="STARVATION",
                    message=(
                        f"Agent input selector '{in_sel}' is neither injected nor produced by any agent in the group."
                    ),
                )
                self.warnings.append(warning)
                logger.warning(warning.message)

        if self.fail_on_warnings and self.warnings:
            raise BiosCheckError(
                f"[BIOS POST FAILED] Warnings treated as errors: {self.warnings}"
            )

    @staticmethod
    def selector_matches(target_selector: str, pattern: str) -> bool:
        """Matches a target selector against an agent pattern (supports exact and wildcards like # or *)."""
        if pattern == "#" or pattern == "*":
            return True
        if pattern.endswith(".#"):
            prefix = pattern[:-2]
            return target_selector == prefix or target_selector.startswith(prefix + ".")
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            return target_selector.startswith(prefix + ".")
        return target_selector == pattern
