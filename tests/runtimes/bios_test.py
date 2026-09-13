"""Unit tests for ScanBios pre-scan verification engine."""

import pytest

from ostorlab.assets import domain_name, extensible_asset
from ostorlab.runtimes import bios, definitions


def testScanBios_whenValidAssetMatchesInSelector_passesCheck():
    agent_settings = definitions.AgentSettings(
        key="agent/ostorlab/aws_scout",
        in_selectors=["v4.asset.cloud.aws.#"],
        out_selectors=["v3.report.vulnerability"],
    )
    agent_group = definitions.AgentGroupDefinition(agents=[agent_settings])
    target = extensible_asset.ExtensibleAsset(
        selector="v4.asset.cloud.aws.account",
        data={"account_id": "123"},
    )

    validator = bios.ScanBios(agent_group_definition=agent_group, assets=[target])
    validator.check()


def testScanBios_whenAssetHasNoConsumer_raisesBiosCheckError():
    agent_settings = definitions.AgentSettings(
        key="agent/ostorlab/nmap",
        in_selectors=["v3.asset.ip.v4"],
        out_selectors=["v3.asset.ip.v4.port"],
    )
    agent_group = definitions.AgentGroupDefinition(agents=[agent_settings])
    target = extensible_asset.ExtensibleAsset(
        selector="v4.asset.cloud.azure.subscription",
        data={"sub_id": "xyz"},
    )

    validator = bios.ScanBios(agent_group_definition=agent_group, assets=[target])
    with pytest.raises(bios.BiosCheckError) as exc_info:
        validator.check()

    assert "Unhandled Target Asset" in str(exc_info.value)
    assert "v4.asset.cloud.azure.subscription" in str(exc_info.value)


def testScanBios_whenEmptyAgentGroup_raisesBiosCheckError():
    agent_group = definitions.AgentGroupDefinition(agents=[])
    target = domain_name.DomainName(name="ostorlab.co")

    validator = bios.ScanBios(agent_group_definition=agent_group, assets=[target])
    with pytest.raises(bios.BiosCheckError) as exc_info:
        validator.check()

    assert "Agent group contains no agents" in str(exc_info.value)


def testScanBios_whenAssetFailsJsonSchema_raisesBiosCheckError():
    agent_settings = definitions.AgentSettings(
        key="agent/ostorlab/aws_scout",
        in_selectors=["v4.asset.cloud.aws"],
        asset_schemas={
            "v4.asset.cloud.aws": {
                "type": "object",
                "required": ["account_id", "region"],
                "properties": {
                    "account_id": {"type": "string"},
                    "region": {"type": "string"},
                },
            }
        },
    )
    agent_group = definitions.AgentGroupDefinition(agents=[agent_settings])
    # Missing required 'region'
    target = extensible_asset.ExtensibleAsset(
        selector="v4.asset.cloud.aws",
        data={"account_id": "12345"},
    )

    validator = bios.ScanBios(agent_group_definition=agent_group, assets=[target])
    with pytest.raises(bios.BiosCheckError) as exc_info:
        validator.check()

    assert "Asset schema validation error" in str(exc_info.value)


def testScanBios_whenAssetPassesJsonSchema_passesCheck():
    agent_settings = definitions.AgentSettings(
        key="agent/ostorlab/aws_scout",
        in_selectors=["v4.asset.cloud.aws"],
        asset_schemas={
            "v4.asset.cloud.aws": {
                "type": "object",
                "required": ["account_id", "region"],
                "properties": {
                    "account_id": {"type": "string"},
                    "region": {"type": "string"},
                },
            }
        },
    )
    agent_group = definitions.AgentGroupDefinition(agents=[agent_settings])
    target = extensible_asset.ExtensibleAsset(
        selector="v4.asset.cloud.aws",
        data={"account_id": "12345", "region": "eu-west-1"},
    )

    validator = bios.ScanBios(agent_group_definition=agent_group, assets=[target])
    validator.check()


def testScanBios_whenWildcardInSelector_matchesCorrectly():
    agent_settings = definitions.AgentSettings(
        key="agent/ostorlab/wildcard_agent",
        in_selectors=["#"],
    )
    agent_group = definitions.AgentGroupDefinition(agents=[agent_settings])
    target = extensible_asset.ExtensibleAsset(
        selector="v4.asset.any.type",
        data={"foo": "bar"},
    )

    validator = bios.ScanBios(agent_group_definition=agent_group, assets=[target])
    validator.check()
