"""Asset of type v4 Asset (ExtensibleAsset).
This module takes care of preparing an arbitrary v4 asset from JSON or file to be injected onto the message bus.
"""

import json
import logging
from typing import Any

import click

from ostorlab import exceptions
from ostorlab.assets import extensible_asset
from ostorlab.cli import console as cli_console
from ostorlab.cli.scan.run import run

logger = logging.getLogger(__name__)
console = cli_console.Console()


@run.run.command(name="v4-asset")
@click.option(
    "--selector",
    "-s",
    required=True,
    help="Asset selector (e.g., v4.asset.cloud.aws, v4.asset.database.postgres).",
)
@click.option(
    "--data",
    "-d",
    required=False,
    help="Asset data as a JSON string.",
)
@click.option(
    "--file",
    "-f",
    "data_file",
    required=False,
    type=click.Path(exists=True),
    help="Path to a JSON file containing the asset data.",
)
@click.pass_context
def v4_asset_cli(
    ctx: click.core.Context,
    selector: str,
    data: str | None,
    data_file: str | None,
) -> None:
    """Run scan with an extensible v4 asset injected onto the message bus.

    Examples:
        - oxo scan run --agent=agent/ostorlab/aws_scout v4-asset --selector v4.asset.cloud.aws --data '{"account_id": "123"}'
        - oxo scan run --agent=agent/ostorlab/pg_scout v4-asset --selector v4.asset.database.postgres --file db.json
    """
    if not selector.startswith("v4.asset."):
        console.error(f"Selector must start with 'v4.asset.', got '{selector}'")
        raise click.exceptions.Exit(2)

    if data is None and data_file is None:
        console.error("Either --data or --file must be specified.")
        raise click.exceptions.Exit(2)

    payload_dict: dict[str, Any] = {}
    if data is not None:
        try:
            payload_dict = json.loads(data)
        except json.JSONDecodeError as e:
            console.error(f"Failed to parse JSON data: {e}")
            raise click.exceptions.Exit(2)
    elif data_file is not None:
        try:
            with open(data_file, "r", encoding="utf-8") as f:
                payload_dict = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            console.error(f"Failed to read JSON file '{data_file}': {e}")
            raise click.exceptions.Exit(2)

    runtime = ctx.obj["runtime"]
    assets = [extensible_asset.ExtensibleAsset(selector=selector, data=payload_dict)]

    logger.debug("injecting v4 asset %s", assets)
    try:
        created_scan = runtime.scan(
            title=ctx.obj["title"],
            agent_group_definition=ctx.obj["agent_group_definition"],
            assets=assets,
        )
        if created_scan is not None:
            runtime.link_agent_group_scan(
                created_scan, ctx.obj["agent_group_definition"]
            )
            runtime.link_assets_scan(created_scan.id, assets)

    except exceptions.OstorlabError as e:
        console.error(f"An error was encountered while running the scan: {e}")
        raise click.exceptions.Exit(2)
