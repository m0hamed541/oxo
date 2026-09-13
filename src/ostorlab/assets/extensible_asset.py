"""Generic extensible v4 asset implementation."""

from typing import Any

from ostorlab.assets import asset


class ExtensibleAsset(asset.Asset):
    """Generic asset representing any v4 asset dynamically without SDK releases."""

    def __init__(
        self,
        selector: str,
        data: dict[str, Any],
        schema_version: str = "1.0.0",
        content_type: str = "application/json",
    ) -> None:
        if not selector.startswith("v4.asset."):
            raise ValueError(
                f"ExtensibleAsset selector must start with 'v4.asset.', got '{selector}'"
            )
        self.selector = selector
        self.data = data
        self.schema_version = schema_version
        self.content_type = content_type

    def to_proto(self) -> bytes:
        from ostorlab.agent.message import serializer

        payload_dict = dict(self.data)
        payload_dict["_schema_version"] = self.schema_version
        payload_dict["_content_type"] = self.content_type
        return serializer.serialize(self.selector, payload_dict).SerializeToString()

    @property
    def proto_field(self) -> str:
        return "v4_asset"

    def __repr__(self) -> str:
        return f"ExtensibleAsset(selector='{self.selector}', data={self.data})"
