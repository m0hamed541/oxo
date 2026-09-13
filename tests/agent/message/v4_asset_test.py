"""Tests for v4.asset serialization and deserialization."""

import json

from ostorlab.agent.message import message, serializer
from ostorlab.assets import extensible_asset


def testV4AssetSerializer_whenValidPayload_serializesAndDeserializesCorrectly():
    selector = "v4.asset.cloud.aws.account"
    payload = {
        "account_id": "123456789012",
        "regions": ["us-east-1", "eu-west-1"],
        "metadata": {"env": "prod"},
    }

    proto_msg = serializer.serialize(selector, payload)
    assert proto_msg.selector == selector
    assert proto_msg.content_type == "application/json"
    assert proto_msg.schema_version == "1.0.0"

    decoded_payload = json.loads(proto_msg.payload.decode("utf-8"))
    assert decoded_payload == payload

    serialized_bytes = proto_msg.SerializeToString()
    deserialized_msg = serializer.deserialize(selector, serialized_bytes)
    assert deserialized_msg.selector == selector

    # Test Message abstraction
    msg = message.Message.from_raw(selector, serialized_bytes)
    assert msg.selector == selector
    assert msg.data == payload


def testV4AssetSerializer_whenUsingExtensibleAsset_producesValidBinaryProto():
    selector = "v4.asset.database.postgres"
    data = {"host": "10.0.0.5", "port": 5432, "database": "users"}

    asset = extensible_asset.ExtensibleAsset(selector=selector, data=data)
    assert asset.selector == selector
    assert asset.proto_field == "v4_asset"

    raw_bytes = asset.to_proto()
    assert isinstance(raw_bytes, bytes)

    msg = message.Message.from_raw(selector, raw_bytes)
    assert msg.data == data


def testV4AssetSerializer_whenLegacyV3Asset_maintainsFullBackwardCompatibility():
    selector = "v3.asset.domain_name"
    data = {"name": "example.com"}

    proto_msg = serializer.serialize(selector, data)
    assert proto_msg.name == "example.com"

    raw_bytes = proto_msg.SerializeToString()
    msg = message.Message.from_raw(selector, raw_bytes)
    assert msg.data["name"] == "example.com"
