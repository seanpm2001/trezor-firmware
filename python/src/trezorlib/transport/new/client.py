from __future__ import annotations

import logging

from ... import mapping
from ...mapping import ProtobufMapping
from .channel_data import ChannelData
from .protocol_and_channel import ProtocolAndChannel, ProtocolV1
from .protocol_v2 import ProtocolV2
from .session import Session, SessionV1, SessionV2
from .transport import NewTransport

LOG = logging.getLogger(__name__)


class NewTrezorClient:
    management_session: Session | None = None

    def __init__(
        self,
        transport: NewTransport,
        protobuf_mapping: ProtobufMapping | None = None,
        protocol: ProtocolAndChannel | None = None,
    ) -> None:
        self.transport = transport

        if protobuf_mapping is None:
            self.mapping = mapping.DEFAULT_MAPPING
        else:
            self.mapping = protobuf_mapping
        if protocol is None:
            try:
                self.protocol = self._get_protocol()
            except Exception as e:
                print(e)
        else:
            self.protocol = protocol
        self.protocol.mapping = self.mapping

    @classmethod
    def resume(
        cls,
        transport: NewTransport,
        channel_data: ChannelData,
        protobuf_mapping: ProtobufMapping | None = None,
    ) -> NewTrezorClient:
        if protobuf_mapping is None:
            protobuf_mapping = mapping.DEFAULT_MAPPING
        if channel_data.protocol_version == 2:
            protocol = ProtocolV2(transport, protobuf_mapping, channel_data)
        else:
            protocol = ProtocolV1(transport, protobuf_mapping, channel_data)
        return NewTrezorClient(transport, protobuf_mapping, protocol)

    def get_session(
        self,
        passphrase: str | None = None,
        derive_cardano: bool = False,
    ) -> Session:
        if isinstance(self.protocol, ProtocolV1):
            return SessionV1.new(self, passphrase, derive_cardano)
        if isinstance(self.protocol, ProtocolV2):
            return SessionV2.new(self, passphrase, derive_cardano)
        raise NotImplementedError  # TODO

    def get_management_session(self):
        if self.management_session is not None:
            return self.management_session

        if isinstance(self.protocol, ProtocolV1):
            self.management_session = SessionV1.new(self, "", False)
        elif isinstance(self.protocol, ProtocolV2):
            self.management_session = SessionV2(self, b"\x00")
        assert self.management_session is not None
        return self.management_session

    def resume_session(self, session_id: bytes) -> Session:
        raise NotImplementedError  # TODO

    def _get_protocol(self) -> ProtocolAndChannel:

        from ... import mapping, messages
        from ...messages import FailureType
        from .protocol_and_channel import ProtocolV1

        self.transport.open()

        protocol = ProtocolV1(self.transport, mapping.DEFAULT_MAPPING)

        protocol.write(messages.Initialize())

        response = protocol.read()
        self.transport.close()
        if isinstance(response, messages.Failure):
            if (
                response.code == FailureType.UnexpectedMessage
                and response.message == "Invalid protocol"
            ):
                LOG.debug("Protocol V2 detected")
                protocol = ProtocolV2(self.transport, self.mapping)
        return protocol
