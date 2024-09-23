from __future__ import annotations

import logging

from ... import messages
from ...mapping import ProtobufMapping
from .channel_data import ChannelData
from .transport import NewTransport

LOG = logging.getLogger(__name__)


class ProtocolAndChannel:

    def __init__(
        self,
        transport: NewTransport,
        mapping: ProtobufMapping,
        channel_data: ChannelData | None = None,
    ) -> None:
        self.transport = transport
        self.mapping = mapping
        self.channel_keys = channel_data

    def close(self) -> None: ...

    # def write(self, session_id: bytes, msg: t.Any) -> None: ...

    # def read(self, session_id: bytes) -> t.Any: ...

    def get_features(self) -> messages.Features:
        raise NotImplementedError()

    def get_channel_data(self) -> ChannelData:
        raise NotImplementedError

    def update_features(self) -> None:
        raise NotImplementedError
