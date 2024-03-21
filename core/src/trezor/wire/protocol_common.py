from trezor import protobuf


class Message:
    def __init__(
        self,
        message_data: bytes,
    ) -> None:
        self.data = message_data

    def to_bytes(self):
        return self.data


class MessageWithType(Message):
    def __init__(
        self,
        message_type: int,
        message_data: bytes,
    ) -> None:
        self.type = message_type
        super().__init__(message_data)

    def to_bytes(self):
        return self.type.to_bytes(2, "big") + self.data


class MessageWithId(MessageWithType):
    def __init__(
        self,
        message_type: int,
        message_data: bytes,
        session_id: bytearray | None = None,
    ) -> None:
        self.session_id = session_id
        super().__init__(message_type, message_data)


class WireError(Exception):
    pass


class Context:
    def __init__(self, iface, channel_id) -> None:
        self.iface = iface
        self.channel_id = channel_id

    async def write(self, msg: protobuf.MessageType) -> None: ...
