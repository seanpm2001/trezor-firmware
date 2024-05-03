from typing import TYPE_CHECKING

from trezor import protobuf

if TYPE_CHECKING:
    from trezorio import WireInterface
    from typing import Container, TypeVar, overload

    LoadedMessageType = TypeVar("LoadedMessageType", bound=protobuf.MessageType)
    T = TypeVar("T")


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


class Context:
    def __init__(self, iface: WireInterface, channel_id: bytes) -> None:
        self.iface: WireInterface = iface
        self.channel_id: bytes = channel_id

    if TYPE_CHECKING:

        @overload
        async def read(
            self, expected_types: Container[int]
        ) -> protobuf.MessageType: ...

        @overload
        async def read(
            self, expected_types: Container[int], expected_type: type[LoadedMessageType]
        ) -> LoadedMessageType: ...

    async def read(
        self,
        expected_types: Container[int],
        expected_type: type[protobuf.MessageType] | None = None,
    ) -> protobuf.MessageType: ...

    async def write(self, msg: protobuf.MessageType) -> None: ...

    if TYPE_CHECKING:

        @overload
        def cache_get(self, key: int) -> bytes | None: ...

        @overload
        def cache_get(self, key: int, default: T) -> bytes | T: ...

    def cache_get(self, key: int, default: T | None = None) -> bytes | T | None: ...

    def cache_get_int(self, key: int, default: T | None = None) -> int | T | None: ...

    def cache_is_set(self, key: int) -> bool: ...

    def cache_set(self, key: int, value: bytes) -> None: ...

    def cache_set_int(self, key: int, value: int) -> None: ...


class WireError(Exception):
    pass
