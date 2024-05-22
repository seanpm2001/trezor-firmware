from typing import TYPE_CHECKING

from trezor.wire.protocol_common import WireError


class ThpError(WireError):
    pass


if TYPE_CHECKING:
    from enum import IntEnum
    from trezorio import WireInterface
    from typing import List, Protocol, TypeVar

    from storage.cache_thp import ChannelCache
    from trezor import loop, protobuf, utils
    from trezor.enums import FailureType
    from trezor.wire.thp.pairing_context import PairingContext
    from trezor.wire.thp.session_context import GenericSessionContext

    T = TypeVar("T")

    class ChannelContext(Protocol):
        buffer: utils.BufferType
        iface: WireInterface
        channel_id: bytes
        channel_cache: ChannelCache
        selected_pairing_methods: List[int] = []  # TODO add type
        sessions: dict[int, GenericSessionContext]
        waiting_for_ack_timeout: loop.spawn | None
        write_task_spawn: loop.spawn | None
        connection_context: PairingContext | None

        def get_channel_state(self) -> int: ...

        def set_channel_state(self, state: "ChannelState") -> None: ...

        async def write(
            self, msg: protobuf.MessageType, session_id: int = 0
        ) -> None: ...

        async def write_error(self, err_type: FailureType, message: str) -> None: ...

        async def write_handshake_message(
            self, ctrl_byte: int, payload: bytes
        ) -> None: ...

        def decrypt_buffer(self, message_length: int) -> None: ...

        def get_channel_id_int(self) -> int: ...

else:
    IntEnum = object


class ChannelState(IntEnum):
    UNALLOCATED = 0
    TH1 = 1
    TH2 = 2
    TP1 = 3
    TP2 = 4
    TP3 = 5
    TP4 = 6
    TC1 = 7
    ENCRYPTED_TRANSPORT = 8


class SessionState(IntEnum):
    UNALLOCATED = 0
    ALLOCATED = 1
    MANAGEMENT = 2


class WireInterfaceType(IntEnum):
    MOCK = 0
    USB = 1
    BLE = 2


def is_channel_state_pairing(state: int) -> bool:
    if state in (
        ChannelState.TP1,
        ChannelState.TP2,
        ChannelState.TP3,
        ChannelState.TP4,
        ChannelState.TC1,
    ):
        return True
    return False


if __debug__:

    def state_to_str(state: int) -> str:
        name = {
            v: k for k, v in ChannelState.__dict__.items() if not k.startswith("__")
        }.get(state)
        if name is not None:
            return name
        return "UNKNOWN_STATE"
