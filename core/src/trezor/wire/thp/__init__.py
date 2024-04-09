from typing import TYPE_CHECKING  # pyright: ignore[reportShadowedImports]

if TYPE_CHECKING:
    from enum import IntEnum
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


class WireInterfaceType(IntEnum):
    MOCK = 0
    USB = 1
    BLE = 2
