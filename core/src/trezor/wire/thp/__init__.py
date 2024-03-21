from typing import TYPE_CHECKING

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
    TP5 = 7
    ENCRYPTED_TRANSPORT = 8
