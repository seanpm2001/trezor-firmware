from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.wire.thp import ChannelContext


class Retransmission:

    def __init__(
        self, channel_context: ChannelContext, ctrl_byte: int, payload: memoryview
    ) -> None:
        self.channel_context: ChannelContext = channel_context
        self.ctrl_byte: int = ctrl_byte
        self.payload: memoryview = payload

    def start(self):
        pass

    def stop(self):
        pass

    def change_ctrl_byte(self, ctrl_byte: int) -> None:
        self.ctrl_byte = ctrl_byte
