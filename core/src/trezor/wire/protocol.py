from trezor import utils
from trezor.wire import codec_v1, thp_v1
from trezor.wire.protocol_common import Message
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezorio import WireInterface


class WireProtocol:
    async def read_message(
        self, iface: WireInterface, buffer: utils.BufferType
    ) -> Message:
        if utils.USE_THP:
            return await thp_v1.read_message(iface, buffer)
        return await codec_v1.read_message(iface, buffer)

    async def write_message(self, iface: WireInterface, message: Message) -> None:
        if utils.USE_THP:
            return thp_v1.write_to_wire(iface, message)
        return codec_v1.write_message(iface, message.type, message.data)
