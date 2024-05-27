from micropython import const  # pyright: ignore[reportMissingModuleSource]
from typing import TYPE_CHECKING  # pyright: ignore[reportShadowedImports]

from trezor import io, log, loop, utils
from trezor.wire.thp.thp_messages import InitHeader

INIT_DATA_OFFSET = const(5)
CONT_DATA_OFFSET = const(3)
REPORT_LENGTH = const(64)
MAX_PAYLOAD_LEN = const(60000)
MESSAGE_TYPE_LENGTH = const(2)

if TYPE_CHECKING:
    from trezorio import WireInterface  # pyright: ignore[reportMissingImports]


async def write_payload_to_wire(
    iface: WireInterface, header: InitHeader, transport_payload_with_crc: bytes
):
    if __debug__:
        log.debug(__name__, "write_payload_to_wire")
    # prepare the report buffer with header data
    payload_len = len(transport_payload_with_crc)

    # prepare the report buffer with header data
    report = bytearray(REPORT_LENGTH)
    header.pack_to_buffer(report)

    # write initial report
    nwritten = utils.memcpy(report, INIT_DATA_OFFSET, transport_payload_with_crc, 0)

    await _write_report_to_wire(iface, report)

    # if we have more data to write, use continuation reports for it
    if nwritten < payload_len:
        header.pack_to_cont_buffer(report)

    while nwritten < payload_len:
        if nwritten >= payload_len - REPORT_LENGTH:
            # Sanitation of last report
            report = bytearray(REPORT_LENGTH)
            header.pack_to_cont_buffer(report)

        nwritten += utils.memcpy(
            report, CONT_DATA_OFFSET, transport_payload_with_crc, nwritten
        )
        await _write_report_to_wire(iface, report)


async def _write_report_to_wire(iface: WireInterface, report: utils.BufferType) -> None:
    while True:
        await loop.wait(iface.iface_num() | io.POLL_WRITE)
        if __debug__:
            log.debug(
                __name__, "write_report_to_wire: %s", utils.get_bytes_as_str(report)
            )
        n = iface.write(report)
        if n == len(report):
            return
