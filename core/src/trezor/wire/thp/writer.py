from micropython import const
from trezorcrypto import crc
from typing import TYPE_CHECKING

from trezor import io, log, loop, utils
from trezor.wire.thp.thp_messages import InitHeader

INIT_DATA_OFFSET = const(5)
CONT_DATA_OFFSET = const(3)
REPORT_LENGTH = const(64)
CHECKSUM_LENGTH = const(4)
MAX_PAYLOAD_LEN = const(60000)
MESSAGE_TYPE_LENGTH = const(2)

if TYPE_CHECKING:
    from trezorio import WireInterface
    from typing import Sequence


async def write_payload_to_wire_and_add_checksum(
    iface: WireInterface, header: InitHeader, transport_payload: bytes
):
    header_checksum: int = crc.crc32(header.to_bytes())
    checksum: bytes = crc.crc32(transport_payload, header_checksum).to_bytes(
        CHECKSUM_LENGTH, "big"
    )
    data = (transport_payload, checksum)
    await write_payloads_to_wire(iface, header, data)


async def write_payloads_to_wire(
    iface: WireInterface, header: InitHeader, data: Sequence[bytes]
):
    n_of_data = len(data)
    total_length = sum(len(item) for item in data)

    current_data_idx = 0
    current_data_offset = 0

    report = bytearray(REPORT_LENGTH)
    header.pack_to_buffer(report)
    report_offset: int = INIT_DATA_OFFSET
    report_number = 0
    nwritten = 0
    while nwritten < total_length:
        if report_number == 1:
            header.pack_to_cont_buffer(report)
        if report_number >= 1 and nwritten >= total_length - REPORT_LENGTH:
            report[:] = bytearray(REPORT_LENGTH)
            header.pack_to_cont_buffer(report)
        while True:
            n = utils.memcpy(
                report, report_offset, data[current_data_idx], current_data_offset
            )
            report_offset += n
            current_data_offset += n
            nwritten += n

            if report_offset < REPORT_LENGTH:
                current_data_idx += 1
                current_data_offset = 0
                if current_data_idx >= n_of_data:
                    break
            elif report_offset == REPORT_LENGTH:
                break
            else:
                raise Exception("Should not happen!!!")
        report_number += 1
        report_offset = CONT_DATA_OFFSET
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
