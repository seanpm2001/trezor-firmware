import struct
from binascii import hexlify
from typing import Tuple

from ..protocol import Handle
from ..thp import checksum
from .packet_header import PacketHeader

INIT_HEADER_LENGTH = 5
CONT_HEADER_LENGTH = 3
PACKET_LENGTH = 64
CHECKSUM_LENGTH = 4
MAX_PAYLOAD_LEN = 60000
MESSAGE_TYPE_LENGTH = 2

CONTINUATION_PACKET = 0x80


def write_payload_to_wire_and_add_checksum(
    handle: Handle, header: PacketHeader, transport_payload: bytes
):
    chksum: bytes = checksum.compute(header.to_bytes_init() + transport_payload)
    data = transport_payload + chksum
    write_payload_to_wire(handle, header, data)


def write_payload_to_wire(
    handle: Handle, header: PacketHeader, transport_payload: bytes
):
    handle.open()
    buffer = bytearray(transport_payload)
    chunk = header.to_bytes_init() + buffer[: PACKET_LENGTH - INIT_HEADER_LENGTH]
    chunk = chunk.ljust(PACKET_LENGTH, b"\x00")
    handle.write_chunk(chunk)

    buffer = buffer[PACKET_LENGTH - INIT_HEADER_LENGTH :]
    while buffer:
        chunk = header.to_bytes_cont() + buffer[: PACKET_LENGTH - CONT_HEADER_LENGTH]
        chunk = chunk.ljust(PACKET_LENGTH, b"\x00")
        handle.write_chunk(chunk)
        buffer = buffer[PACKET_LENGTH - CONT_HEADER_LENGTH :]


def read(handle: Handle) -> Tuple[PacketHeader, bytes, bytes]:
    buffer = bytearray()
    # Read header with first part of message data
    header, first_chunk = read_first(handle)
    buffer.extend(first_chunk)

    # Read the rest of the message
    while len(buffer) < header.data_length:
        buffer.extend(read_next(handle, header.cid))
    # print("buffer read (data):", hexlify(buffer).decode())
    # print("buffer len (data):", datalen)
    # TODO check checksum?? or do not strip ?
    data_len = header.data_length - CHECKSUM_LENGTH
    return header, buffer[:data_len], buffer[data_len : data_len + CHECKSUM_LENGTH]


def read_first(handle: Handle) -> Tuple[PacketHeader, bytes]:
    chunk = handle.read_chunk()
    try:
        ctrl_byte, cid, data_length = struct.unpack(
            PacketHeader.format_str_init, chunk[:INIT_HEADER_LENGTH]
        )
    except Exception:
        raise RuntimeError("Cannot parse header")

    data = chunk[INIT_HEADER_LENGTH:]
    return PacketHeader(ctrl_byte, cid, data_length), data


def read_next(handle: Handle, cid: int) -> bytes:
    chunk = handle.read_chunk()
    ctrl_byte, read_cid = struct.unpack(
        PacketHeader.format_str_cont, chunk[:CONT_HEADER_LENGTH]
    )
    if ctrl_byte != CONTINUATION_PACKET:
        raise RuntimeError("Continuation packet with incorrect control byte")
    if read_cid != cid:
        raise RuntimeError("Continuation packet for different channel")

    return chunk[CONT_HEADER_LENGTH:]
