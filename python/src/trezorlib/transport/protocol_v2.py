import hashlib
import hmac
import logging
from enum import IntEnum
from typing import Optional, Tuple

from ..mapping import ProtobufMapping
from ..protobuf import MessageType
from ..transport.protocol import Handle, Protocol
from .thp.packet_header import PacketHeader

LOG = logging.getLogger(__name__)


def _sha256_of_two(val_1: bytes, val_2: bytes) -> bytes:
    hash = hashlib.sha256(val_1)
    hash.update(val_2)
    return hash.digest()


def _hkdf(chaining_key: bytes, input: bytes):
    temp_key = hmac.new(chaining_key, input, hashlib.sha256).digest()
    output_1 = hmac.new(temp_key, b"\x01", hashlib.sha256).digest()
    ctx_output_2 = hmac.new(temp_key, output_1, hashlib.sha256)
    ctx_output_2.update(b"\x02")
    output_2 = ctx_output_2.digest()
    return (output_1, output_2)


def _get_iv_from_nonce(nonce: int) -> bytes:
    if not nonce <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Nonce overflow, terminate the channel")
    return bytes(4) + nonce.to_bytes(8, "big")


class DeprecatedProtocolV2(Protocol):
    def __init__(self, handle: Handle) -> None:
        super().__init__(handle)

    def initialize_connection(
        self,
        mapping: ProtobufMapping,
        session_id: Optional[bytes] = None,
        derive_caradano: Optional[bool] = None,
    ):
        # self.session_id: int = 0
        # self.sync_bit_send: int = 0
        # self.sync_bit_receive: int = 0
        # self.mapping = mapping
        # # Send channel allocation request
        # channel_id_request_nonce = os.urandom(8)
        # thp_io.write_payload_to_wire_and_add_checksum(
        #     self.handle,
        #     PacketHeader.get_channel_allocation_request_header(12),
        #     channel_id_request_nonce,
        # )

        # # Read channel allocation response
        # header, payload = self._read_until_valid_crc_check()
        # if not self._is_valid_channel_allocation_response(
        #     header, payload, channel_id_request_nonce
        # ):
        #     print("TODO raise exception here, I guess")

        # self.cid = int.from_bytes(payload[8:10], "big")
        # self.device_properties = payload[10:]

        # # Send handshake init request
        # ha_init_req_header = PacketHeader(0, self.cid, 36)
        # host_ephemeral_privkey = curve25519.get_private_key(os.urandom(32))
        # host_ephemeral_pubkey = curve25519.get_public_key(host_ephemeral_privkey)

        # thp_io.write_payload_to_wire_and_add_checksum(
        #     self.handle, ha_init_req_header, host_ephemeral_pubkey
        # )

        # # Read ACK
        # header, payload = self._read_until_valid_crc_check()
        # if not header.is_ack() or len(payload) > 0:
        #     print("Received message is not a valid ACK ")

        # # Read handshake init response
        # header, payload = self._read_until_valid_crc_check()
        # self._send_ack_1()

        # if not header.is_handshake_init_response():
        #     print("Received message is not a valid handshake init response message")

        # trezor_ephemeral_pubkey = payload[:32]
        # encrypted_trezor_static_pubkey = payload[32:80]
        # noise_tag = payload[80:96]

        # # TODO check noise tag
        # print("noise_tag: ", hexlify(noise_tag).decode())

        # # Prepare and send handshake completion request
        # PROTOCOL_NAME = b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"
        # IV_1 = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        # IV_2 = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        # h = _sha256_of_two(PROTOCOL_NAME, self.device_properties)
        # h = _sha256_of_two(h, host_ephemeral_pubkey)
        # h = _sha256_of_two(h, trezor_ephemeral_pubkey)
        # ck, k = _hkdf(
        #     PROTOCOL_NAME,
        #     curve25519.multiply(host_ephemeral_privkey, trezor_ephemeral_pubkey),
        # )

        # aes_ctx = AESGCM(k)
        # try:
        #     trezor_masked_static_pubkey = aes_ctx.decrypt(
        #         IV_1, encrypted_trezor_static_pubkey, h
        #     )
        #     # print("masked_key", hexlify(trezor_masked_static_pubkey).decode())
        # except Exception as e:
        #     print(type(e))  # TODO how to handle potential exceptions? Q for Matejcik
        # h = _sha256_of_two(h, encrypted_trezor_static_pubkey)
        # ck, k = _hkdf(
        #     ck, curve25519.multiply(host_ephemeral_privkey, trezor_masked_static_pubkey)
        # )
        # aes_ctx = AESGCM(k)

        # tag_of_empty_string = aes_ctx.encrypt(IV_1, b"", h)
        # h = _sha256_of_two(h, tag_of_empty_string)
        # # TODO: search for saved credentials (or possibly not, as we skip pairing phase)

        # zeroes_32 = int.to_bytes(0, 32, "little")
        # temp_host_static_privkey = curve25519.get_private_key(zeroes_32)
        # temp_host_static_pubkey = curve25519.get_public_key(temp_host_static_privkey)
        # aes_ctx = AESGCM(k)
        # encrypted_host_static_pubkey = aes_ctx.encrypt(IV_2, temp_host_static_pubkey, h)
        # h = _sha256_of_two(h, encrypted_host_static_pubkey)
        # ck, k = _hkdf(
        #     ck, curve25519.multiply(temp_host_static_privkey, trezor_ephemeral_pubkey)
        # )
        # msg_data = mapping.encode_without_wire_type(
        #     messages.ThpHandshakeCompletionReqNoisePayload(
        #         pairing_methods=[
        #             messages.ThpPairingMethod.NoMethod,
        #         ]
        #     )
        # )

        # aes_ctx = AESGCM(k)

        # encrypted_payload = aes_ctx.encrypt(IV_1, msg_data, h)
        # h = _sha256_of_two(h, encrypted_payload)
        # ha_completion_req_header = PacketHeader(
        #     0x12,
        #     self.cid,
        #     len(encrypted_host_static_pubkey)
        #     + len(encrypted_payload)
        #     + CHECKSUM_LENGTH,
        # )
        # thp_io.write_payload_to_wire_and_add_checksum(
        #     self.handle,
        #     ha_completion_req_header,
        #     encrypted_host_static_pubkey + encrypted_payload,
        # )

        # # Read ACK
        # header, payload = self._read_until_valid_crc_check()
        # if not header.is_ack() or len(payload) > 0:
        #     print("Received message is not a valid ACK ")

        # # Read handshake completion response, ignore payload as we do not care about the state
        # header, _ = self._read_until_valid_crc_check()
        # if not header.is_handshake_comp_response():
        #     print("Received message is not a valid handshake completion response")
        # self._send_ack_2()

        # self.key_request, self.key_response = _hkdf(ck, b"")
        # self.nonce_request: int = 0
        # self.nonce_response: int = 1

        # # Send StartPairingReqest message
        # message = messages.ThpStartPairingRequest()
        # message_type, message_data = mapping.encode(message)

        # self._encrypt_and_write(message_type.to_bytes(2, "big"), message_data)

        # # Read ACK
        # header, payload = self._read_until_valid_crc_check()
        # if not header.is_ack() or len(payload) > 0:
        #     print("Received message is not a valid ACK ")

        # # Read
        # _, msg_type, msg_data = self.read_and_decrypt()
        # maaa = mapping.decode(msg_type, msg_data)
        # self._send_ack_1()

        # assert isinstance(maaa, messages.ThpEndResponse)

        # # Send get features
        # message = messages.GetFeatures()
        # message_type, message_data = mapping.encode(message)

        # self.session_id: int = 0
        # self._encrypt_and_write(message_type.to_bytes(2, "big"), message_data, 0x14)
        # _ = thp_io.read(self.handle)
        # session_id, msg_type, msg_data = self.read_and_decrypt()
        # features = mapping.decode(msg_type, msg_data)
        # assert isinstance(features, messages.Features)
        # features.session_id = int.to_bytes(self.cid, 2, "big") + session_id
        # self._send_ack_2()
        # return features
        ...

    def _encrypt_and_write(
        self, message_type: bytes, message_data: bytes, ctrl_byte: int = 0x04
    ) -> None:
        # assert self.key_request is not None
        # aes_ctx = AESGCM(self.key_request)
        # data = self.session_id.to_bytes(1, "big") + message_type + message_data
        # nonce = _get_iv_from_nonce(self.nonce_request)
        # self.nonce_request += 1
        # encrypted_message = aes_ctx.encrypt(nonce, data, b"")
        # header = PacketHeader(
        #     ctrl_byte, self.cid, len(encrypted_message) + CHECKSUM_LENGTH
        # )

        # thp_io.write_payload_to_wire_and_add_checksum(
        #     self.handle, header, encrypted_message
        # )
        ...

    def _write_message(self, message: MessageType, mapping: ProtobufMapping):
        try:
            message_type, message_data = mapping.encode(message)
            self.write(message_type, message_data)
        except Exception as e:
            print(type(e))

    def write(self, message_type: int, message_data: bytes) -> None:
        # data = (
        #     self.session_id.to_bytes(1, "big")
        #     + message_type.to_bytes(2, "big")
        #     + message_data
        # )
        # ctrl_byte = 0x04
        # self._write_and_encrypt(data, ctrl_byte)
        ...

    def _write_and_encrypt(self, data: bytes, ctrl_byte: int) -> None:
        # aes_ctx = AESGCM(self.key_request)
        # nonce = _get_iv_from_nonce(self.nonce_request)
        # self.nonce_request += 1
        # encrypted_data = aes_ctx.encrypt(nonce, data, b"")
        # header = PacketHeader(
        #     ctrl_byte, self.cid, len(encrypted_data) + CHECKSUM_LENGTH
        # )
        # thp_io.write_payload_to_wire_and_add_checksum(
        #     self.handle, header, encrypted_data
        # )
        ...

    def read_and_decrypt(self) -> Tuple[bytes, int, bytes]:
        # header, raw_payload = self._read_until_valid_crc_check()
        # if not header.is_encrypted_transport():
        #     print("Trying to decrypt not encrypted message!")
        # aes_ctx = AESGCM(self.key_response)
        # nonce = _get_iv_from_nonce(self.nonce_response)
        # self.nonce_response += 1

        # message = aes_ctx.decrypt(nonce, raw_payload, b"")
        # session_id = message[0]
        # message_type = message[1:3]
        # message_data = message[3:]
        # return (
        #     int.to_bytes(session_id, 1, "big"),
        #     int.from_bytes(message_type, "big"),
        #     message_data,
        # )
        ...

    def end_session(self, session_id: bytes) -> None:
        pass

    def resume_session(self, session_id: bytes) -> bytes:
        print("protocol 2 resume session")
        return self.start_session("")

    def start_session(self, passphrase: str) -> bytes:
        # try:
        #     msg = messages.ThpCreateNewSession(passphrase=passphrase)
        # except Exception as e:
        #     print(e)
        # print("s")

        # self._write_message(msg, self.mapping)
        # print("p")
        # response_type, response_data = self._read_until_valid_crc_check()
        # print(response_type, response_data)
        # return b""
        ...

    def read(self) -> Tuple[int, bytes]:
        # header, raw_payload, chksum = thp_io.read(self.handle)
        # print("Read message", hexlify(raw_payload))
        # return (0x00, header.to_bytes_init() + raw_payload + chksum)  # TODO change
        ...

    def _get_control_byte(self) -> bytes:
        return b"\x42"

    def _read_until_valid_crc_check(
        self,
    ) -> Tuple[PacketHeader, bytes]:
        # is_valid = False
        # header, payload, chksum = thp_io.read(self.handle)
        # while not is_valid:
        #     is_valid = checksum.is_valid(chksum, header.to_bytes_init() + payload)
        #     if not is_valid:
        #         print(hexlify(header.to_bytes_init() + payload + chksum))
        #         LOG.debug("Received a message with invalid checksum")
        #         header, payload, chksum = thp_io.read(self.handle)

        # return header, payload
        ...

    def _is_valid_channel_allocation_response(
        self, header: PacketHeader, payload: bytes, original_nonce: bytes
    ) -> bool:
        if not header.is_channel_allocation_response():
            print("Received message is not a channel allocation response")
            return False
        if len(payload) < 10:
            print("Invalid channel allocation response payload")
            return False
        if payload[:8] != original_nonce:
            print("Invalid channel allocation response payload (nonce mismatch)")
            return False
        return True

    class ControlByteType(IntEnum):
        CHANNEL_ALLOCATION_RES = 1
        HANDSHAKE_INIT_RES = 2
        HANDSHAKE_COMP_RES = 3
        ACK = 4
        ENCRYPTED_TRANSPORT = 5
