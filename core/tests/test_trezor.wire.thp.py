from common import *

from apps.thp import pairing
from trezor.enums import ThpPairingMethod, MessageType
from trezor.wire.errors import UnexpectedMessage
from trezor.wire.protocol_common import MessageWithId
from trezor.wire.thp.pairing_context import PairingContext
from trezor.messages import (
    ThpCodeEntryChallenge,
    ThpCodeEntryCpaceHost,
    ThpCodeEntryTag,
    ThpCredentialRequest,
    ThpEndRequest,
    ThpStartPairingRequest,
)
from trezor import io, protobuf
from trezor.loop import wait
from trezor.wire import thp_v1
from trezor.wire.thp import interface_manager
from storage import cache_thp
from trezor.wire.thp import ChannelState
from trezor.crypto import elligator2
from trezor.crypto.curve import curve25519


class MockHID:
    def __init__(self, num):
        self.num = num
        self.data = []

    def iface_num(self):
        return self.num

    def write(self, msg):
        self.data.append(bytearray(msg))
        return len(msg)

    def wait_object(self, mode):
        return wait(mode | self.num)


def dummy_decode_iface(cached_iface: bytes):
    return MockHID(0xDEADBEEF)


def getBytes(a):
    return hexlify(a).decode("utf-8")


class TestTrezorHostProtocol(unittest.TestCase):
    def setUp(self):
        self.interface = MockHID(0xDEADBEEF)
        buffer = bytearray(64)
        thp_v1.set_buffer(buffer)
        interface_manager.decode_iface = dummy_decode_iface

    def test_simple(self):
        self.assertTrue(True)

    def test_channel_allocation(self):
        cid_req = (
            b"\x40\xff\xff\x00\x0c\x00\x11\x22\x33\x44\x55\x66\x77\x96\x64\x3c\x6c"
        )
        expected_response = "41ffff001e001122334455667712340a0454335731100518002001280128026dcad4ba0000000000000000000000000000000000000000000000000000000000"
        test_counter = cache_thp.cid_counter + 1
        self.assertEqual(len(thp_v1.CHANNELS), 0)
        self.assertFalse(test_counter in thp_v1.CHANNELS)
        gen = thp_v1.thp_main_loop(self.interface, is_debug_session=True)
        query = gen.send(None)
        self.assertObjectEqual(query, self.interface.wait_object(io.POLL_READ))
        gen.send(cid_req)
        gen.send(None)
        self.assertEqual(
            getBytes(self.interface.data[-1]),
            expected_response,
        )
        self.assertTrue(test_counter in thp_v1.CHANNELS)
        self.assertEqual(len(thp_v1.CHANNELS), 1)

    def test_channel_default_state_is_TH1(self):
        self.assertEqual(thp_v1.CHANNELS[4660].get_channel_state(), ChannelState.TH1)

    def test_pairing(self):
        channel = thp_v1.CHANNELS[4660]
        channel.selected_pairing_methods = [
            ThpPairingMethod.PairingMethod_CodeEntry,
            ThpPairingMethod.PairingMethod_NFC_Unidirectional,
            ThpPairingMethod.PairingMethod_QrCode,
        ]
        pairing_ctx = PairingContext(channel)
        request_message = ThpStartPairingRequest()
        with self.assertRaises(UnexpectedMessage) as e:
            pairing.handle_pairing_request(pairing_ctx, request_message)
        print(e.value.message)
        channel.set_channel_state(ChannelState.TP1)
        gen = pairing.handle_pairing_request(pairing_ctx, request_message)
        gen.send(None)

        session_id = bytearray(b"\x00")

        msg_code_entry = ThpCodeEntryChallenge(challenge=b"\x12\x34")
        buffer: bytearray = bytearray(protobuf.encoded_length(msg_code_entry))
        protobuf.encode(buffer, msg_code_entry)
        code_entry_challenge = MessageWithId(
            MessageType.ThpCodeEntryChallenge, buffer, session_id
        )
        gen.send(code_entry_challenge)

        # tag_qrc = b"\x55\xdf\x6c\xba\x0b\xe9\x5e\xd1\x4b\x78\x61\xec\xfa\x07\x9b\x5d\x37\x60\xd8\x79\x9c\xd7\x89\xb4\x22\xc1\x6f\x39\xde\x8f\x3b\xc3"
        # tag_nfc = b"\x8f\xf0\xfa\x37\x0a\x5b\xdb\x29\x32\x21\xd8\x2f\x95\xdd\xb6\xb8\xee\xfd\x28\x6f\x56\x9f\xa9\x0b\x64\x8c\xfc\x62\x46\x5a\xdd\xd0"

        pregenerator_host = b"\xf6\x94\xc3\x6f\xb3\xbd\xfb\xba\x2f\xfd\x0c\xd0\x71\xed\x54\x76\x73\x64\x37\xfa\x25\x85\x12\x8d\xcf\xb5\x6c\x02\xaf\x9d\xe8\xbe"
        generator_host = elligator2.map_to_curve25519(pregenerator_host)
        cpace_host_private_key = b"\x02\x80\x70\x3c\x06\x45\x19\x75\x87\x0c\x82\xe1\x64\x11\xc0\x18\x13\xb2\x29\x04\xb3\xf0\xe4\x1e\x6b\xfd\x77\x63\x11\x73\x07\xa9"
        cpace_host_public_key: bytes = curve25519.multiply(
            cpace_host_private_key, generator_host
        )
        msg = ThpCodeEntryCpaceHost(cpace_host_public_key=cpace_host_public_key)

        # msg = ThpQrCodeTag(tag=tag_qrc)
        # msg = ThpNfcUnidirectionalTag(tag=tag_nfc)
        buffer: bytearray = bytearray(protobuf.encoded_length(msg))

        protobuf.encode(buffer, msg)
        user_message = MessageWithId(
            MessageType.ThpCodeEntryCpaceHost, buffer, session_id
        )
        gen.send(user_message)

        tag_ent = b"\xf5\x20\xee\xae\xb8\xa9\x65\x3e\x77\x89\x8f\x81\x8d\x03\x4d\xaa\x93\x79\xc3\xe4\x89\x3c\xb8\x31\x42\xdc\x01\x57\x2d\x5d\x11\xb5"

        msg = ThpCodeEntryTag(tag=tag_ent)

        buffer: bytearray = bytearray(protobuf.encoded_length(msg))

        protobuf.encode(buffer, msg)
        user_message = MessageWithId(MessageType.ThpCodeEntryTag, buffer, session_id)
        gen.send(user_message)

        host_static_pubkey = b"\x00\x11\x22\x33\x44\x55\x66\x77\x00\x11\x22\x33\x44\x55\x66\x77\x00\x11\x22\x33\x44\x55\x66\x77\x00\x11\x22\x33\x44\x55\x66\x77\x00\x11\x22\x33\x44\x55\x66\x77\x00\x11\x22\x33\x44\x55\x66\x77"
        msg = ThpCredentialRequest(host_static_pubkey=host_static_pubkey)
        buffer: bytearray = bytearray(protobuf.encoded_length(msg))
        protobuf.encode(buffer, msg)
        credential_request = MessageWithId(
            MessageType.ThpCredentialRequest, buffer, session_id
        )
        gen.send(credential_request)

        msg = ThpEndRequest()

        buffer: bytearray = bytearray(protobuf.encoded_length(msg))
        protobuf.encode(buffer, msg)
        end_request = MessageWithId(1012, buffer, session_id)
        with self.assertRaises(StopIteration) as e:
            gen.send(end_request)
        print("response message:", e.value.value.MESSAGE_NAME)


if __name__ == "__main__":
    unittest.main()


# trezor.wire.thp.credential_manager DEBUG credential raw: 0a020a001220fd9ad35963ea06ebfea46590388503d8b78353b6b762b08c96832fbe2ff03a9f
