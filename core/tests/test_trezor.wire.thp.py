from common import *

from apps.thp import pairing
from trezor.enums import ThpPairingMethod, MessageType
from trezor.wire.errors import UnexpectedMessage
from trezor.wire.protocol_common import MessageWithId
from trezor.wire.thp.pairing_context import PairingContext
from trezor.messages import (
    ThpEndRequest,
    ThpNfcUnidirectionalTag,
    ThpStartPairingRequest,
)
from trezor import io, protobuf
from trezor.loop import wait
from trezor.wire import thp_v1
from trezor.wire.thp import interface_manager
from storage import cache_thp
from trezor.wire.thp import ChannelState


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

        # tag_qrc = b"\x55\xdf\x6c\xba\x0b\xe9\x5e\xd1\x4b\x78\x61\xec\xfa\x07\x9b\x5d\x37\x60\xd8\x79\x9c\xd7\x89\xb4\x22\xc1\x6f\x39\xde\x8f\x3b\xc3"
        tag_nfc = b"\x8f\xf0\xfa\x37\x0a\x5b\xdb\x29\x32\x21\xd8\x2f\x95\xdd\xb6\xb8\xee\xfd\x28\x6f\x56\x9f\xa9\x0b\x64\x8c\xfc\x62\x46\x5a\xdd\xd0"
        session_id = bytearray(b"\x00")

        # msg = ThpQrCodeTag(tag=tag_qrc)
        msg = ThpNfcUnidirectionalTag(tag=tag_nfc)
        buffer: bytearray = bytearray(protobuf.encoded_length(msg))
        protobuf.encode(buffer, msg)
        qr_code_tag = MessageWithId(
            MessageType.ThpNfcUnidirectionalTag, buffer, session_id
        )
        gen.send(qr_code_tag)

        msg = ThpEndRequest()

        buffer: bytearray = bytearray(protobuf.encoded_length(msg))
        protobuf.encode(buffer, msg)
        end_request = MessageWithId(1012, buffer, session_id)
        with self.assertRaises(StopIteration) as e:
            gen.send(end_request)
        print("response message:", e.value.value.MESSAGE_NAME)


if __name__ == "__main__":
    unittest.main()
