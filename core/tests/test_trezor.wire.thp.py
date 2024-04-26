from common import *

from trezor import io
from trezor.loop import wait
from trezor.wire import thp_v1
from trezor.wire.thp import channel
from storage import cache_thp
from ubinascii import hexlify
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
        channel._decode_iface = dummy_decode_iface

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


if __name__ == "__main__":
    unittest.main()
