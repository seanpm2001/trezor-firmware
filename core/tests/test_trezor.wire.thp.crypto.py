from common import *
from trezor import utils

if utils.USE_THP:
    from trezor.wire.thp import crypto


@unittest.skipUnless(utils.USE_THP, "only needed for THP")
class TestTrezorHostProtocolCrypto(unittest.TestCase):
    key_1 = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07"

    # 0:key, 1:nonce, 2:auth_data, 3:plaintext, 4:expected_ciphertext, 5:expected_tag
    vectors = [
        (
            key_1,
            0,
            b"\x55\x64",
            b"\x00\x01\x02\x03\x04\05\x06\x07\x08\x09",
            b"e2c9dd152fbee5821ea7",
            b"10625812de81b14a46b9f1e5100a6d0c",
        )
    ]

    def setUp(self):
        utils.DISABLE_ENCRYPTION = False

    def test_correct_vectors(self):
        for v in self.vectors:
            buffer = bytearray(v[3])
            tag = crypto.enc(buffer, v[0], v[1], v[2])
            self.assertEqual(hexlify(buffer), v[4])
            self.assertEqual(hexlify(tag), v[5])
            self.assertTrue(crypto.dec(buffer, tag, v[0], v[1], v[2]))
            self.assertEqual(buffer, v[3])

    def test_incorrect_vectors(self):
        pass


if __name__ == "__main__":
    unittest.main()
