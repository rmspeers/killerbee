import unittest
import struct
import argparse
import os

import pytest

import zigbee_crypt as _zc
from zigbee_crypt import *

KEY = bytes(range(16))

class TestPyZigbeeCryptSubstitute(unittest.TestCase):
    """Validates the pure-python substitute against the same known vectors."""

    def test_vectors(self):
        from conftest import PyZigbeeCrypt as P
        nonce = bytes(range(13))
        enc, mic = P.encrypt_ccm(KEY, nonce, 4, b'\x01\x02\x03\x04', b'\x00' * 4)
        self.assertEqual((b'\x17\x36\xb7\x8c', b'\xfc\xe0\xce\x86'), (enc, mic))
        self.assertEqual((b'\x01\x02\x03\x04', 1), P.decrypt_ccm(KEY, nonce, mic, enc, b'\x00' * 4))
        self.assertEqual((b'\x01\x02\x03\x04', 0), P.decrypt_ccm(KEY, nonce, b'\0\0\0\0', enc, b'\x00' * 4))
        e0, m0 = P.encrypt_ccm(KEY, nonce, 0, b'\x01\x02', b'')
        self.assertEqual(b'', m0)
        self.assertEqual(b'\x01\x02', P.decrypt_ccm(KEY, nonce, b'', e0, b'')[0])
        self.assertEqual(b'\xd2\x28\x9c\x6f\xeb\xfe\xdc\xb8\x91\xda\x27\xdc\xd0\xb6\x88\x5d',
                         P.sec_key_hash(KEY, b'\x00'))


class TestZigbeeCrypt(unittest.TestCase):
    def test_argument_validation(self):
        self.assertRaises(TypeError, _zc.encrypt_ccm)
        self.assertRaises(TypeError, _zc.decrypt_ccm, 1)
        self.assertRaises(TypeError, _zc.sec_key_hash, 1, 2)
        n = bytes(13)
        self.assertRaises(ValueError, _zc.sec_key_hash, b'short', b'\x00')
        self.assertRaises(ValueError, _zc.encrypt_ccm, b'short', n, 4, b'a', b'')
        self.assertRaises(ValueError, _zc.encrypt_ccm, KEY, b'short', 4, b'a', b'')
        self.assertRaises(ValueError, _zc.encrypt_ccm, KEY, n, 5, b'a', b'')
        self.assertRaises(ValueError, _zc.decrypt_ccm, KEY, n, bytes(17), b'a', b'')

    def test_roundtrip_and_tamper(self):
        n = bytes(range(13))
        for mic_len in (0, 4, 8, 16):
            for pt in (b'', b'x', bytes(range(40))):
                enc, mic = _zc.encrypt_ccm(KEY, n, mic_len, pt, b'hdr')
                self.assertEqual(len(mic), mic_len)
                self.assertEqual((pt, 1), _zc.decrypt_ccm(KEY, n, mic, enc, b'hdr'))
        enc, mic = _zc.encrypt_ccm(KEY, n, 4, b'abcd', b'hdr')
        self.assertEqual(0, _zc.decrypt_ccm(KEY, n, mic, enc, b'HDR')[1])

    def test_key_hash_with_embedded_nul(self):
        """Result is a full 16 bytes even if it contains NUL bytes."""
        self.assertEqual(16, len(_zc.sec_key_hash(bytes(16), b'\x00')))

    def test_encrypt_ccm(self):
        key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        nonce = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c'
        pt_data = b'\x01\x02\x03\x04'
        zigbee_data = b'\x00\x00\x00\x00'
        mic_len = 4 
       
        (enc_data, mic) = encrypt_ccm(key, nonce, mic_len, pt_data, zigbee_data)

        self.assertEqual(b'\x17\x36\xb7\x8c', enc_data)
        self.assertEqual(b'\xfc\xe0\xce\x86', mic)

    def test_decrypt_cm(self):
        key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        nonce = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c'
        enc_data = b'\x17\x36\xb7\x8c'
        mic = b'\xfc\xe0\xce\x86'
        zigbee_data = b'\x00\x00\x00\x00'
     
        (pt_data, mic_check) = decrypt_ccm(key, nonce, mic, enc_data, zigbee_data)
 
        self.assertEqual(b'\x01\x02\x03\x04', pt_data) 
        self.assertTrue(mic_check)

    def test_sec_key_hash(self):
        key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        key_hash = sec_key_hash(key, b'\x00') 
        self.assertEqual(b'\xd2\x28\x9c\x6f\xeb\xfe\xdc\xb8\x91\xda\x27\xdc\xd0\xb6\x88\x5d', key_hash)
        
if __name__ == "__main__":
    unittest.main()

