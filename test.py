#!/usr/bin/python3


from byx import *

import unittest


class TestNormalizeInput(unittest.TestCase):
    def test_bytes(self):
        self.assertEqual(normalize_input('bytes', b'ABCD\x00'), b'ABCD\x00')
        self.assertEqual(normalize_input('hexstr', '4142434400'), b'ABCD\x00')
        self.assertEqual(normalize_input('big-endian bytes', b'ABCD\x00'),
                         EndiannedBytes(b'ABCD\x00', endianness='big-endian'))

    def test_integers(self):
        self.assertEqual(normalize_input('decimal', '34'), 34)
        self.assertEqual(normalize_input('octal', '31'), 25)
        self.assertEqual(normalize_input('signed hexadecimal short', '0xffff'),
                         -1)

    def test_widthlist(self):
        self.assertEqual(normalize_input('signed hexadecimal short list',
                                         '[0, ffff, 0x010]'), [0, -1, 16])


class TestConvert(unittest.TestCase):
    def test_byte_to_byte(self):
        self.assertEqual(convert('bytes', b'ABCD'), b'ABCD')
        self.assertEqual(convert('hexstr', b'ABCD'), '41424344')

    def test_byte_to_integer(self):
        ebytes = EndiannedBytes(b'ABCD', endianness='big-endian')
        self.assertEqual(convert('integer', ebytes), 0x41424344)
        self.assertEqual(convert('hexadecimal', ebytes), '41424344')

    def test_byte_to_widthlist(self):
        ebytes = EndiannedBytes(b'ABCD', endianness='big-endian')
        self.assertEqual(convert('unsigned hexadecimal int list', ebytes),
                         ['41424344'])

        sebytes = EndiannedBytes(b'\xff\xff\xfe\xff',
                                 endianness='little-endian')
        self.assertEqual(convert('signed short list', sebytes), [-1, -2])

    def test_integer_to_integer(self):
        self.assertEqual(convert('integer', 0x41424344), 0x41424344)
        self.assertEqual(convert('octal', 0x41424344), '10120441504')

    def test_integer_to_width(self):
        self.assertEqual(convert('unsigned byte', 0x41424344), 0x44)

    def test_integer_to_bytes(self):
        self.assertEqual(convert('little-endian bytes', 0x4142434445),
                         b'EDCBA')


def main():
    unittest.main(__name__)

if __name__ == '__main__':
    main()
