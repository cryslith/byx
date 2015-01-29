#!/usr/bin/python3


import binascii
import re
import sys
import argparse


BYTES = 'bytes'
HEX_STRING = 'hexstr'
BYTE_STRING_FORMATS = [BYTES, HEX_STRING]
BYTE_STRING_REGEX = '(?P<bytes>{})'.format('|'.join(BYTE_STRING_FORMATS))

BINARY = 'binary'
OCTAL = 'octal'
DECIMAL = 'decimal'
HEX = 'hexadecimal'
BASES = {BINARY: 2, OCTAL: 8, DECIMAL: 10, HEX: 16}
BASE_FORMATS = {BINARY: '{:b}', OCTAL: '{:o}', DECIMAL: '{}', HEX: '{:x}'}
BASE_REGEX = '(?P<base>{})'.format('|'.join(BASES))

INTEGER = 'integer'
INTEGER_REGEX = '({base}|{integer})'.format(base=BASE_REGEX, integer=INTEGER)

BYTE = 'byte'
SHORT = 'short'
INT = 'int'
LONG = 'long'
WIDTHS = {BYTE: 1, SHORT: 2, INT: 4, LONG: 8}
WIDTH_REGEX = '(?P<width>{})'.format('|'.join(WIDTHS))

SIGNED = 'signed'
UNSIGNED = 'unsigned'
SIGNS = [SIGNED, UNSIGNED]
SIGN_REGEX = '(?P<sign>{})'.format('|'.join(SIGNS))

BIG_ENDIAN = 'big-endian'
LITTLE_ENDIAN = 'little-endian'
ENDIANNESSES = [BIG_ENDIAN, LITTLE_ENDIAN]
ENDIANNESS_REGEX = '(?P<endianness>{})'.format('|'.join(ENDIANNESSES))


idfn = lambda x: x


def dehex(x):
    if isinstance(x, str):
        x = x.encode('ascii')
    return binascii.unhexlify(x)


def enhex(x):
    return binascii.hexlify(x).decode('ascii')


byte_string_converters = {BYTES: (idfn, idfn),
                          HEX_STRING: (dehex, enhex)}


base_converters = {base: ((lambda s, base=base: int(s, BASES[base])),
                          (lambda n, base=base:
                               BASE_FORMATS[base].format(n)))
                   for base in BASES}


class EndiannedBytes(bytes):
    def __new__(*args, **kwargs):
        if 'endianness' in kwargs:
            endianness = kwargs['endianness']
            del kwargs['endianness']
        else:
            endianness = None
        b = bytes.__new__(*args, **kwargs)
        b.endianness = endianness
        return b


def limit_width(bits, n):
    return n % (2 ** bits)


def signify(bits, sign, n):
    if sign == UNSIGNED:
        return limit_width(bits, n)
    elif sign == SIGNED:
        return limit_width(bits, n) - 2 ** bits
    else:
        raise ValueError('unknown sign {!r}'.format(sign))


def designify(bits, sign, n):
    if sign == UNSIGNED:
        if n < 0 or n >= 2 ** bits:
            raise ValueError('n outside range [0, {}): {}'.format(
                    2 ** bits, n))
        return n
    elif sign == SIGNED:
        if n < -(2 ** (bits - 1)) or n >= 2 ** bits:
            raise ValueError('n outside range [{}, {}): {}'.format(
                    -(2 ** (bits - 1)), 2 ** bits, n))
        if n < 2 ** (bits - 1):
            return n
        return n - 2 ** bits
    else:
        raise ValueError('unknown sign {!r}'.format(sign))


def bytes_to_number(s):
    if s.endianness is None:
        raise ValueError('no endianness')
    if s.endianness == LITTLE_ENDIAN:
        s = reversed(s)
    elif s.endianness != BIG_ENDIAN:
        raise ValueError('unknown endianness {!r}'.format(s.endianness))
    n = 0
    for x in s:
        n *= 0x100
        n += x
    return n


def number_to_bytes(endianness, n):
    if n < 0:
        raise ValueError('n cannot be negative: {}'.format(n))
    bs = []
    while n > 0:
        bs.append(n % 0x100)
        n //= 0x100
    if endianness is None:
        raise ValueError('no endianness')
    elif endianness == LITTLE_ENDIAN:
        return EndiannedBytes(bs, endianness=endianness)
    elif endianness == BIG_ENDIAN:
        return EndiannedBytes(reversed(bs), endianness=endianness)
    else:
        raise ValueError('unknown endianness {!r}'.format(endianness))


def bytes_to_widthlist(sign, width, s):
    l = []
    if width == BYTE:
        return s
    if s.endianness is None:
        raise ValueError(
            'no endianness and non-byte width {!r}'.format(width))
    if len(s) % WIDTHS[width] != 0:
        raise ValueError(
            'length {} is not a multiple of width {!r}'.format(len(s), width))

    for i in range(0, len(s), WIDTHS[width]):
        l.append(
            signify(WIDTHS[width] * 8, sign,
                    bytes_to_number(EndiannedBytes(s[i:i + WIDTHS[width]],
                                                   endianness=s.endianness))))
    return l


BYTE_STRING_REGEX = re.compile('^({endianness} )?{bytes}$'.format(
        endianness=ENDIANNESS_REGEX, bytes=BYTE_STRING_REGEX))

INTEGER_INPUT_REGEX = re.compile('^{base}$'.format(base=BASE_REGEX))

INTEGER_OUTPUT_REGEX = re.compile('^{number}$'.format(number=INTEGER_REGEX))

WIDTH_INPUT_REGEX = re.compile(
    '^{sign} {base} {width}$'.format(
        sign=SIGN_REGEX, base=BASE_REGEX, width=WIDTH_REGEX))

WIDTH_OUTPUT_REGEX = re.compile(
    '^({sign} )({base} )?{width}$'.format(
        sign=SIGN_REGEX, base=BASE_REGEX, width=WIDTH_REGEX))

WIDTHLIST_INPUT_REGEX = re.compile(
    '^{sign} {base} {width} list$'.format(
        sign=SIGN_REGEX, base=BASE_REGEX, width=WIDTH_REGEX))

WIDTHLIST_OUTPUT_REGEX = re.compile(
    '^({sign} )({base} )?{width} list$'.format(
        sign=SIGN_REGEX, base=BASE_REGEX, width=WIDTH_REGEX))


def normalize_input(inspec, s):
    m = BYTE_STRING_REGEX.match(inspec)
    if m:
        if isinstance(s, str):
            s = s.encode('ascii')
        endianness = m.group('endianness')
        return EndiannedBytes(byte_string_converters[m.group('bytes')][0](s),
                              endianness=endianness)

    m = INTEGER_INPUT_REGEX.match(inspec)
    if m:
        return base_converters[m.group('base')][0](s)

    m = WIDTH_INPUT_REGEX.match(inspec)
    if m:
        sign = m.group('sign')
        base = m.group('base')
        width = m.group('width')
        return designify(WIDTHS[width] * 8, sign, base_converters[base][0](s))

    m = WIDTHLIST_INPUT_REGEX.match(inspec)
    if m:
        sign = m.group('sign')
        base = m.group('base')
        width = m.group('width')
        return [designify(WIDTHS[width] * 8, sign, base_converters[base][0](x))
                for x in s.strip().strip('[]').split(',')]

    raise ValueError('no such input specifier {!r}'.format(inspec))


def convert(outspec, inval):
    if isinstance(inval, bytes):
        if outspec in BYTE_STRING_FORMATS:
            return byte_string_converters[outspec][1](inval)
        m = INTEGER_OUTPUT_REGEX.match(outspec)
        if m:
            base = m.group('base')
            n = bytes_to_number(inval)
            if base is None:
                return n
            return base_converters[base][1](n)
        m = WIDTHLIST_OUTPUT_REGEX.match(outspec)
        if m:
            width = m.group('width')
            base = m.group('base')
            sign = m.group('sign')
            widthlist = bytes_to_widthlist(sign, width, inval)
            if base is None:
                return widthlist
            base_converter = base_converters[base][1]
            return [base_converter(n) for n in widthlist]
        raise ValueError('no conversion from bytes to {!r}'.format(outspec))

    if isinstance(inval, int):
        m = INTEGER_OUTPUT_REGEX.match(outspec)
        if m:
            base = m.group('base')
            if base is None:
                return inval
            return base_converters[base][1](inval)
        m = WIDTH_OUTPUT_REGEX.match(outspec)
        if m:
            sign = m.group('sign')
            if sign is None:
                sign = SIGNED if inval < 0 else UNSIGNED
            base = m.group('base')
            width = m.group('width')
            n = signify(WIDTHS[width] * 8, sign, inval)
            if base is None:
                return n
            return base_converters[base][1](n)
        m = BYTE_STRING_REGEX.match(outspec)
        if m:
            return byte_string_converters[m.group('bytes')][1](
                number_to_bytes(m.group('endianness'), inval))
        raise ValueError('no conversion from int to {!r}'.format(outspec))

    raise ValueError('no conversion from value {!r}'.format(inval))


def normalize_output(outval):
    if isinstance(outval, bytes):
        return outval
    if isinstance(outval, str):
        return outval.encode('ascii') + b'\n'
    return repr(outval).encode('ascii') + b'\n'


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('input_spec')
    argparser.add_argument('output_spec')
    argparser.add_argument('input', nargs='?')

    args = argparser.parse_args()

    inp = args.input if args.input is not None else sys.stdin.buffer.read()
    inval = normalize_input(args.input_spec, inp)
    outval = convert(args.output_spec, inval)
    sys.stdout.buffer.write(normalize_output(outval))
    sys.stdout.buffer.flush()
if __name__ == '__main__':
    main()
