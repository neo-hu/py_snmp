# coding:utf-8
from __future__ import absolute_import, division, print_function, with_statement
import array

from py_snmp.exceptions import ParseIdentifierException, MarshalIdentifierException, ParseException


def parse_object_identifier(bytes):
    if len(bytes) == 0:
        raise ParseIdentifierException("zero length OBJECT IDENTIFIER")
    s = [int(bytes[0] / 40), bytes[0] % 40]
    offset = 1
    while offset < len(bytes):
        v, offset = parse_base128_int(bytes, offset)
        s.append(v)
    return s

def marshal_object_identifier(oids):
    if len(oids) < 2 or oids[0] > 6 or oids[1] >= 40:
        raise MarshalIdentifierException("invalid object identifier")
    ret = array.array('B', [oids[0] * 40 + oids[1]])
    for n in oids[2:]:
        # ret += marshal_base128_int(n)
        ret.extend(marshal_base128_int(n))
    return ret


def uvarint(data):
    x = 0
    for i, b in enumerate(data):
        x = (x << 8) + b
        if i == 7:
            return x
    return x


def parse_int64(bytes):
    l = len(bytes)
    if l > 8:
        raise ParseException("integer too large")
    ret = 0
    for read in range(0, l):
        ret <<= 8
        ret |= bytes[read]
    ret <<= 64 - len(bytes) * 8
    ret >>= 64 - len(bytes) * 8
    return ret


def parse_int(bytes):
    ret64 = parse_int64(bytes)
    return int(ret64)


def parse_base128_int(bytes, offset):
    ret = 0
    for shifted in range(0, len(bytes)):
        if shifted > 4:
            raise ParseException("Structural Error: base 128 integer too large")
        ret <<= 7
        b = bytes[offset]
        ret |= b & 0x7f
        offset += 1
        if b & 0x80 == 0:
            return ret, offset
    raise ParseException("Syntax Error: truncated base 128 integer")

def marshal_base128_int(value):
    pieces = array.array('B', )
    if value == 0:
        pieces.append(0)
        return pieces
    # pieces = []
    l = 0
    i = value
    while i:
        i >>= 7
        l += 1
    for i in range(l - 1, -1, -1):
        o = value >> i * 7
        o &= 0x7f
        if i != 0:
            o |= 0x80
        pieces.append(o)
    return pieces
