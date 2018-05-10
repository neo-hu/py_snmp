# coding:utf-8
from __future__ import absolute_import, division, print_function, with_statement

from pysnmp.proto.rfc1902 import Opaque

from py_snmp.exceptions import DecodeException
from py_snmp.helper import parse_int, parse_object_identifier, uvarint


class SnmpDataTypes(object):
    Integer = 0x02
    BitString = 0x03
    OctetString = 0x04
    Null = 0x05
    ObjectIdentifier = 0x06
    Sequence = 0x30
    IpAddress = 0x40
    Counter32 = 0x41
    Gauge32 = 0x42
    TimeTicks = 0x43
    Opaque = 0x44
    NsapAddress = 0x45
    Counter64 = 0x46
    Uinteger32 = 0x47
    NoSuchObject = 0x80
    NoSuchInstance = 0x81
    GetRequest = 0xa0
    GetNextRequest = 0xa1
    GetResponse = 0xa2
    SetRequest = 0xa3
    Trap = 0xa4
    GetBulkRequest = 0xa5
    EndOfMibView = 0x82

    type_map = {
        Integer: "Integer",
        BitString: "BitString",
        OctetString: "OctetString",
        Null: "Null",
        ObjectIdentifier: "ObjectIdentifier",
        Sequence: "Sequence",
        IpAddress: "IpAddress",
        Counter32: "Counter32",
        Gauge32: "Gauge32",
        TimeTicks: "TimeTicks",
        Opaque: "Opaque",
        NsapAddress: "NsapAddress",
        Counter64: "Counter64",
        Uinteger32: "Uinteger32",
        NoSuchObject: "NoSuchObject",
        NoSuchInstance: "NoSuchInstance",
        GetRequest: "GetRequest",
        GetNextRequest: "GetNextRequest",
        GetResponse: "GetResponse",
        SetRequest: "SetRequest",
        Trap: "Trap",
        GetBulkRequest: "GetBulkRequest",
        EndOfMibView: "EndOfMibView",
    }

    @classmethod
    def data_type_string(cls, data_type):
        return cls.type_map.get(data_type, data_type)


class Variable(object):
    value = None
    valueType = None

    def __init__(self, size):
        self.size = size


def decode_value(value_type, data):
    val = Variable(len(data))
    val.valueType = value_type
    if value_type == SnmpDataTypes.Sequence:
        val.value = data
    elif value_type == SnmpDataTypes.Integer:
        val.value = parse_int(data)
    elif value_type == SnmpDataTypes.Null:
        val.value = None
    elif value_type == SnmpDataTypes.OctetString:
        val.value = data.tostring()
    elif value_type == SnmpDataTypes.ObjectIdentifier:
        val.value = parse_object_identifier(data)
    elif value_type == SnmpDataTypes.EndOfMibView:
        val.value = "endOfMib"
    elif value_type == SnmpDataTypes.TimeTicks:
        val.value = parse_int(data)
    elif value_type == SnmpDataTypes.Opaque:
        val.value = data
    elif value_type in [SnmpDataTypes.Counter64, SnmpDataTypes.Counter32, SnmpDataTypes.Gauge32]:
        val.value = uvarint(data)
    elif value_type == SnmpDataTypes.IpAddress:
        val.value = "%d.%d.%d.%d" % (data[0], data[1], data[2], data[3])
    elif value_type == SnmpDataTypes.GetResponse:
        val.value = data
    else:
        raise DecodeException("Unable to decode `%s` not implemented %s" % (SnmpDataTypes.data_type_string(value_type), data))
    return val
