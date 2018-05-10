# coding:utf-8
from __future__ import absolute_import, division, print_function, with_statement
import six
import struct
import random
import array

from py_snmp.log import log
from py_snmp.decode import SnmpDataTypes, decode_value
from py_snmp.exceptions import ParseException
from py_snmp.helper import marshal_object_identifier, uvarint


@six.python_2_unicode_compatible
class SnmpPDU(object):
    pdu_type = None
    value = None

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return "<SnmpPDU name=%s, value=(%s)%s>" % (self.name, SnmpDataTypes.data_type_string(self.pdu_type), self.value)

    __repr__ = __str__


@six.python_2_unicode_compatible
class SnmpPacket(object):
    version = None

    def __init__(self, version=None, community=None, request_type=None, variables=None, non_repeaters=0, max_repetitions=0):
        self.version = version
        self.community = community
        self.request_id = random.randint(0, 1 << 16)
        # self.request_id = 3
        self.request_type = request_type
        self.variables = variables
        self.error = 0
        self.non_repeaters = non_repeaters
        self.max_repetitions = max_repetitions
        self.error_index = 0

    def marshal(self):
        pdu_buf = array.array("B", [self.request_type, 0, 2, 4])
        request_id_bytes = struct.pack('!I', self.request_id)
        pdu_buf.extend(array.array("B", request_id_bytes))

        if self.request_type == SnmpDataTypes.GetBulkRequest:
            pdu_buf.extend([2, 1, self.non_repeaters,
                            2, 1, self.max_repetitions])
        else:
            pdu_buf.extend([2, 1, self.error,
                            2, 1, self.error_index])

        pdu_buf.extend([SnmpDataTypes.Sequence, 0])  # todo Varbind list length预留一个
        pdu_length = 0
        for varlist in self.variables:
            pdu = marshalPDU(varlist)
            pdu_length += len(pdu)
            pdu_buf += pdu
        pdu_buf[15] = pdu_length
        # SNMP PDU length (PDU header + varbind list length)
        pdu_buf[1] = pdu_length + 14

        # Write the message type 0x30
        buf = array.array("B", [SnmpDataTypes.Sequence])
        data_length = len(pdu_buf) + len(self.community) + 5
        if data_length >= 128:
            raise
        else:
            buf.append(data_length)
        # Write the Version
        buf += array.array("B", [2, 1, self.version])
        # Write Community
        buf.extend([4, len(self.community)])
        buf.extend(array.array("B", self.community))
        buf.extend(pdu_buf)
        return buf

    def __str__(self):
        return "<SnmpPacket version=%s, request_type=%s, request_id=%s variables=%s error=%s(%s)>" % (
            self.version, self.request_type,
            self.request_id, self.variables, self.error, self.error_index)

    __repr__ = __str__


def marshalPDU(pdu):
    oid = marshalOID(pdu.name)
    r = array.array("B", [
        SnmpDataTypes.Sequence, len(oid) + 4,
        SnmpDataTypes.ObjectIdentifier, len(oid),
    ])
    r.extend(oid)
    r.extend([SnmpDataTypes.Null, 0x00])
    return r


def oidToString(oid):
    return ".".join(map(lambda x: str(x), oid))


def marshalOID(oid):
    oid = oid.strip(".")
    return marshal_object_identifier([int(v) for v in oid.split(".")])


class RawBER(object):
    def __init__(self, ttype):
        self.ttype = ttype
        self.header_length = 0
        self.data_length = 0
        self.data = None
        self.variable = None


def parse_field(data):
    if len(data) == 0:
        raise ParseException("Unable to parse BER: Data length 0")
    ber = RawBER(data[0])
    length = data[1]
    if length > 0x80:
        length = length - 0x80
        ber.data_length = uvarint(data[2: 2 + length])
        ber.header_length = 2 + length
    else:
        ber.header_length = 2
        ber.data_length = length
    if ber.data_length > len(data):
        raise ParseException("Unable to parse BER: provided data length is longer than actual data (%d vs %d)" % (
        ber.data_length, len(data)))
    ber.data = data[ber.header_length: ber.header_length + ber.data_length]
    ber.variable = decode_value(ber.ttype, ber.data)
    return ber


def unmarshal(packet):
    packet = array.array("B", packet)
    if len(packet) == 0:
        raise ParseException("Unable to parse BER: Data length 0")
    log.debug("Begin SNMP Packet unmarshal bytes(%d)", len(packet))
    response = SnmpPacket(variables=[])
    cursor = 0
    # todo First bytes should be 0x30
    if packet[0] == SnmpDataTypes.Sequence:
        ber = parse_field(packet)
        cursor += ber.header_length
        log.debug("Packet sanity verified, we got all the bytes (%d)", ber.data_length)
        raw_version = parse_field(packet[cursor:])
        log.debug("Parsed [%d-%d] Version %d", cursor, cursor + raw_version.header_length + raw_version.data_length,
                  raw_version.variable.value)
        cursor += raw_version.header_length + raw_version.data_length
        response.version = raw_version.variable.value

        raw_community = parse_field(packet[cursor:])
        response.community = raw_community.variable.value
        log.debug("Parsed [%d-%d] Community", cursor, cursor + raw_community.header_length + raw_community.data_length)
        cursor += raw_community.header_length + raw_community.data_length
        raw_PDU = parse_field(packet[cursor:])
        log.debug("Parsed [%d-%d] PDU", cursor, cursor + raw_PDU.header_length + raw_PDU.data_length)
        response.request_type = raw_PDU.ttype
        if response.request_type in (SnmpDataTypes.GetResponse, SnmpDataTypes.GetRequest, SnmpDataTypes.GetBulkRequest):
            log.debug("SNMP Packet is %s", SnmpDataTypes.data_type_string(raw_PDU.ttype))
            log.debug("PDU Size is %s", raw_PDU.data_length)
            cursor += raw_PDU.header_length

            raw_request_id = parse_field(packet[cursor:])
            cursor += raw_request_id.data_length + raw_request_id.header_length
            response.request_id = raw_request_id.variable.value

            raw_error = parse_field(packet[cursor:])
            response.error = raw_error.variable.value
            cursor += raw_error.data_length + raw_error.header_length

            raw_error_index = parse_field(packet[cursor:])
            response.error_index = raw_error_index.variable.value
            log.debug("Parsed Request ID:%d error:%d Error Index:%d", response.request_id, response.error,
                      response.error_index)
            cursor += raw_error_index.data_length + raw_error_index.header_length

            raw_resp = parse_field(packet[cursor:])
            cursor += raw_resp.header_length
            while cursor < len(packet):
                log.debug("Parsing var bind response (Cursor at %d/%d)", cursor, len(packet))
                raw_varbind = parse_field(packet[cursor:])
                cursor += raw_varbind.header_length
                log.debug("Varbind length: %d/%d", raw_varbind.header_length, raw_varbind.data_length)
                raw_oid = parse_field(packet[cursor:])
                cursor += raw_oid.data_length + raw_oid.header_length
                log.debug("OID (%s) Field was %d bytes", raw_oid.variable.value, raw_oid.data_length)
                raw_value = parse_field(packet[cursor:])
                cursor += raw_value.data_length + raw_value.header_length
                pdu = SnmpPDU(oidToString(raw_oid.variable.value))
                pdu.pdu_type = raw_value.variable.valueType
                pdu.value = raw_value.variable.value
                log.debug("Value field was %d bytes", raw_value.data_length)
                response.variables.append(pdu)
                log.debug("Varbind decoding success")

    else:
        raise ParseException("Invalid packet header")
    return response
