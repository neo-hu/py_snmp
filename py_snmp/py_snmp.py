# coding:utf-8
from __future__ import absolute_import, division, print_function, with_statement
import socket
import os

# DefaultPort is the default SNMP port
import array

from py_snmp.log import log
from py_snmp.decode import SnmpDataTypes
from py_snmp.exceptions import NoResponsesException, RequestIDMismatchException
from py_snmp.packet import SnmpPacket, SnmpPDU, unmarshal

DEFAULT_PORT = 161


class SnmpVersion(object):
    Version1 = 0x0
    Version2c = 0x1


class PySnmp(object):
    def __init__(self, host, community, timeout, version=SnmpVersion.Version1):
        if ":" in host:
            self.host, self.port = host.split(":", 2)
            self.port = int(self.port)
        else:
            self.host = host
            self.port = DEFAULT_PORT
        self.version = version
        self.community = community
        self.address = (self.host, self.port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def get_bulk(self, non_repeaters, max_repetitions, *oids):
        return self.send_packet(SnmpPacket(self.version, self.community,
                                           SnmpDataTypes.GetBulkRequest, oids_to_pbus(*oids),
                                           non_repeaters, max_repetitions))

    def get_multi(self, *oids):
        return self.request(SnmpDataTypes.GetRequest, *oids)

    def bulk_walk(self, max_repetitions, oid):
        if oid.startswith("."):
            oid = oid[1:]
        return self._bulk_walk(max_repetitions, oid, oid)

    def _bulk_walk(self, max_repetitions, searching_oid, root_oid):
        results = []
        rep = self.get_bulk(0, max_repetitions, searching_oid)
        for index, v in enumerate(rep.variables):
            if v.value == "endOfMib":
                break
            if v.name.startswith(root_oid):
                results.append(v)
                if index == len(rep.variables) - 1:
                    sub_results = self._bulk_walk(max_repetitions, v.name, root_oid)
                    results.extend(sub_results)

        return results

    def walk(self, oid):
        request_oid = oid
        results = []
        while True:
            res = self.get_next(oid)
            if res:
                if len(res.variables) > 0:
                    if res.variables[0].name.startswith(request_oid):
                        results.append(res.variables[0])
                        oid = res.variables[0].name
                        log.debug("Moving to %s", oid)
                    else:
                        log.debug("Root OID mismatch, stopping walk")
                        break
                else:
                    break
            else:
                break
        return results

    def get_next(self, oid):
        return self.request(SnmpDataTypes.GetNextRequest, oid)

    def get(self, oid):
        return self.request(SnmpDataTypes.GetRequest, oid)

    def request(self, request_type, *oids):
        return self.send_packet(SnmpPacket(self.version, self.community, request_type, oids_to_pbus(*oids)))

    def send_packet(self, packet):
        self.sock.sendto(packet.marshal(), (self.host, self.port))
        pdu = unmarshal(self.sock.recv(8192))
        if len(pdu.variables) == 0:
            raise NoResponsesException("No responses received.")
        if packet.request_id != pdu.request_id:
            raise RequestIDMismatchException("Request ID mismatch %s != %s" % (packet.request_id, pdu.request_id))
        return pdu

    def close(self):
        try:
            self.sock.close()
        except:
            pass


def oids_to_pbus(*oids):
    pdus = []
    for oid in oids:
        pdus.append(SnmpPDU(oid))
    return pdus
