# coding:utf-8
from __future__ import absolute_import, division, print_function, with_statement


class PySnmpException(Exception):
    pass


class RequestIDMismatchException(PySnmpException):
    pass

class NoResponsesException(PySnmpException):
    pass


class DecodeException(PySnmpException):
    pass


class MarshalException(PySnmpException):
    pass


class ParseException(PySnmpException):
    pass

class ParseIdentifierException(ParseException):
    pass


class MarshalIdentifierException(MarshalException):
    pass

