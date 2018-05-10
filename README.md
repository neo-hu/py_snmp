# py_snmp
python snmp

snmp = PySnmp("127.0.0.1", "public", 10, SnmpVersion.Version1)
response = snmp.bulk_walk(120, ".1.3.6.1.2.1.1")
for v in response:
    print(v.name, v.value)