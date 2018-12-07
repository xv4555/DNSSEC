import socket
import codecs
import sys
import struct
import random
import math
import base64
import hashlib

if len(sys.argv) != 4:
    print("Usage: ./351dnsclient @<server:port> <domain-name> <record>")
elif sys.argv[1][0] != "@":
    print("Usage: ./351dnsclient @<server:port> <domain-name> <record>")
elif sys.argv[3] != 'A' or sys.argv[3] != 'DNSKEY' or sys.argv[3] != 'DS':
    print("Record argument must be A(A records), DNSKEY(DNSKEY records), or DS(DS records).")
else:
    serverInfo = sys.argv[1][1:].split(':')
    server = serverInfo[0]
    port = serverInfo[1]


name = sys.argv[2]
if(len(serverInfo) < 2):
    port = 53
else:
    port = serverInfo[1]

record = sys.argv[3]

print(port)
print(server)
client = DNSClient(server, port)
client.sendQuery(name)

client.socket.close()
