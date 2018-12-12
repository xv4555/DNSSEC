#!/usr/bin/env python3

# Authors: Abraham Glasser and David Zou
# Team: Blue Dragon
# CSCI 351 Project 2
# DNS Client

# MUST RUN WITH PYTHON 3

import socket
import codecs
import sys
import struct as st
import random as rand
import math
import binascii
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA256 
from base64 import b64decode 

PY3K = sys.version_info >= (3, 0)
addit_rec = bytes([0,0,41,16,0,0,0,128,0,0,0])
AREC = 1
DNSKEYREC = 48
DSREC = 43
RRSIGREC = 46
CNAMEREC = 5

# --- - chunking helpers
def chunks(seq, size):
    '''Generator that cuts sequence (bytes, memoryview, etc.)
        into chunks of given size. If `seq` length is not multiply
        of `size`, the lengh of the last chunk returned will be
        less than requested.

        >>> list( chunks([1,2,3,4,5,6,7], 3) )
        [[1, 2, 3], [4, 5, 6], [7]]
    '''
    d, m = divmod(len(seq), size)
    for i in range(d):
        yield seq[i*size:(i+1)*size]
    if m:
        yield seq[d*size:]

def chunkread(f, size):
    '''Generator that reads from file like object. May return less
    data than requested on the last read.'''
    c = f.read(size)
    while len(c):
        yield c
        c = f.read(size)

def genchunks(mixed, size):
  '''Generator to chunk binary sequences or file like objects.
     The size of the last chunk returned may be less than
     requested.'''
  if hasattr(mixed, 'read'):
    return chunkread(mixed, size)
  else:
    return chunks(mixed, size)
# --- - /chunking helpers

def dump(binary, size=2, sep=' '):
  '''
  Convert binary data (bytes in Python 3 and str in
  Python 2) to hex string like '00 DE AD BE EF'.
  `size` argument specifies length of text chunks
  and `sep` sets chunk separator.
  '''
  hexstr = binascii.hexlify(binary)
  if PY3K:
    hexstr = hexstr.decode('ascii')
  return sep.join(chunks(hexstr.upper(), size))

def dumpgen(data):
  '''
  Generator that produces strings:

  '00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................'
  '''
  generator = genchunks(data, 16)
  for addr, d in enumerate(generator):
    # 00000000:
    line = '%08X: ' % (addr*16)
    # 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 
    dumpstr = dump(d)
    line += dumpstr[:8*3]
    if len(d) > 8:  # insert separator if needed
      line += ' ' + dumpstr[8*3:]
    # ................
    # calculate indentation, which may be different for the last line
    pad = 2
    if len(d) < 16:
      pad += 3*(16 - len(d))
    if len(d) <= 8:
      pad += 1
    line += ' '*pad

    for byte in d:
      # printable ASCII range 0x20 to 0x7E
      if not PY3K:
        byte = ord(byte)
      if 0x20 <= byte <= 0x7E:
        line += chr(byte)
      else:
        line += '.'
    yield line
  
def hexdump(data):
  '''
  Transform binary data to the hex dump text format:

  00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

    [x] data argument as a binary string
    [x] data argument as a file like object

  Returns result depending on the `result` argument:
    'print'     - prints line by line
    'return'    - returns single string
    'generator' - returns generator that produces lines
  '''
  if PY3K and type(data) == str:
    raise TypeError('Abstract unicode data (expected bytes sequence)')

  gen = dumpgen(data)
  for line in gen:
    print(line)


def decode_string(mess, off):
    ind = off
    off = 0
    res = ''
    while mess[ind] != 0:

        v = mess[ind]

        if (v>>6) == 3:
            next = st.unpack('>H', mess[ind:ind + 2])[0]
            if off == 0:
                off = ind + 2
            ind = next ^ (3<<14)
        else:
            res += mess[ind + 1:ind + 1 + v].decode('utf-8') + '.'
            ind += v + 1
    if off == 0:
        off = ind + 1
    res = res[:-1]

    return (res, off)

class DNSMessageFormat:

    def encode(self, hname, recur_desired, qtype):
        mess = b''
        self.header = MessHeader()
        self.header.set_question_header(recur_desired)
        self.question = DNSQuest()

        self.question.name = hname
        if(qtype == 'A'):
            self.question.type = 1
        elif(qtype == 'DNSKEY'):
            self.question.type = 48
        elif(qtype == 'ipv6'):
            self.question.type = 28
        else:
            self.question.type = 43

        self.question.req_class = 1

        mess += self.header.encode()
        mess += self.question.encode()
        mess += addit_rec
        return mess

    def decode(self, mess):

        self.header = MessHeader()
        self.auth_RRs = []
        self.addit_RRs = []
        self.quests = []
        self.answers = []
        off = self.header.decode(mess)
        for i in range(0,self.header.qd):
            self.quests.append(DNSQuest())
            off = self.quests[i].decode(mess, off)
        for i in range(0,self.header.an):
            self.answers.append(ResRecord())
            off = self.answers[i].decode(mess, off)
        for i in range(0,self.header.ns):
            self.auth_RRs.append(ResRecord())
            off = self.auth_RRs[i].decode(mess, off)
        for i in range(0,self.header.ar):
            self.addit_RRs.append(ResRecord())
            off = self.addit_RRs[i].decode(mess, off)


class AResource:
    def __init__(self, name, typ, req_class, ttl, rdata):
        off = 0
        self.name = name
        self.typ = typ
        self.req_class = req_class
        self.ttl = ttl
        self.length = 4
        self.rdata = rdata

        ip = st.unpack('BBBB', rdata)
        self.ip = str(ip[0]) + '.' + str(ip[1])
        self.ip += '.' + str(ip[2]) + '.' + str(ip[3])
        print('A res', str(ip))
        

class CNAME_Resource:
    def __init__(self, name, typ, req_class, ttl, length, rdata):
        self.name = name
        self.typ = typ
        self.req_class = req_class
        self.ttl = ttl
        self.length = length

        print(self.name)

class DNSKEY_Resource:
    def __init__(self, name, typ, req_class, ttl, length, rdata):
        off = 0
        self.name = name
        self.typ = typ
        self.req_class = req_class
        self.ttl = ttl
        self.length = length
        self.flags, self.protocol, self.algorithm = st.unpack('!HBB', rdata[:4])
        self.KSK = st.unpack('>H', rdata[:2])[0]

        self.rdata = rdata[4:]
        self.digest = self.rdata

        print('DNSKEY:', self.KSK)

        # hexdump(self.digest)

class DS_Resource:
    def __init__(self, name, typ, req_class, ttl, length, rdata):
        self.name = name
        self.typ = typ
        self.req_class = req_class
        self.ttl = ttl
        self.length = length
        self.id, self.algorithm, self.digestType = st.unpack('!HBB', rdata[:4])
        self.rdata = rdata[4:]
        self.digest = self.rdata

        print('DS Record', self.id)



class RRSIG_Resource:
    def __init__(self, name, typ, req_class, ttl, length, rdata):
        self.name = name
        self.typ = typ
        self.req_class = req_class
        self.ttl = ttl
        self.length = length
        self.type, self.algorithm, self.label, self.OrgTTL, self.expiration, self.inception, self.keytag = st.unpack('>HBBIIIH', rdata[:18])
        ord = 18
        if(name == '<Root>'):
            ord += 1
        elif(len(name) <=3):
            ord+=len(name)
        else:
            ord+=len(name)+2


        self.rdata = rdata[ord:]
        
        print('RRSIG', self.keytag, self.algorithm)
        # hexdump(self.rdata)

        
        
    
        


# Extract response record:
class ResRecord:

    def decode(self, mess, off):
        name = decode_string(mess, off)
        off = name[1]



        self.name = name[0]
        self.type = st.unpack('>H',mess[off:off + 2])[0]
        off += 2
        self.req = st.unpack('>H', mess[off:off + 2])[0]
        off += 2
        self.ttl = st.unpack('>I', mess[off:off + 4])[0]
        off += 4
        self.rd_length = st.unpack('>H', mess[off:off + 2])[0]
        off += 2

        rdata = mess[off: off + self.rd_length]
        if self.type == 1:
            self.resource_data = AResource(self.name, self.type, self.req, self.ttl, rdata)
        elif self.type == 5:
            self.resource_data = CNAME_Resource(self.name, self.type, self.req, self.ttl, self.rd_length, rdata)
        elif self.type == 48:
            self.resource_data = DNSKEY_Resource(self.name, self.type, self.req, self.ttl, self.rd_length, rdata)
        elif self.type == 46:
            self.resource_data = RRSIG_Resource(self.name, self.type, self.req, self.ttl, self.rd_length, rdata)
        elif self.type == 43:
            self.resource_data = DS_Resource(self.name, self.type, self.req, self.ttl, self.rd_length, rdata)

        return off + self.rd_length


class DNSQuest:

    def decode(self, mess, off):
        name = decode_string(mess, off)
        off = name[1]
        self.name = name[0]
        self.type = st.unpack('>H', mess[off:off + 2])[0]
        self.req_class = st.unpack('>H', mess[off + 2:off + 4])[0]
        return off + 4

    def encode_name(self):
        if(self.name == 'root'):
            return b'\x00'
        n = self.name
        if n.endswith('.'):
            n = n[:-1]
        res = b''
        domain_name = n.split('.')
        for i in range(1,len(domain_name)+1):
            res += st.pack('B', len(domain_name[i-1]))
            res += bytes(domain_name[i-1], 'utf-8')
        res += b'\x00'
        return res

    def encode(self):
        res = self.encode_name()
        res += st.pack('>H', self.type)
        res += st.pack('>H', self.req_class)
        return res

class MessHeader:

    def generate_ID(self):
        sum = 0
        for i in range(0, 16):
            sum += math.pow(2, i)
        return rand.randint(0, sum)

    def set_question_header(self, recur_desired):
        # message ID
        self.messID = self.generate_ID()
        # authoritative answer
        self.aa = 0
        # Query response
        self.qr = 0
        # truncation
        self.tc = 0
        # opcode
        self.opcode = 0
        # recursion desired
        if not(recur_desired):
            self.rd = 0
        else:
            self.rd = 1
        # recursion available
        self.ra = 0
        # Z
        self.z = 0
        # authentic data
        self.ad = 1
        # checking disabled
        self.cd = 1
        #response code
        self.rcode = 0
        # questions
        self.qd = 1
        # answers
        self.an = 0
        # authority RRs
        self.ns = 0
        # additional RRs
        self.ar = 1

    def decode(self, mess):
        self.messID = st.unpack('>H', mess[0:2])[0]
        m = st.unpack('>H', mess[2:4])[0]
        self.rcode = (m & 15)
        m >>= 7
        self.ra = (m & 1)
        m >>= 1
        self.rd = (m & 1)
        m >>= 1
        self.tc = (m & 1)
        m >>= 1
        self.aa = (m & 1)
        m >>= 1
        self.opcode = (m & 15)
        m >>= 4
        self.qr = m
        self.qd = st.unpack('>H', mess[4:6])[0]
        self.an = st.unpack('>H', mess[6:8])[0]
        self.ns = st.unpack('>H', mess[8:10])[0]
        self.ar = st.unpack('>H', mess[10:12])[0]
        return 12

    def encode(self):
        res = st.pack('>H', self.messID)
        m = 0
        m |= self.qr
        m <<= 1
        m |= self.opcode
        m <<= 4
        m |= self.aa
        m <<= 1
        m |= self.tc
        m <<= 1
        m |= self.rd
        m <<= 1
        m |= self.ra
        m <<= 2
        m |= self.ad
        m <<= 1
        m |= self.cd
        m <<= 4
        m |= self.rcode
        res += st.pack('>H', m)
        res += st.pack('>H', self.qd)
        res += st.pack('>H', self.an)
        res += st.pack('>H', self.ns)
        res += st.pack('>H', self.ar)
        return res


class DNSClient:
    #constructor
    def __init__(self, server, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # set timeout to 5 seconds
        self.socket.settimeout(5)
        try:
            self.socket.connect((server, port))
        except Exception:
            print("ERROR CONNECTING TO SERVER. PLEASE MAKE SURE YOUR SERVER IS CORRECT.")
            quit()
        self.server = server
        self.port = port


    def check_for_error(self, response_code):
        # checks for errors and prints accordingly
        if response_code == 0:
            pass

        else:
            if response_code == 3:
                #NAME ERROR
                print("NOTFOUND\n")
                quit()

            elif response_code == 1:
                print("ERROR\tRESPONSE CODE 1: FORMAT ERROR")
                quit()

            elif response_code == 2:
                print("ERROR\tRESPONSE CODE 2: SERVER FAILURE")
                quit()

            elif response_code == 4:
                print("ERROR\tRESPONSE CODE 4: NOT IMPLEMENTED")
                quit()

            elif response_code == 5:
                print("ERROR\tRESPONSE CODE 5: REFUSED")
                quit()

    # function to send a request
    def sendQuery(self, request, recursion_desired, qtype):

        # CODE IN OTHER CLASS TAKES CARE OF MAKING THE DNS PACKET / QUERY
        dns_packet = DNSMessageFormat()
        query = dns_packet.encode(request, recursion_desired, qtype)

        print('\n')
        print("\nSending packet for ",str(dns_packet.question.type), " to ",dns_packet.question.name ,"\n")
        hexdump(query)
        # Sends DNS Query Packet to specified DNS server using
        self.socket.send(query)
        try:
            response = self.socket.recv(2048)
        except Exception:
            # Timeout
            print("NORESPONSE\n")
            quit()

        # hexdump(response)
        
        dns_packet.decode(response)




        # check for error in response code
        self.check_for_error(dns_packet.header.rcode)

        # if len(dns_packet.answers) > 0:
        #     # go through the answers in the packet
        #     for answer in dns_packet.answers:
        #         # check whether there's authoritation
        #         if bool(dns_packet.header.aa) == True:
        #             if answer.type == 1:
        #                 print("IP\t" + str(answer.resource_data.ip) + "\t" + "auth")
        #             elif answer.type == 5:
        #                 print("CNAME\t" + str(answer.resource_data.name) + "\t" + "auth")
        #         else:
        #             if answer.type == 1:
        #                 print("IP\t" + str(answer.resource_data.ip) + "\t" + "nonauth")
        #             elif answer.type == 5:
        #                 print("CNAME\t" + str(answer.resource_data.name) + "\t" + "nonauth")

        #     print("")
        #     self.socket.close()
        return dns_packet



if len(sys.argv) != 4:
    print("Usage: ./351dns.py @<server:port> <name> <record>")
elif sys.argv[1][0] != "@":
    print("Usage: ./351dns.py @<server:port> <name> <record>")
else:
    servernport = sys.argv[1][1:].split(':')
    server = servernport[0]

    record = sys.argv[3]
   
    
    name = sys.argv[2]
    if(len(servernport) < 2):
        port = 53
    else:
        port = servernport[1]

    zone = name.split('.')[1]

    client = DNSClient(server, port)
    # p1 = client.sendQuery(name, True, record)
    # p2 = client.sendQuery(zone, True, record)
    # p3 = client.sendQuery('root', True, record)

    if(record == 'A'):
        domain1_A = client.sendQuery(name, True, 'A')
        domain1_Key = client.sendQuery(name, True, 'DNSKEY')
        for item in domain1_Key.answers:
            print(item.type)
            if(item.type == DNSKEYREC):
                if(item.resource_data.KSK == 257):
                    key = item.resource_data
        for item in domain1_A.answers:
            if(item.type == AREC):
                ip = item.resource_data
            if(item.type == RRSIGREC):
                sig = item.resource_data
        
        strDigest = str(codecs.encode(key.digest, 'hex_codec'), 'utf-8')
        print(strDigest[:2])
        # print(strDigest)
        # rsakey = RSA.importKey(strDigest) 
        # signer = PKCS1_v1_5.new(rsakey) 
        # digest = SHA256.new() 
        # digest.update(b64decode(data)) 
        # if signer.verify(digest, b64decode(domain1_A.answers[1].rdata)):
        #     print("True")
        # print("False")

    elif(record == 'DNSKEY'):
        print('test')
    else:
        print('DS')
    # for answer in p1.answers:
    #     if(answer.type == 1):
    #         print(str(answer.resource_data.ip))
    #     if(answer.type == RRSIGREC):
    #         print(answer.resource_data.algorithm)


    client.socket.close()







