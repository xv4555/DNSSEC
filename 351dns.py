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

    def encode(self, hname, recur_desired, IPv6):
        mess = b''
        self.header = MessHeader()
        self.header.set_question_header(recur_desired)
        self.question = DNSQuest()

        self.question.name = hname
        if not IPv6:
            self.question.type = 1
        else:
            self.question.type = 28

        self.question.req = 1

        mess += self.header.encode()
        mess += self.question.encode()
        return mess

    def decode(self, mess):

        self.header = MessHeader()
        self.auth_RRs = []
        self.addit_RRs = []
        self.quests = []
        self.answers = []
        off = self.header.decode(mess)
        for i in range(1,self.header.qd+1):
            self.quests.append(DNSQuest())
            off = self.quests[i-1].decode(mess, off)
        for i in range(1,self.header.an+1):
            self.answers.append(ResRecord())
            off = self.answers[i-1].decode(mess, off)
        for i in range(1,self.header.ns+1):
            self.auth_RRs.append(ResRecord())
            off = self.auth_RRs[i-1].decode(mess, off)
        for i in range(1,self.header.ar+1):
            self.addit_RRs.append(ResRecord())
            off = self.addit_RRs[i-1].decode(mess, off)

class AResource:

    def __init__(self, data):
        ip = st.unpack('BBBB', data)
        self.ip = str(ip[0]) + '.' + str(ip[1])
        self.ip += '.' + str(ip[2]) + '.' + str(ip[3])

class CNAME_Resource:

    def __init__(self, mess, off):
        self.name = decode_string(mess, off)[0]

class ResRecord:

    def decode(self, mess, off):
        name = decode_string(mess, off)
        off = name[1]
        self.name = name[0]
        self.type = st.unpack('>H',mess[off:off + 2])[0]
        off += 2
        self.req = st.unpack('>H', mess[off:off + 2])[0]
        off += 2
        self.ttl = st.unpack('>I', mess[off: off + 4])[0]
        off += 4
        self.rd_length = st.unpack('>H', mess[off:off + 2])[0]
        off += 2

        rdata = mess[off: off + self.rd_length]

        if self.type == 1:
            self.resource_data = AResource(rdata)
        elif self.type == 5:
            self.resource_data = CNAME_Resource(mess, off)
        else:
            print("NOTFOUND")
            quit()

        return off + self.rd_length


class DNSQuest:

    def decode(self, mess, off):
        name = decode_string(mess, off)
        off = name[1]
        self.name = name[0]
        self.type = st.unpack('>H', mess[off:off + 2])[0]
        self.req = st.unpack('>H', mess[off + 2:off + 4])[0]
        return off + 4

    def encode_name(self):
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
        res += st.pack('>H', self.req)
        res += st.pack('>H', self.type)
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
        #questions
        self.qd = 1
        # answers
        self.an = 0
        # authority RRs
        self.ns = 0
        # additional RRs
        self.ar = 0
        #response code
        self.rcode = 0

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
        m <<= 7
        m |= self.rcode
        res += st.pack('>H', m)
        res += st.pack('>H', self.qd)
        res += st.pack('>H', self.ar)
        res += st.pack('>H', self.ns)
        res += st.pack('>H', self.an)
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
    def sendQuery(self, request, recursion_desired=True, v6=False):

        # CODE IN OTHER CLASS TAKES CARE OF MAKING THE DNS PACKET / QUERY
        dns_packet = DNSMessageFormat()
        query = dns_packet.encode(request, recursion_desired, v6)

        print("\nPacket to send:\n")
        print(query)
        print("\nHex representation of packet:\n")
        print(str(codecs.encode(query, "hex"), "utf-8"))
        print("\nSending packet . . .\n")

        self.socket.send(query)
        try:
            response = self.socket.recv(1024)
        except Exception:
            # Timeout
            print("NORESPONSE\n")
            quit()

        #TODO
        # CODE IN DNS_DATA TAKES CARE OF THE RESPONSE
        dns_packet.decode(response)

        #TODO TODO
        # FOR DEBUGGING, REMOVE LATER ?
        print("*** RESPONSE FROM SERVER ***\n")


        # check for error in response code
        self.check_for_error(dns_packet.header.rcode)

        if len(dns_packet.answers) > 0:
            # go through the answers in the packet
            for answer in dns_packet.answers:
                # check whether there's authoritation
                if bool(dns_packet.header.aa) == True:
                    if answer.type == 1:
                        print("IP\t" + str(answer.resource_data.ip) + "\t" + "auth")
                    elif answer.type == 5:
                        print("CNAME\t" + str(answer.resource_data.name) + "\t" + "auth")
                else:
                    if answer.type == 1:
                        print("IP\t" + str(answer.resource_data.ip) + "\t" + "nonauth")
                    elif answer.type == 5:
                        print("CNAME\t" + str(answer.resource_data.name) + "\t" + "nonauth")

            print("")
            self.socket.close()

        elif not recursion_desired:

            for resource_record in dns_packet.additional_RRs:
                try:
                    #connect to server again
                    self.socket.connect((server, port))

                    # check if IPv6
                    ipv6 = (resource_record.type == 28)

                    # send query again
                    self.sendQuery(request, recursion_desired=False, v6=ipv6)
                except Exception:
                    # NOTFOUND or ERROR?
                    print("ERROR CONNECTING TO SERVER. PLEASE MAKE SURE YOUR SERVER IS CORRECT.")
                    quit()

if len(sys.argv) != 3:
    print("Usage: ./351dns.py @<server:port> <name>")
elif sys.argv[1][0] != "@":
    print("Usage: ./351dns.py @<server:port> <name>")
else:
    servernport = sys.argv[1][1:].split(':')
    server = servernport[0]

   
    
    name = sys.argv[2]
    if(len(servernport) < 2):
        port = 53
    else:
        port = servernport[1]
    print(port)
    print(server)
    client = DNSClient(server, port)
    client.sendQuery(name)

    client.socket.close()