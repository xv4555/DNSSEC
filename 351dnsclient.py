<<<<<<< HEAD
"""
DNSClient Class calls for the query construction and sending queries back and forth
to the respective DNS server. DNSClient verifies the responses and outputs to STDOUT.
"""
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

        # Sends DNS Query Packet to specified DNS server using UDP
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


=======
import socket
import codecs
import sys
import struct
import random
import math
import base64
import hashlib
>>>>>>> a6a5bdd8befce74dbd904d7c8d2ddc82c77a18fd

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


<<<<<<< HEAD
    name = sys.argv[2]
    if(len(servernport) < 2):
        port = 53
    # else:
    #     port = servernport[1]
    print(port)
    print(server)
    client = DNSClient(server, port)
    client.sendQuery(name)
=======
name = sys.argv[2]
if(len(serverInfo) < 2):
    port = 53
else:
    port = serverInfo[1]
>>>>>>> a6a5bdd8befce74dbd904d7c8d2ddc82c77a18fd

record = sys.argv[3]

print(port)
print(server)
client = DNSClient(server, port)
client.sendQuery(name)

client.socket.close()
