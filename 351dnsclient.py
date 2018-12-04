

def main():
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
    if(len(servernport) < 2):
        port = 53
    # else:
    #     port = servernport[1]
    print(port)
    print(server)
    client = DNSClient(server, port)
    client.sendQuery(name)

    client.socket.close()
