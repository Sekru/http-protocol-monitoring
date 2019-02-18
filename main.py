
import socket
import struct
import textwrap

def ethernetFrame(data):
    destMac, srcMac, proto = struct.unpack('! 6s 6s H', data[:14])
    return socket.htons(proto), data[14:]

def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        data, addr = connection.recvfrom(65536)
        ethProto, data = ethernetFrame(data)
        if ethProto == 8:
            version, headerLength, ttl, protocol, src, target, data = ipv4Packet(data)
            if protocol == 6:
                srcPort, destPort, sequence, ack, offset = struct.unpack('! H H L L H', data[:14])
                offset = (offset >> 12) * 4
                data = data[offset:]
                if srcPort == 80 or destPort == 80:
                    print('\n')
                    print('Source: {}, Target: {}'.format(src, target))
                    print('Version: {}, Header Length: {}, TTL: {}'.format(version, headerLength, ttl))
                    print('Destination Port: {}, Source Port: {}'.format(destPort, srcPort))
                    if len(data) > 0:
                        try:
                            print(data.decode('utf-8'))
                        except:
                            print('Cannot decode data by utf-8')

def ipv4Packet(data):
    versionHeaderLength = data[0]
    version = versionHeaderLength >> 4
    headerLength = (versionHeaderLength & 15) * 4
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, headerLength, ttl, protocol, ipv4(src), ipv4(target), data[headerLength:]

def ipv4(addr):
    return '.'.join(map(str, addr))

main()
