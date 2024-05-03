import socket
import struct
import textwrap

TAB_1 '\t - '
TAB_2 '\t\t - '
TAB_3 '\t\t\t - '
TAB_4 '\t\t\t\t - '

DATA_TAB_1 '\t '
DATA_TAB_2 '\t\t '
DATA_TAB_3 '\t\t\t '
DATA_TAB_4 '\t\t\t\t '


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame: ')
        print('Destination: {}, Source {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
        
        #8 for IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet: ')

#unpack ethernet frame
#Grab first 14 bytes and unpack it (contains dest. and source info)
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

#Return properly formatted MAC address (AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr
    
#Unpack IPv4 packet 
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto. src, target = struct.unpack('! 8x B B 2x 4s 4s', data[0:20])
    return version, header_length, ttl, proto, ipv4(src), ivp4(target), data[header_length:]
    
#Returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str,addr)) #convert to string and combine 
    

#Unpacks UDP packet
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[0:8])
    return src_port, dest_port, size, data[8:]
    

main()
