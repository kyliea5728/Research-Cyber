from scapy.layers.inet import IP, UDP, TCP
import scapy.all as scapy

# Source IP and port
src_ip = '169.254.5.236'
src_port = 60908

# Destination IP and port
dst_ip = '169.254.62.118'
dst_port = 12345

# Craft the IP segment of the packet with custom source and destination
ip_segment = IP(src=src_ip, dst=dst_ip)

#Craft the data to be in the packet
payload = "data"

#-----------------------
#TCP
# Craft the TCP segment with custom source and destination ports
tcp_segment = TCP(sport=src_port, dport=dst_port)


# Combine the segments of the packet
crafted_packet = ip_segment / tcp_segment/ payload

#-------------------------
'''#UDP
udp_segment = UDP(sport=src_port, dport=dst_port)

# Combine the segments of the packet
crafted_packet = ip_segment / udp_segment/ payload'''



scapy.all.send(crafted_packet)



