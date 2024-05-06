#Import necessary modules from Scapy for packet manipulation
from scapy.all import sniff, Raw
from scapy.layers.inet import IP, UDP

connection_info = None # Variable to store initial connection information

#----------------------------
def handle_packet(packet):

    print(packet.summary()) #prints a summary of the packet

    if IP in packet: #print source and destination IP if its an IP packet
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)

    if Raw in packet: #print the Raw field in a packet if it contains that field
        raw_payload = packet[Raw].load
        print("Raw payload:", raw_payload)

    print("------------------------")
#----------------------------

# Start sniffing
sniff(iface="en10", prn=handle_packet)



