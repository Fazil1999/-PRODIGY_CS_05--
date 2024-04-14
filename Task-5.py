from scapy.all import *

# Callback function to process captured packets
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = packet[TCP].payload
            print(f"TCP packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}, protocol: {protocol}, payload: {payload}")
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload = packet[UDP].payload
            print(f"UDP packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}, protocol: {protocol}, payload: {payload}")
        elif ICMP in packet:
            print(f"ICMP packet from {src_ip} to {dst_ip}, protocol: {protocol}")
        else:
            print(f"Other IP packet from {src_ip} to {dst_ip}, protocol: {protocol}")

# Sniff packets on the network
sniff(prn=packet_callback, filter="ip", count=10)