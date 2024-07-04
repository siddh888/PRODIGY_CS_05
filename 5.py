from scapy.all import IP, TCP, UDP, sniff


def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        if TCP in packet:
            payload = packet[TCP].payload
        elif UDP in packet:
            payload = packet[UDP].payload
        else:
            payload = packet[IP].payload
        
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}")
        print("-" * 50)

def start_sniffing(interface=None):
    if interface:
        sniff(iface=interface, prn=packet_callback, store=0)
    else:
        sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    # Start sniffing (optionally specify an interface, e.g., "eth0")
    start_sniffing()
