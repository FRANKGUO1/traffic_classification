import dpkt
import os
import socket

pcap_file = "/home/sinet/gzc/traffic_classification/dataset/VPN-PCAPS-02/vpn_voipbuster1a.pcap"  # 替换为你的pcap文件路径

print(f"File size: {os.path.getsize(pcap_file)} bytes")

with open(pcap_file, 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    linktype = pcap.datalink()
    print(f"Link-layer type: {linktype} (1=Ethernet, 12/101=Raw IP)")
    
    for i, (ts, buf) in enumerate(pcap):
        if i >= 10:
            break
        print(f"\nPacket {i}:")
        print(f"Timestamp: {ts}")
        print(f"Raw bytes (first 20): {buf[:20].hex()}")
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            print(f"eth.type: {eth.type} (2048=IPv4, 2054=ARP, 34525=IPv6)")
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                ip = eth.data
                print(f"IP src: {socket.inet_ntoa(ip.src)} -> dst: {socket.inet_ntoa(ip.dst)}")
        except Exception as e:
            print(f"Error parsing packet: {e}")