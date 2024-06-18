#!/usr/bin/python

from scapy.all import *
import argparse


def main():
    """
    """
    #packet = IP(dst="10.7.100.10")/TCP()/"from scapy packet"
    #send(packet)


def packet_with_seq_n():
    packet = Ether(src="00:04:00:00:00:00", dst="00:00:01:01:01:01")/IP(dst="10.1.2.2", src="10.1.1.2")/TCP(sport=1234, dport=4321, flags="S")/"111111112222222233333333"
    sendp(packet, iface="eth0")

if __name__ == "__main__":
    main()
    parser = argparse.ArgumentParser(description='Simple script that sends TCP packets to an interface using scapy package')
    args = parser.parse_args()
    for i in range(0, 1):
        packet_with_seq_n()

