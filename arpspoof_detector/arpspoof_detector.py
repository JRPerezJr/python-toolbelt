#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import subprocess

subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface',
                        help='Interface ex.(eht0, wlan0)')
    options = parser.parse_args()
    if not options.interface:
        # code to handle error
        parser.error(
            '[-] Please specify an Interface, use --help for more information.')
    return options


def get_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(
        arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:

            real_mac = get_mac_address(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            # print(packet.show())

            if real_mac != response_mac:
                print('[+] Active arp spoof attack detected in response!!')

        except IndexError:
            pass


options = get_arguments()
sniff(options.interface)
