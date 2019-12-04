#!/usr/bin/env python3

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='ip',
                        help='IP Address or Range that will be scanned ex.(10.0.2.1 or 10.0.2.1/24)')
    options = parser.parse_args()
    if not options.ip:
        # code to handle error
        parser.error(
            '[-] Please specify an IP Address or range, use --help for more information.')
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(
        arp_request_broadcast, timeout=1, verbose=False)[0]

    print('IP\t\t\tMacAddress\n-------------------------------------')
    clients_list = []

    for element in answered_list:
        client_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        clients_list.append(client_dict)
        print(element[1].psrc + '\t\t' + element[1].hwsrc)
    return(clients_list)


def print_result(results_list):
    print('IP\t\t\tMac Address\n------------------------------------')
    for client in results_list:
        print(client['ip'] + '\t\t' + client['mac'])


options = get_arguments()
scan_result = scan(options.ip)
print_result(scan_result)
