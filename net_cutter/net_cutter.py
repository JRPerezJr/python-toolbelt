#!/usr/bin/env python

# iptables - I INPUT - j NFQUEUE - -queue-num 0
# iptables - I OUTPUT - j NFQUEUE - -queue-num 0

import netfilterqueue


def process_packet(packet):
    print(packet)


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
