#!/usr/bin/env python3

import subprocess
import optparse
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--interface', dest='interface',
                      help='Interface that will be changed ex.(eth0, wlan0)')
    parser.add_option('-m', '--mac', dest='new_mac',
                      help='New Mac Address')
    (options, arguments) = parser.parse_args()
    if not options.interface:
        # code to handle error
        parser.error(
            '[-] Please specify an interface, use --help for more information.')
    elif not options.new_mac:
        # code to handle error
        parser.error(
            '[-] Please specify a new mac address, use --help for more information.')
    return options


def change_mac(interface, new_mac):
    print('[+] Changing the MAC address for interface:' +
          interface + ' to ' + new_mac)
    subprocess.call(['ifconfig', interface, 'down'])
    subprocess.call(['ifconfig', interface, 'hw', 'ether', new_mac])
    subprocess.call(['ifconfig', interface, 'up'])
    print('[+] Applied changes!')


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(['ifconfig', interface])
    mac_address_search_filter = re.search(
        r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', ifconfig_result)
    if mac_address_search_filter:
        return mac_address_search_filter.group(0)
    else:
        print('[-] Could not read MAC address.')


options = get_arguments()
current_mac = get_current_mac(options.interface)
print('Current Mac is ' + str(current_mac))

change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print('[+] MAC address was successfully changed to ' + current_mac)
else:
    print('[-] MAC address was not changed.')


# All these lines were refactored

# ifconfig_result = subprocess.check_output(['ifconfig', options.interface])
# mac_address_search_filter = re.search(
#     r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', ifconfig_result)
# if mac_address_search_filter:
#     print(mac_address_search_filter.group(0))
# else:
#     print('[-] Could not read MAC address.')


# parser.add_option('-i', '--interface', dest='interface',
#                   help='Interface that will be changed ex.(eth0, wlan0)')
# parser.add_option('-m', '--mac', dest='new_mac',
#                   help='New Mac Address')

# (options, arguments) = parser.parse_args()
# This code was changed after options was introduced
# interface = input('Enter Interface > ')
# new_mac = input('Enter New Mac Address > ')

# New code
# interface = options.interface
# new_mac = options.new_mac


# For Python 2
# interface = raw_input('Enter Interface > ')
# new_mac = raw_input('Enter New Mac Address > ')

#print('[+] Changing the MAC address for ' + interface + ' to ' + new_mac)

# subprocess.call('ifconfig ' + interface + ' down', shell=True)
# subprocess.call('ifconfig ' + interface +
#                 ' hw ether ' + new_mac, shell=True)
# subprocess.call('ifconfig ' + interface + ' up', shell=True)

# A secure version of those above commands.

# This code was commented out when change_mac function was created
# subprocess.call(['ifconfig', interface, 'down'])
# subprocess.call(['ifconfig', interface, 'hw', 'ether', new_mac])
# subprocess.call(['ifconfig', interface, 'up'])

# print('[+] Changes were successful!')
