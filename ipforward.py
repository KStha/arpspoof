'''IP Forwarding'''

IP_FWD_FILE = '/proc/sys/net/ipv4/ip_forward'


def chk_pkt_fwd_unix():
    '''Check if IP Forwarding is enabled or not'''
    with open(IP_FWD_FILE, 'r') as ip_forward_file:
        for value in ip_forward_file:
            ip_fwd = bool(value.strip() == '1')

        ip_forward_file.close()

    return ip_fwd


def en_pkt_fwd_unix():
    '''Enable IP Forwarding'''
    with open(IP_FWD_FILE, 'w') as ip_forward_file:
        ip_forward_file.write('1')
        ip_forward_file.close()


def dis_pkt_fwd_unix():
    '''Disable IP Forwarding'''
    with open(IP_FWD_FILE, 'w') as ip_forward_file:
        ip_forward_file.write('0')
        ip_forward_file.close()
