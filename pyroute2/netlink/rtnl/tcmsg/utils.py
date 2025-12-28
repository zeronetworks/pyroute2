import socket

from pyroute2 import protocols


def parse_mac(mac_str):
    return bytes.fromhex(mac_str.replace(':', ''))


def parse_ip(ip_str):
    addr, _, prefix = ip_str.partition('/')

    if not prefix:
        return addr, None

    prefix = int(prefix)
    if is_ipv6_addr(addr):
        bits = 128
        family = socket.AF_INET6
    else:
        bits = 32
        family = socket.AF_INET

    mask = (1 << bits) - (1 << (bits - prefix))
    mask_bytes = mask.to_bytes(bits // 8, 'big')
    mask_str = socket.inet_ntop(family, mask_bytes)

    return addr, mask_str


def detect_protocol(kwargs):
    for ip_field in ['src_ip', 'dst_ip']:
        if ip_field in kwargs:
            if is_ipv6_addr(ip_field):
                return protocols.ETH_P_IPV6

            return protocols.ETH_P_IP

    return protocols.ETH_P_ALL


TC_INFO_PROTOCOL_MASK = 0x0000FFFF
TC_INFO_PRIO_MASK = 0xFFFF0000


def build_tc_info_field(protocol, prio):
    return socket.htons(protocol & TC_INFO_PROTOCOL_MASK) | ((prio << 16) & TC_INFO_PRIO_MASK)


def is_ipv6_addr(addr):
    return ':' in addr


ICMPV6_SIMPLIFIED_PROTO_NAME = 'icmp6' # getprotobyname expects: "ipv6-icmp6"
ICMPV6_PROTO_NUMBER = 58


def get_protocol_by_name(protocol_name):
    if protocol_name == ICMPV6_SIMPLIFIED_PROTO_NAME:
        return ICMPV6_PROTO_NUMBER

    try:
        return socket.getprotobyname(protocol_name)
    except OSError:
        return None


def parse_geneve_opt(opt):
    if isinstance(opt, str):
        parts = opt.split(':')
        if len(parts) != 3:
            raise ValueError('geneve_opts string must be "class:type:data"')
        opt_class = int(parts[0], 16)
        opt_type = int(parts[1], 16)
        opt_data = bytes.fromhex(parts[2])
    elif isinstance(opt, dict):
        if 'class' not in opt:
            raise ValueError('geneve_opts dict requires "class"')
        if 'type' not in opt:
            raise ValueError('geneve_opts dict requires "type"')
        if 'data' not in opt:
            raise ValueError('geneve_opts dict requires "data"')

        opt_class = int(opt['class'])
        opt_type = int(opt['type'])
        opt_data = opt['data']
        if isinstance(opt_data, str):
            opt_data = bytes.fromhex(opt_data)
    else:
        raise ValueError('geneve_opts must be string or dict')

    if len(opt_data) < 4 or len(opt_data) > 128 or len(opt_data) % 4 != 0:
        raise ValueError('geneve option data must be 4-128 bytes and multiple of 4')

    return opt_class, opt_type, opt_data
