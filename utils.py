import ipaddress
import struct


def tabs(n):
    return '\t' * n


def get_readable_mac(bytes_mac):
    return bytes_mac.hex(':')


def unpack_ethernet_frame(ethernet_frame):
    macs_and_proto = ethernet_frame[:14]
    dest_mac, source_mac, frame_type = struct.unpack('! 6s 6s H', macs_and_proto)
    dest_mac = get_readable_mac(dest_mac)
    source_mac = get_readable_mac(source_mac)
    return dest_mac, source_mac, frame_type, ethernet_frame[14:]


def unpack_ipv4_frame(data):
    version_length = data[0]
    version = version_length >> 4
    header_length = (version_length & 15) * 4
    ttl, protocol, src_ipv4, dest_ipv4 = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src_ipv4 = str(ipaddress.ip_address(src_ipv4))
    dest_ipv4 = str(ipaddress.ip_address(dest_ipv4))
    return protocol, src_ipv4, dest_ipv4, data[header_length:]


def unpack_ipv6_frame(data):
    # unable to test at the moment
    ipv6_first_word, ipv6_payload_legth, ipv6_next_header, ipv6_hoplimit = struct.unpack("! I H B B", data[0:8])
    src_ipv6 = str(ipaddress.ip_address(data[8:24]))
    dest_ipv6 = str(ipaddress.ip_address(data[24:40]))
    return ipv6_next_header, src_ipv6, dest_ipv6, data[40:]


def unpack_tcp_frame(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    data = data[offset:]
    return src_port, dest_port, sequence, acknowledgment, data
