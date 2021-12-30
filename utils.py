import ipaddress
import struct

IPV4_FRAME = 0x0800
IPV6_FRAME = 0x86dd

TCP_PROTO_ID = 6

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
