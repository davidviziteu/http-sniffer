import ipaddress
import struct
import ethernet_frame_types


def tabs(n):
    r"""Returns the tab (\t) character multiplied by n."""
    return '\t' * n


def get_readable_mac(bytes_mac):
    """Returns the human-readable version of a mac address represented in bytes."""
    return bytes_mac.hex(':')


def unpack_ethernet_frame(ethernet_frame):
    """
    Extracts from an ethernet frame's header the source mac, destination mac and ip version (ipv4 or ipv6).
    Returns the human readable version of the mac addresses, the ip version and the payload.
    """
    macs_and_proto = ethernet_frame[:14]
    dest_mac, source_mac, ip_version = struct.unpack('! 6s 6s H', macs_and_proto)
    dest_mac = get_readable_mac(dest_mac)
    source_mac = get_readable_mac(source_mac)
    if ip_version == ethernet_frame_types.IPV4:
        ip_version = 4
    elif ip_version == ethernet_frame_types.IPV6:
        ip_version = 6
    return dest_mac, source_mac, ip_version, ethernet_frame[14:]


def unpack_ipv4_frame(data):
    """
    Extracts from an ipv4 packet's header the protocol of the payload (TCP or UDP etc), the length of the header, the
    source and destination ip addresses.
    Returns payload protocol (type), the human readable version of the ip addresses and the payload.
    """
    version_length = data[0]
    header_length = (version_length & 15) * 4
    ttl, protocol, src_ipv4, dest_ipv4 = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src_ipv4 = str(ipaddress.ip_address(src_ipv4))
    dest_ipv4 = str(ipaddress.ip_address(dest_ipv4))
    return protocol, src_ipv4, dest_ipv4, data[header_length:]


def unpack_ipv6_frame(data):
    """
    Extracts from an ipv6 packet's header the protocol of the payload (TCP or UDP etc), the
    source and destination ip addresses.
    Returns payload protocol (type), the human readable version of the ip addresses and the payload.

    Note: I was unable to test this function at the moment of writing. I will delete this message when I will be able
    to test and to confirm that it is working properly.
    """
    ipv6_first_word, ipv6_payload_length, ipv6_next_header, ipv6_hoplimit = struct.unpack("! I H B B", data[0:8])
    src_ipv6 = str(ipaddress.ip_address(data[8:24]))
    dest_ipv6 = str(ipaddress.ip_address(data[24:40]))
    return ipv6_next_header, src_ipv6, dest_ipv6, data[40:]


def unpack_tcp_frame(data):
    """
    Extracts from a TCP packet's header the source and destination port, the payload offset, the sequence and ack fields.
    Returns the source port, the destination port, the sequence number number and the payload.
    """
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, data[offset:]
