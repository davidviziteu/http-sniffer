import struct

IPV4_FRAME = 0x0800
IPV6_FRAME = 0x86dd

def get_readable_mac(bytes_mac):
    return bytes_mac.hex(':')

def unpack_ethernet_frame(ethernet_frame):
    macs_and_proto = ethernet_frame[:14]
    dest_mac, source_mac, frame_type = struct.unpack('! 6s 6s H', macs_and_proto)
    dest_mac = get_readable_mac(dest_mac)
    source_mac = get_readable_mac(source_mac)
    return dest_mac, source_mac, frame_type, ethernet_frame[14:]

