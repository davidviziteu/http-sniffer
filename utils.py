import struct

def get_readable_mac(bytes_mac):
    return bytes_mac.hex(':')

def unpack_ethernet_frame(ethernet_frame):
    macs_and_proto = ethernet_frame[:14]
    dest_mac, source_mac, protocol = struct.unpack('! 6s 6s H', macs_and_proto)
    dest_mac = get_readable_mac(dest_mac)
    source_mac = get_readable_mac(source_mac)
    return dest_mac, source_mac, protocol, ethernet_frame[14:]

