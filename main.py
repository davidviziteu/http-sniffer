from utils import get_readable_mac, unpack_ethernet_frame
import socket

def main():
    socket_conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while 1:
        raw_eth_frame, other_data = socket_conn.recvfrom(60000)
        dest_mac, src_mac, proto, payload = unpack_ethernet_frame(raw_eth_frame)
        physical_device = other_data[0]
        print(f'dest mac: {dest_mac} srcmac: {src_mac}, proto: {proto}, physical_device: {physical_device} other_data: \
        {other_data}')

if __name__ == '__main__':
    main()

