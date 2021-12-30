from utils import *
import socket
import protocol_types
import ethernet_frame_types

def main():
    socket_conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while 1:
        raw_eth_frame, other_data = socket_conn.recvfrom(60000)
        dest_mac, src_mac, frame_type, eth_payload = unpack_ethernet_frame(raw_eth_frame)
        physical_device = other_data[0]

        if frame_type == ethernet_frame_types.IPV4:
            protocol, src_ip, dest_ip, ipv4_payload = unpack_ipv4_frame(eth_payload)
            frame_type = 'IPV4'
        elif frame_type == ethernet_frame_types.IPV6:
            protocol, src_ip, dest_ip, ipv4_payload = unpack_ipv6_frame(eth_payload)
            frame_type = 'IPV6'
        else:
            continue

        src_port, dest_port, sequence, acknowledgment, tpc_payload = unpack_tcp_frame(ipv4_payload)
        if dest_port != 80:
            continue
        try:
            tcp_payload = tpc_payload.decode("utf8")
        except UnicodeDecodeError:
            print('Unable to decode tcp payload as it contains non utf8 characters')
            continue
        if 'HTTP' not in tcp_payload:
            continue
        print(tabs(0) + f'ETHERNET FRAME - device: {physical_device}')
        print(tabs(1) + f'dest mac: {dest_mac}')
        print(tabs(1) + f'srcmac: {src_mac}')
        print(tabs(1) + f'frame_type: {frame_type}')
        print(tabs(1) + f'TCP FRAME:')
        print(tabs(2) + f'src_port: {src_port}')
        print(tabs(2) + f'dest_port: {dest_port}:')
        print(tabs(2) + f'sequence: {sequence}')
        print(tabs(2) + f'acknowledgment: {acknowledgment}')
        print(tabs(2) + f'tpc_payload: {tcp_payload}')
        print()


if __name__ == '__main__':
    main()


