from utils import *
import socket
import protocol_types
import ethernet_frame_types
import os
import argparse


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

        src_port, dest_port, sequence, tpc_payload = unpack_tcp_frame(ipv4_payload)
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
        print(tabs(1) + f'frame_type: {frame_type}')
        print(tabs(1) + f'TCP FRAME:')
        print(tabs(2) + f'src: {src_mac} - {src_ip} : {src_port}')
        print(tabs(2) + f'dst: {dest_mac} - {dest_ip} : {dest_port}')
        print(tabs(2) + f'sequence: {sequence}')
        print(tabs(2) + f'===========tpc_payload===========\n{tcp_payload}')
        print(tabs(2) + f'=================================')
        print()


if __name__ == '__main__':
    # if os.geteuid() != 0:
    #     exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    parser = argparse.ArgumentParser(description='Sniff http requests leaving and coming to this machine')
    parser.add_argument('--from-ip', type=str, dest='filter_from_ip',
                        help='filter only http requests coming from ip address',
                        action='append')
    parser.add_argument('--to-ip', type=str, dest='filter_to_ip', help='filter only http requests going to ip address',
                        action='append')
    parser.add_argument('--from-mac', type=str, dest='filter_from_mac',
                        help='filter only http requests coming from a mac address',
                        action='append')
    parser.add_argument('--to-mac', type=str, dest='filter_to_mac',
                        help='filter only http requests going to a mac address',
                        action='append')
    parser.add_argument('--http-verb', type=str, dest='filter_http_verb',
                        help='filter only http that have the respective verb', action='append')
    parser.add_argument('--contain-text', type=str, dest='filter_contain_text',
                        help='filter only http that contain text', action='append')
    args = parser.parse_args()
    main()
