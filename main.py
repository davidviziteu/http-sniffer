from utils import *
import socket
import protocol_types
import ethernet_frame_types
import os
import argparse

try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser


def check_filters(filters, device, src_mac, src_ip, src_port, dest_mac, dest_ip, http_data):
    """checks whether or not the given tcp packet is subject to the applied filters or not"""
    pass


def main():
    socket_conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    httpParser = HttpParser()
    while 1:
        raw_eth_frame, other_data = socket_conn.recvfrom(60000)
        dest_mac, src_mac, ip_version, eth_payload = unpack_ethernet_frame(raw_eth_frame)
        physical_device = other_data[0]

        if ip_version == 4:
            protocol, src_ip, dest_ip, ipvX_payload = unpack_ipv4_frame(eth_payload)
            ip_version = 'IPV4'
        elif ip_version == 6:
            protocol, src_ip, dest_ip, ipvX_payload = unpack_ipv6_frame(eth_payload)
            ip_version = 'IPV6'
        else:
            continue

        src_port, dest_port, sequence, tcp_payload = unpack_tcp_frame(ipvX_payload)
        if dest_port != 80:
            continue
        try:
            decoded_tcp_payload = tcp_payload.decode("utf8")
        except UnicodeDecodeError:
            print('Unable to decode tcp payload as it contains non utf8 characters')
            continue
        if 'HTTP' not in decoded_tcp_payload:
            continue

        print(tabs(0) + f'ETHERNET FRAME - device: {physical_device}')
        print(tabs(1) + f'frame_type: {ip_version}')
        print(tabs(1) + f'TCP FRAME:')
        print(tabs(2) + f'src: {src_mac} - {src_ip} : {src_port}')
        print(tabs(2) + f'dst: {dest_mac} - {dest_ip} : {dest_port}')
        print(tabs(2) + f'sequence: {sequence}')

        len_parsed = httpParser.execute(tcp_payload, len(tcp_payload))
        if len(tcp_payload) == len_parsed:
            print(tabs(2) + f'tcp payload:')
            print(tabs(2) + f'headers: {httpParser.get_headers()}')
        else:
            print(tabs(2) + f'tcp payload http parsing failed')
        print()


if __name__ == '__main__':
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
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
