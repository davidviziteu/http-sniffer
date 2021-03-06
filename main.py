from utils import *
import socket
import os
import argparse

try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser


def print_headers(n_tabs, headers):
    """nicely prints headers from HttpParser instance with the given tabs."""
    for key, value in headers.items():
        print(tabs(n_tabs) + f'{key}: {value}')


def check_filters(filters, device, src_mac, src_ip, dest_mac, dest_ip, http_data: HttpParser):
    """checks whether or not the given tcp packet is subject to the applied filters or not."""
    if filters.ip_related and src_ip not in filters.ip_related and dest_ip not in filters.ip_related:
        return False
    if filters.filter_from_ip and src_ip not in filters.filter_from_ip:
        return False
    if filters.filter_to_ip and dest_ip not in filters.filter_to_ip:
        return False
    if filters.filter_from_mac and src_mac not in filters.filter_from_mac:
        return False
    if filters.filter_to_mac and dest_mac not in filters.filter_to_mac:
        return False
    if http_data:
        if filters.filter_http_verb and http_data.get_method() not in filters.filter_http_verb:
            return False
    if filters.filter_device and device not in filters.filter_device:
        return False
    return True


def main(filters):
    socket_conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while 1:
        raw_eth_frame, other_data = socket_conn.recvfrom(60000)
        dest_mac, src_mac, ip_version, eth_payload = unpack_ethernet_frame(raw_eth_frame)
        physical_device = other_data[0]

        if ip_version == 4:
            protocol, src_ip, dest_ip, ipvX_payload = unpack_ipv4_frame(eth_payload)
        elif ip_version == 6:
            protocol, src_ip, dest_ip, ipvX_payload = unpack_ipv6_frame(eth_payload)
        else:
            continue

        src_port, dest_port, sequence, tcp_payload = unpack_tcp_frame(ipvX_payload)
        if dest_port != 80 and src_port != 80:
            continue

        if filters.show_raw_tcp_payload:
            httpParser = None
            parsed_len = None
        else:
            httpParser = HttpParser()
            payload_len = len(tcp_payload)
            parsed_len = httpParser.execute(tcp_payload, payload_len)

            if len(tcp_payload) != parsed_len:
                parsed_len = None
                httpParser = None

        if not check_filters(filters, physical_device, src_mac, src_ip, dest_mac, dest_ip, httpParser):
            continue

        print(tabs(0) + f'ETHERNET FRAME - device: {physical_device}')
        print(tabs(1) + f'ip version: {ip_version}')
        print(tabs(1) + f'TCP FRAME:')
        print(tabs(2) + f'src: {src_mac} - {src_ip} : {src_port}')
        print(tabs(2) + f'dst: {dest_mac} - {dest_ip} : {dest_port}')
        print(tabs(2) + f'tcp payload:')
        if parsed_len is not None:
            print(tabs(3) + f'http verb: {httpParser.get_method()}')
            print(tabs(3) + f'headers:')
            print_headers(4, httpParser.get_headers())
            if httpParser.get_method() != 'GET' and httpParser.get_method() != 'HEAD':
                http_raw_body = httpParser.recv_body()
                try:
                    decoded_http_req_body = http_raw_body.decode("utf8")
                except UnicodeDecodeError:
                    decoded_http_req_body = 'Body contains non-utf8 characters. Raw body: ' + str(http_raw_body)
                print(tabs(3) + f'body: {decoded_http_req_body}')
        else:
            print(tabs(3) + str(tcp_payload))
        print()


if __name__ == '__main__':
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    parser = argparse.ArgumentParser(description='Sniff http requests leaving and coming to this machine')
    parser.add_argument('--device', type=str, dest='filter_device',
                        help='filter only http requests related to physical device',
                        action='append')
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
    parser.add_argument('--ip-related', type=str, dest='ip_related',
                        help='filter only http requests related to ip address',
                        action='append')
    parser.add_argument('--raw-tcp-payload', dest='show_raw_tcp_payload',
                        help='filter only http requests related to ip address',
                        action='store_true')

    args = parser.parse_args()
    main(args)
