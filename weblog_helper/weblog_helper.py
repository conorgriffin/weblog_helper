#!/usr/bin/env python

import sys
if sys.version_info < (3, 0):
    sys.stderr.write('This script requires Python 3\n')
    sys.exit(1)
import re
import ipaddress
import argparse
import operator
from datetime import datetime, timedelta

# Regex to match messages
# ^([\d.]+) (\S+) (\S+) \[(\d+\/\w+\/\d+:\d+:\d+:\d+\W[-+]\d{4})\] \"(\w+)\s(\S+)\s(\S+)\"\s(\d{3})\s(\d+)\s\"(\S)\"\s\"(.*?)\"\s\"(\S*?)\"


def main():
    """
    Process the input from the user and determine whether to search by IP address or by network
    :return:
    """
    parser = argparse.ArgumentParser('Search a logfile for an IP address or IP addresses in a CIDR range')
    parser.add_argument('--ip',
                        help='IP Address to search for in dotted decimal or CIDR notation',
                        required=False,
                        type=ipaddress.IPv4Interface)
    parser.add_argument('--top-ips',
                        help='The number of most common IP addresses to print',
                        required=False,
                        type=int)
    parser.add_argument('--rpm',
                        help='The number of requests per minute',
                        required=False,
                        action='store_true')
    parser.add_argument('logfile', type=argparse.FileType('r'))
    args = parser.parse_args()
    file = args.logfile

    if args.ip:
        interface = args.ip
        network = ipaddress.ip_network(interface.network)
        if network.num_addresses == 1:
            find_by_host(file, interface.ip)
        else:
            find_by_network(file, interface.network)
    elif args.top_ips:
        print_top_ips(file, args.top_ips)
    elif args.rpm:
        print_requests_per_minute(file)
    file.close()


def find_by_host(logfile, ip):
    """
    Output any line in logfile that starts with host
    :param logfile: The file to search
    :param ip: The IP address to search for
    :return:
    """
    regex = r'^' + str(ip)
    for line in logfile:
        if re.search(regex, line):
            sys.stdout.write(line)


def find_by_network(logfile, network):
    """
    Output any line in logfile that starts with an IP address in the given network
    :param logfile: The file to search
    :param network: The network of addresses to search for in logfile
    :return:
    """
    for line in logfile:
        ip = line.split()[0]
        # the network of the given IP will be a /32 (single host) so we check if that host is in the network
        if ipaddress.IPv4Interface(ip).network.overlaps(network):
            sys.stdout.write(line)


def print_top_ips(logfile, number_to_print):
    """
    Output the n most common ips in the logfile
    :param logfile: The file to search
    :param number_to_print: The number of ips to search
    :return:
    """
    ip_occurrences = {}
    for line in logfile:
        ip = line.split()[0]
        if ip_occurrences.get(ip):
            ip_occurrences[ip] += 1
        else:
            ip_occurrences[ip] = 1

    sorted_ip_occurrences = sorted(ip_occurrences.items(), key=operator.itemgetter(1), reverse=True)
    for entry in sorted_ip_occurrences[:number_to_print]:
        # print(str(entry[0]) + ' (' + str(entry[1]) + ' requests)')
        print("{} ({} requests)" % str(entry[0]), str(entry[1]))


def print_requests_per_minute(logfile, start_time=None, end_time=None):
    """
    Output a minute timestamp followed by a count of requests in that minute
    :param logfile: The file to search
    :param start_time: The start time for the interval to check - HH:MM format
    :param end_time: The end time for the interval to check - HH:MM format
    :return:
    """
    minute_last_message_processed_occurred_in = ''
    requests_in_last_minute_processed = 0
    for line in logfile:
        fragment = line.split()[3]
        minute_message_was_logged = fragment[1:-3]
        if minute_message_was_logged == minute_last_message_processed_occurred_in:
            requests_in_last_minute_processed += 1
        else:
            if start_time is not None and end_time is not None:
                if not message_was_logged_in_interval(minute_message_was_logged[-5:], start_time, end_time):
                    continue  # skip this line in the logfile
            print(minute_message_was_logged + ' ' + str(requests_in_last_minute_processed))
            minute_last_message_processed_occurred_in = minute_message_was_logged
            requests_in_last_minute_processed = 1


def message_was_logged_in_interval(minute_message_was_logged, start_time, end_time):
    start_time = datetime.strptime(start_time, '%H:%M')
    end_time = datetime.strptime(end_time, '%H:%M')
    if end_time < start_time:
        end_time += end_time + timedelta(days=1)
    message_time = datetime.strptime(minute_message_was_logged, '%H:%M')
    if start_time <= message_time <= end_time:
        return True
    return False


if __name__ == "__main__":
    main()
