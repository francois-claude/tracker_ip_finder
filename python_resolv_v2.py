#!/usr/bin/env python3

import os
import sys
import re
import requests
import shutil
import subprocess
import netaddr
import ipaddress
import pprint

from time import sleep

DNS_SERVERS = {
    'pihole':      '10.114.27.1',
    'quad nine':   '9.9.9.9',
    'opendns':     '208.67.222.222',
    'cloudflare':  '1.1.1.1',
    'google':      '8.8.8.8'
}

def pull_tlds():
    try:
        response = requests.get('https://static.fclaude.net/whitelist-master.txt')
        if response.status_code == 200:
            tlds = re.findall(r'[^\n]+', response.text)
            resolve(tlds)  # send to scanner
        else:
            print(f"Failed to fetch TLDs, status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error occurred: {e}")

def validate_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv4Address):
            if ip.is_global and not ip.is_multicast and not ip.is_loopback and not ip.is_private:
                return 'IPv4'
        elif isinstance(ip, ipaddress.IPv6Address):
            if ip.is_global and not ip.is_multicast and not ip.is_link_local and not ip.is_loopback:
                return 'IPv6'
    except ValueError:
        # Ignore invalid IP addresses
        pass
    return None


def resolve(subdomains):
    v4, v6 = [], []

    file_paths = {
        'v4': '/var/www/static/tracker-ipaddrs-v4.txt',
        'v6': '/var/www/static/tracker-ipaddrs-v6.txt'
    }

    for subdomain in subdomains:
        print('Resolving ' + subdomain + ':')
        for key, val in DNS_SERVERS.items():

            # resolve urls
            dig_v4 = os.popen('dig A +short +tries=2 +time=5 @' + val + ' ' + subdomain)
            dig_v6 = os.popen('dig AAAA +short +tries=2 +time=5 @' + val + ' ' + subdomain)
            result = dig_v4.read().splitlines() + dig_v6.read().splitlines()

            for ip in result:
                if validate_ip(ip) == 'IPv4' and ip not in v4:
                    v4.extend([ip])
                    print(ip)

                elif validate_ip(ip) == 'IPv6':
                    ip = ipaddress.ip_address(ip).exploded
                    if ip not in v6:
                        v6.extend([ip])
                        print(ip)

    # write to file(s)
    sorted_v4 = sorted(v4)
    sorted_v6 = sorted(v6)

    for ip_version, ips in [('v4', sorted_v4), ('v6', sorted_v6)]:
        with open(file_paths[ip_version], 'w') as file:
            for ip in ips:
                file.write(ip + '\n')

    pprint.pprint(sorted_v4)
    pprint.pprint(sorted_v6)

def main():
    pull_tlds()

if __name__ == "__main__":
    main()
