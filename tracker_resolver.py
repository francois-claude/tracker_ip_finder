#!/usr/bin/env python3

import re
import sys
import requests
import subprocess
import ipaddress
import pprint
import dns.resolver
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from tracker_utils import fetch_domains_from_url, dedupe_and_sort, write_list_to_file, validate_ip
from tracker_resolver_utils import resolve_subdomain, resolve_subdomain_list

dns_servers = [["10.114.27.1"], # pihole
    ["165.246.10.2"], # Korea
    ["54.94.175.250"], # Brazil
    ["172.193.67.34"], # AU - Brisbane
    ["102.216.223.7"], # South Africa
    ["172.193.67.34"], # AU - Brisbane
    ["208.67.222.222", "208.67.220.220", "208.67.220.222"], # US - OpenDNS
    ["1.2.4.8", "210.2.4.8"], # CN - CNNIC SDNS
    ["223.5.5.5", "223.6.6.6"], # CN - AliDNS
    ["217.150.35.129"], # RU - Joint Stock Company TransTeleCom
    ["80.80.80.80", "80.80.81.81"], # NL - Freenom World
    ["77.88.8.1", "77.88.8.8"], # RU - Yandex
    ["1.1.1.1", "1.0.0.1"], # US - Cloudflare
    ["93.95.230.101 "], # Iceland
    ["94.206.42.74", "94.206.47.14"], # UAE - Dubai
    ["14.192.0.139"], # India
    ["101.101.101.101", "101.102.103.104"], # Taiwan - Taiwan Network Information Center
    ["8.8.8.8", "8.8.4.4"]] # US - Google

# global variables
url_tracker_subdomains = "https://static.fclaude.net/tracker-subdomains.txt"
path_tracker_ipv4 = "/var/www/static/tracker-ipaddrs-ipv4.txt"
path_tracker_ipv6 = "/var/www/static/tracker-ipaddrs-ipv6.txt"

# workers & sleep
resolve_sleep = 0.75
resolve_workers = 10

def tracker_resolver():
    # fetch subdomains
    domains_to_resolve = fetch_domains_from_url(url_tracker_subdomains)

    # resolve subdomains
    resolved_ipv4, resolved_ipv6 = resolve_subdomain_list(
        domains_to_resolve, dns_servers, resolve_sleep, resolve_workers
    )

    # validate resolved ipv4 and ipv6 addresses
    validated_ipv4 = [ip for ip in resolved_ipv4 if validate_ip(ip) == "IPv4"]
    validated_ipv6 = [ip for ip in resolved_ipv6 if validate_ip(ip) == "IPv6"]

    # dedupe & sort ipv4 and ipv6 addresses
    unique_ipv4 = dedupe_and_sort(validated_ipv4)
    unique_ipv6 = dedupe_and_sort(validated_ipv6)

    # write ip addresses to file
    write_list_to_file(unique_ipv4, path_tracker_ipv4)
    write_list_to_file(unique_ipv6, path_tracker_ipv6)

    # print info to screen
    print("----FINAL IPv4 ADDRESSES----")
    pprint.pprint(unique_ipv4)
    print("----FINAL IPv6 ADDRESSES----")
    pprint.pprint(unique_ipv6)
    print("\n")

if __name__ == "__main__":
    # LOGGING TODO
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # debug
    print("---- DNS SERVERS----")
    pprint.pprint(dns_servers)

    # resolve
    tracker_resolver()
