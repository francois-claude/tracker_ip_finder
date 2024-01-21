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

from tracker_utils import fetch_domains_from_url, dedupe_and_sort, write_list_to_file
from tracker_subdomain_utils import enumerate_subdomains, enumerate_subdomain_list

# global variables
url_tracker_domains = "https://static.fclaude.net/tracker-domains.txt"
url_tracker_subdomains = "https://static.fclaude.net/tracker-subdomains.txt"
path_tracker_subdomains = "/var/www/static/tracker-subdomains.txt"

# workers
subdomain_workers = 1

def tracker_subdomain_enumeration():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # fetch domain list
    domain_list = fetch_domains_from_url(url_tracker_domains)

    # debugging
    print("---- DOMAINS TO ENUMERATE----")
    pprint.pprint(domain_list)

    # enumerate subdomains for each domain
    enumerated_subdomains = enumerate_subdomain_list(domain_list, subdomain_workers)

    print("---- ENUMERATED SUBDOMAINS----")
    pprint.pprint(enumerated_subdomains)

    # extend subdomain list
    enumerated_subdomains.extend(fetch_domains_from_url(url_tracker_subdomains))

    # dedupe & sort subdomains
    unique_subdomains = dedupe_and_sort(enumerated_subdomains)

    # write subdomains to list
    write_list_to_file(unique_subdomains, path_tracker_subdomains)

if __name__ == "__main__":
    # LOGGING TODO
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # enumerate subdomains
    tracker_subdomain_enumeration()
