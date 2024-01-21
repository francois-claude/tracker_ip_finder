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

def validate_url(url_str):
    retval = None
    # regex for a valid url
    pattern = re.compile(
        r'^(?!-)'
        r'(?:(?:[a-zA-Z0-9-]{1,63}\.){0,2}'  # 0-2 subdomains - each 1-63 characters long
        r'[a-zA-Z0-9-]{1,63}'                # domain - 1-63 characters long
        r'\.([a-zA-Z]{2,63})'                # tld - 2-63 characters long
        r')$'
    )

    # strip leading (http:// and https://) from string
    if url_str.startswith("http://") or url_str.startswith("https://"):
        url_str = url_str.split("://")[1]

    # check against regex pattern and return string if valid
    if pattern.match(url_str):
        retval = url_str
        return retval

    else:
        return retval

def validate_ip(ip_str):
    """
    Function validates an IP address, returning "IPv4" or "IPv6" if the input is a valid,
    non-special IPv4 or IPv6 address, respectively, and None for invalid IPs. It excludes
    multicast, loopback, private, reserved, and link-local addresses.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv4Address):
            if ip.is_global and not ip.is_multicast and not ip.is_loopback and not ip.is_private and not ip.is_unspecified and not ip.is_reserved and not ip.is_loopback and not ip.is_link_local:
                return "IPv4"
        elif isinstance(ip, ipaddress.IPv6Address):
            if ip.is_global and not ip.is_multicast and not ip.is_link_local and not ip.is_loopback and not ip.is_private and not ip.is_unspecified and not ip.is_reserved:
                return "IPv6"
    except ValueError:
        # Ignore invalid IP addresses
        pass

    return None

def dedupe_and_sort(ip_list):
    deduped_set = set(ip_list)
    sorted_list = sorted(deduped_set)
    return sorted_list

def write_list_to_file(list, file_path):
    try:
        with open(file_path, "w") as file:
            for line in list:
                file.write(line + "\n")
    except IOError as e:
        print(f"Error writing to file: {e}")


def fetch_domains_from_url(url):
    """
    Function sends GET request to URL and extracts all URLs from the response text.
    If the status code is 200, function returns a list of URLs. If the status code
    is not 200 or an error occurs during the request, function prints an error
    message and returns an empty list.
    """
    processed_urls = []
    try:
        response = requests.get(url)
        if response.status_code == 200:
            for item in response.text.splitlines():
                str = item.strip()
                if str and not str.startswith("#"):
                    validated_url = validate_url(str)
                    if validated_url is not None:
                        processed_urls.append(validated_url)
            return processed_urls
        else:
            print(f"Failed to fetch TLDs, status code: {response.status_code}")

    except requests.RequestException as e:
        print(f"Error occurred: {e}")
        # quit script if cant fetch url
        # TODO: write to logfile
        sys.exit(1)
