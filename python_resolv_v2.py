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
import threading

from time import sleep


def fetch_url(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            list = re.findall(r"[^\n]+", response.text)
            return list
        else:
            print(f"Failed to fetch TLDs, status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error occurred: {e}")
        return []


def validate_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv4Address):
            if ip.is_global and not ip.is_multicast and not ip.is_loopback and not ip.is_private:
                return "IPv4"
        elif isinstance(ip, ipaddress.IPv6Address):
            if ip.is_global and not ip.is_multicast and not ip.is_link_local and not ip.is_loopback:
                return "IPv6"
    except ValueError:
        # Ignore invalid IP addresses
        pass
    return None


def enumerate_subdomains(url, url_list):
    enumeration_tools = {
        "findomain": [
            "/home/fclaude/.local/bin/findomain",
            "--rate-limit", "10",
            "--resolver-timeout", "60",
            "--quiet",
            "--target", url,
        ],
        # "amass": [
        #     "/home/fclaude/.local/bin/amass",
        #     "enum",
        #     "-brute",
        #     "-nocolor",
        #     "-dns-qps", "10",
        #     "-timeout", "10",
        #     "-d", url,
        # ],
        # "subfinder": [
        #     "/home/fclaude/.local/bin/subfinder",
        #     "-no-color",
        #     "-silent",
        #     "-rate-limit", "1",
        #     "-max-time", "30",
        #     "-timeout", "120",
        #     "-exclude-ip",
        #     "-all",
        #     "-t", "1",
        #     "-d", url,
        # ],
    }

    for tool_name, cmd in enumeration_tools.items():
        try:
            print(f"Enumerating subdomains for {url} using {tool_name}")
            result = subprocess.check_output(cmd, timeout=3600, encoding="utf8").splitlines()
            for url in result:
                if url not in url_list:
                    url_list.extend(re.findall(re.compile(r"[^\n]+"), url))
        except subprocess.SubprocessError as e:
            print(f"Error using {tool_name} for {url}: {e}")


def scan(url_list):

    # Start enumeration for each TLD in separate threads
    threads = []
    for url in url_list:
        thread = threading.Thread(target=enumerate_subdomains, args=(url, url_list))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # fetch existing subdomains and expand list
    url_list.extend(fetch_url("https://static.fclaude.net/tracker-subdomains.txt"))
    
    resolve(url_list)


def resolve(url_list):
    dns_servers = ["10.114.27.1", "9.9.9.9", "208.67.222.222", "1.1.1.1", "8.8.8.8"]
    v4, v6 = [], []

    file_paths = {
        "v4": "/var/www/static/tracker-ipaddrs-v4.txt",
        "v6": "/var/www/static/tracker-ipaddrs-v6.txt",
    }

    for url in url_list:
        print("Resolving " + url + ":")
        for dns_server in dns_servers:
            # resolve urls
            dig_v4 = os.popen("dig A +short +tries=2 +time=5 @" + dns_server + " " + url)
            dig_v6 = os.popen("dig AAAA +short +tries=2 +time=5 @" + dns_server + " " + url)
            result = dig_v4.read().splitlines() + dig_v6.read().splitlines()

            for ip in result:
                if validate_ip(ip) == "IPv4" and ip not in v4:
                    v4.extend([ip])
                    print(ip)

                elif validate_ip(ip) == "IPv6":
                    ip = ipaddress.ip_address(ip).exploded
                    if ip not in v6:
                        v6.extend([ip])
                        print(ip)

    # write to file(s)
    sorted_v4 = sorted(v4)
    sorted_v6 = sorted(v6)

    for ip_version, ips in [("v4", sorted_v4), ("v6", sorted_v6)]:
        with open(file_paths[ip_version], "w") as file:
            for ip in ips:
                file.write(ip + "\n")

    pprint.pprint(sorted_v4)
    pprint.pprint(sorted_v6)


def main():
    scan(fetch_url("https://static.fclaude.net/tracker-tlds.txt"))


if __name__ == "__main__":
    main()
