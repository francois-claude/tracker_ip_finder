#!/usr/bin/env python3

import re
import sys
import requests
import subprocess
import ipaddress
import pprint
import dns.resolver
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def validate_ip(ip_str):
    """
    Function validates an IP address, returning "IPv4" or "IPv6" if the input is a valid,
    non-special IPv4 or IPv6 address, respectively, and None for invalid IPs. It excludes
    multicast, loopback, private, reserved, and link-local addresses.
    """
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


def write_list_to_file(list, file_path):
    try:
        with open(file_path, "w") as file:
            for line in list:
                file.write(line + "\n")
    except IOError as e:
        print(f"Error writing to file: {e}")


def fetch_url(url):
    """
    Function sends GET request to URL and extracts all URLs from the response text.
    If the status code is 200, function returns a list of URLs. If the status code
    is not 200 or an error occurs during the request, function prints an error
    message and returns an empty list.
    """
    processed_urls = []
    pattern = re.compile(r"^\s*(?:http://|https://)?(.*?)$")
    try:
        response = requests.get(url)
        if response.status_code == 200:
            for tld in response.text.splitlines():
                if not tld.strip() or tld.strip().startswith("#"):
                    continue
                match = pattern.match(tld)
                if match:
                    processed_urls.append(match.group(1))

            return processed_urls
        else:
            print(f"Failed to fetch TLDs, status code: {response.status_code}")

    except requests.RequestException as e:
        print(f"Error occurred: {e}")
        # quit script if cant fetch url
        # TODO: write to logfile
        sys.exit(1)


def enumerate_subdomains(tld):
    """
    Function takes a list of TLDs and returns a list of enumerated subdomains. Can
    be run with multi-threading by changing 'max_workers=4' but amass is a resource
    hog and I'm running this in a resource limited cloud box
    """
    enumerate_subdomains = []
    enumeration_tools = {
        "findomain": [
            "/home/fclaude/.local/bin/findomain",
            "--rate-limit",
            "10",
            "--resolver-timeout",
            "60",
            "--quiet",
            "--target",
            tld,
        ],
        "amass": [
            "/home/fclaude/.local/bin/amass",
            "enum",
            "-brute",
            "-nocolor",
            "-dns-qps",
            "10",
            "-timeout",
            "10",
            "-d",
            tld,
        ],
        "subfinder": [
            "/home/fclaude/.local/bin/subfinder",
            "-no-color",
            "-silent",
            "-rate-limit",
            "1",
            "-max-time",
            "30",
            "-timeout",
            "120",
            "-exclude-ip",
            "-all",
            "-t",
            "1",
            "-d",
            tld,
        ]
    }

    for tool_name, cmd in enumeration_tools.items():
        try:
            print(f"Enumerating subdomains for {tld} using {tool_name}")
            result = subprocess.check_output(cmd, timeout=3600, encoding="utf8").splitlines()
            for subdomain in result:
                if subdomain not in enumerate_subdomains:
                    enumerate_subdomains.extend(re.findall(re.compile(r"[^\n]+"), subdomain))
        except subprocess.SubprocessError as e:
            print(f"Error using {tool_name} for {tld}: {e}")

    return enumerate_subdomains


def enumerate_subdomain_list(tld_list, max_workers):
    """
    Function Uses thread pool to execute the enumerate_subdomains function concurrently for each
    TLD in the input list. The results of each thread are then combined into a single list
    of enumerated subdomains, which is finally returned by the function
    """
    enumerated_subdomain_list = []

    with ThreadPoolExecutor(max_workers) as executor:
        future_to_tld = {executor.submit(enumerate_subdomains, tld): tld for tld in tld_list}

        for future in as_completed(future_to_tld):
            try:
                result = future.result()
                enumerated_subdomain_list.extend(result)
            except Exception as e:
                tld = future_to_tld[future]
                print(f"An error occurred with {tld}: {e}")

    return enumerated_subdomain_list


def resolve_subdomain(subdomain, dns_servers, sleep_interval):
    """
    The function resolves a subdomain's IP addresses (IPv4 and IPv6) using multiple DNS servers,
    returning two lists of addresses. It optionally waits for a specified sleep interval between
    each resolution attempt and moves to the next DNS server if a resolution fails.
    """
    ipv4_list, ipv6_list = [], []

    # resolves ip addresses using each dns server in list
    for dns_server in dns_servers:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]

        try:
            # IPv4 resolution
            # print("Resolving " + subdomain + " with " + dns_server + " (ipv4)")
            for rdata in resolver.resolve(subdomain, "A"):
                ipv4 = str(rdata)
                if validate_ip(ipv4) == "IPv4" and ipv4 not in ipv4_list:
                    ipv4_list.append(ipv4)

            # IPv6 resolution
            # print("Resolving " + subdomain + " with " + dns_server + " (ipv6)")
            for rdata in resolver.resolve(subdomain, "AAAA"):
                ipv6 = str(rdata)
                # Explode ipv6 address
                exploded_ipv6 = ipaddress.ip_address(ipv6).exploded
                if validate_ip(exploded_ipv6) == "IPv6" and exploded_ipv6 not in ipv6_list:
                    ipv6_list.append(exploded_ipv6)

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            # Handle errors if necessary
            pass

        time.sleep(sleep_interval)

    return ipv4_list, ipv6_list


def resolve_subdomain_list(subdomain_list, dns_servers, sleep_interval, max_workers):
    """
    The function resolves IPv4 and IPv6 addresses for a list of subdomains using a thread pool
    executor with up to 5 workers, returning two sorted lists of unique addresses. It prints an
    error message for any resolution errors and removes duplicates before returning the lists.
    """
    resolved_ipv4_list, resolved_ipv6_list = [], []

    with ThreadPoolExecutor(max_workers) as executor:
        future_to_subdomain = {
            executor.submit(resolve_subdomain, subdomain, dns_servers, sleep_interval): subdomain
            for subdomain in subdomain_list
        }

        for future in as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            try:
                ips_v4, ips_v6 = future.result()
                resolved_ipv4_list.extend(ips_v4)
                resolved_ipv6_list.extend(ips_v6)
            except Exception as e:
                print(f"Error resolving {subdomain}: {e}")

    return resolved_ipv4_list, resolved_ipv6_list


def main():
    # dns servers for resolving
    dns_servers = ["10.114.27.1", "9.9.9.9", "208.67.222.222", "1.1.1.1", "8.8.8.8"]
    resolve_sleep = 1
    resolve_workers = 2
    subdomain_workers = 1

    # fetch tld list
    tld_list = fetch_url("https://static.fclaude.net/tracker-tlds.txt")

    # print info to screen
    print("----DNS SERVERS----")
    pprint.pprint(dns_servers)
    print("----TOP-LEVEL DOMAINS----")
    pprint.pprint(tld_list)
    print("\n")

    # enumerate subdomains for each tld
    enumerated_subdomains = enumerate_subdomain_list(tld_list, subdomain_workers)

    # extend, dedupe, sort, and write subdomain list to file
    enumerated_subdomains.extend(fetch_url("https://static.fclaude.net/tracker-subdomains.txt"))
    subdomain_list = sorted(set(enumerated_subdomains))
    write_list_to_file(subdomain_list, "/var/www/static/tracker-subdomains.txt")

    # resolve subdomains
    resolved_ipv4, resolved_ipv6 = resolve_subdomain_list(
        subdomain_list, dns_servers, resolve_sleep, resolve_workers
    )

    # validate, dedupe, sort, and write resolved ipv4 and ipv6 addresses
    validated_ipv4 = [ip for ip in resolved_ipv4 if validate_ip(ip) == "IPv4"]
    ipv4_list = sorted(set(validated_ipv4))
    write_list_to_file(ipv4_list, "/var/www/static/tracker-ipaddrs-ipv4.txt")

    validated_ipv6 = [ip for ip in resolved_ipv6 if validate_ip(ip) == "IPv6"]
    ipv6_list = sorted(set(validated_ipv6))
    write_list_to_file(ipv6_list, "/var/www/static/tracker-ipaddrs-ipv6.txt")

    # print info to screen
    print("----FINAL IPv4 ADDRESSES----")
    pprint.pprint(ipv4_list)
    print("----FINAL IPv6 ADDRESSES----")
    pprint.pprint(ipv6_list)
    print("\n")


if __name__ == "__main__":
    main()
