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

def dedupe_and_sort(ip_list):
    deduped_set = set(ip_list)
    sorted_list = sorted(deduped_set)
    return sorted_list

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


def enumerate_subdomains(domain):
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
            domain,
        ]
        # amass changed their output so needs to be reworked
        #"amass": [
        #    "/home/fclaude/.local/bin/amass",
        #    "enum",
        #    "-passive",
        #    "-nocolor",
        #    "-dns-qps",
        #    "10",
        #    "-timeout",
        #    "10",
        #    "-d",
        #    domain,
        #],
        #"subfinder": [
        #    "/home/fclaude/.local/bin/subfinder",
        #    "-no-color",
        #    "-silent",
        #    "-rate-limit",
        #    "1",
        #    "-max-time",
        #    "30",
        #    "-timeout",
        #    "120",
        #    "-exclude-ip",
        #    "-all",
        #    "-t",
        #    "1",
        #    "-d",
        #    domain,
        #]
    }

    for tool_name, cmd in enumeration_tools.items():
        try:
            print(f"Enumerating subdomains for {domain} using {tool_name}")
            enumeration_result = subprocess.check_output(cmd, timeout=3600, encoding="utf8").splitlines()
            for enumerated_subdomain in enumeration_result:
                # validate enumerated subdomains
                validated_subdomain = validate_url(enumerated_subdomain)
                if validated_subdomain is not None:
                    enumerate_subdomains.append(validated_subdomain.strip())

        except subprocess.SubprocessError as e:
            print(f"Error using {tool_name} for {domain}: {e}")

    return enumerate_subdomains


def enumerate_subdomain_list(domain_list, max_workers):
    """
    Function Uses thread pool to execute the enumerate_subdomains function concurrently for each
    TLD in the input list. The results of each thread are then combined into a single list
    of enumerated subdomains, which is finally returned by the function
    """
    enumerated_subdomain_list = []

    with ThreadPoolExecutor(max_workers) as executor:
        future_to_enumerate_subdomains = {executor.submit(enumerate_subdomains, domain): domain for domain in domain_list}

        for future in as_completed(future_to_enumerate_subdomains):
            try:
                enumerate_subdomain_result = future.result()
                enumerated_subdomain_list.extend(enumerate_subdomain_result)

            except Exception as e:
                domain = future_to_enumerate_subdomains[future]
                print(f"An error occurred with {domain}: {e}")

    return enumerated_subdomain_list


def resolve_subdomain(subdomain, dns_servers, sleep_interval):
    """
    The function resolves a subdomain's IP addresses (IPv4 and IPv6) using multiple DNS servers,
    returning two lists of addresses. It optionally waits for a specified sleep interval between
    each resolution attempt and moves to the next DNS server if a resolution fails.
    """
    if not dns_servers or sleep_interval < 0:
        raise ValueError("Invalid dns_servers list or sleep_interval")

    resolve_ipv4_list, resolve_ipv6_list = [], []
    resolver = dns.resolver.Resolver()

    for dns_server in dns_servers:
        resolver.nameservers = [dns_server]
        try:
            # IPv4 resolution
            dns_response_v4 = resolver.resolve(subdomain, 'A', raise_on_no_answer=False, search=False)
            if dns_response_v4:
                resolve_ipv4_list.extend([ipv4.address for ipv4 in dns_response_v4])
                logging.info(f"{subdomain} ({dns_server}) --------> {resolve_ipv4_list}")

            # IPv6 resolution
            dns_response_v6 = resolver.resolve(subdomain, 'AAAA', raise_on_no_answer=False, search=False)
            if dns_response_v6:
                resolve_ipv6_list.extend([ipv6.address for ipv6 in dns_response_v6])
                logging.info(f"{subdomain} ({dns_server}) --------> {resolve_ipv6_list}")

        except (dns.name.LabelTooLong, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoAnswer) as e:
            #logging.error(f"Error resolving {subdomain} with {dns_server}: {e}")
            #logging.info("Sleeping for 30 seconds...")
            #time.sleep(30)  # Sleep after an unsuccessful resolution
            continue

        time.sleep(sleep_interval)  # Sleep after each successful attempt per DNS server

    return resolve_ipv4_list, resolve_ipv6_list


def resolve_subdomain_list(subdomain_list, dns_servers, sleep_interval, max_workers):
    resolved_ipv4_list, resolved_ipv6_list = [], []

    with ThreadPoolExecutor(max_workers) as executor:
        future_to_resolve_subdomain = {
            executor.submit(resolve_subdomain, subdomain, dns_servers, sleep_interval): subdomain for subdomain in subdomain_list}
        for future in as_completed(future_to_resolve_subdomain):
            subdomain = future_to_resolve_subdomain[future]
            try:
                result_v4, result_v6 = future.result()
                resolved_ipv4_list.extend(result_v4)
                resolved_ipv6_list.extend(result_v6)
            except Exception as e:
                print(f"Error resolving {subdomain}: {e}")

    return resolved_ipv4_list, resolved_ipv6_list


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # dns servers for resolving
    dns_servers = ["10.114.27.1", "9.9.9.9", "208.67.222.222", "1.1.1.1", "8.8.8.8"]
    resolve_sleep = 0.75
    resolve_workers = 3
    subdomain_workers = 1

    print("---- DNS SERVERS----")
    pprint.pprint(dns_servers)

    # fetch domain list
    domain_list = fetch_domains_from_url("https://static.fclaude.net/tracker-domains.txt")

    print("---- DOMAINS TO ENUMERATE----")
    pprint.pprint(domain_list)

    # enumerate subdomains for each domain
    enumerated_subdomains = []
    #enumerated_subdomains = enumerate_subdomain_list(domain_list, subdomain_workers)

    #print("---- ENUMERATED SUBDOMAINS----")
    #pprint.pprint(enumerated_subdomains)

    # extend subdomain list
    enumerated_subdomains.extend(fetch_domains_from_url("https://static.fclaude.net/tracker-subdomains.txt"))

    #print("---- ENUMERATED SUBDOMAINS----")
    #pprint.pprint(enumerated_subdomains)

    # dedupe & sort subdomains
    unique_subdomains = dedupe_and_sort(enumerated_subdomains)

    # write subdomains to list
    #write_list_to_file(unique_subdomains, "/var/www/static/tracker-subdomains.txt")

    # resolve subdomains
    resolved_ipv4, resolved_ipv6 = resolve_subdomain_list(
        unique_subdomains, dns_servers, resolve_sleep, resolve_workers
    )

    write_list_to_file(resolved_ipv4, "/var/www/static/tracker-ipaddrs-ipv4-unduped.txt")
    write_list_to_file(resolved_ipv6, "/var/www/static/tracker-ipaddrs-ipv6-unduped.txt")

    # print info to screen
    print("----UNDUPED IPv4 ADDRESSES----")
    pprint.pprint(resolved_ipv4)
    print("----UNDUPED IPv6 ADDRESSES----")
    pprint.pprint(resolved_ipv6)
    print("\n")

    # dedupe & sort addresses
    #unique_ipv4 = dedupe_and_sort(resolved_ipv4)
    #unique_ipv6 = dedupe_and_sort(resolved_ipv6)

    # validate, dedupe, sort, and write resolved ipv4 and ipv6 addresses
    #validated_ipv4 = [ip for ip in resolved_ipv4 if validate_ip(ip) == "IPv4"]
    #ipv4_list = sorted(set(validated_ipv4))
    #write_list_to_file(ipv4_list, "/var/www/static/tracker-ipaddrs-ipv4.txt")

    #validated_ipv6 = [ip for ip in resolved_ipv6 if validate_ip(ip) == "IPv6"]
    #ipv6_list = sorted(set(validated_ipv6))
    #write_list_to_file(ipv6_list, "/var/www/static/tracker-ipaddrs-ipv6.txt")

    # print info to screen
    print("----FINAL IPv4 ADDRESSES----")
    #pprint.pprint(ipv4_list)
    print("----FINAL IPv6 ADDRESSES----")
    #pprint.pprint(ipv6_list)
    print("\n")


if __name__ == "__main__":
    main()
