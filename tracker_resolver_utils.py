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

def resolve_subdomain(subdomain, dns_servers, sleep_interval):
    """
    The function resolves a subdomain's IP addresses (IPv4 and IPv6) using multiple DNS servers,
    returning two lists of addresses. It optionally waits for a specified sleep interval between
    each resolution attempt and moves to the next DNS server if a resolution fails.
    """
    resolve_ipv4_list, resolve_ipv6_list = [], []
    resolver = dns.resolver.Resolver()

    for dns_server in dns_servers:
        resolver.nameservers = dns_server
        try:
            dns_response_v4 = resolver.resolve(subdomain, 'A', lifetime=30, raise_on_no_answer=False, search=False)
            if dns_response_v4:
                for ipv4 in dns_response_v4:
                    logging.info(f"{subdomain} ({dns_server}) --------> {ipv4.address}")
                    resolve_ipv4_list.append(ipv4.address)

            dns_response_v6 = resolver.resolve(subdomain, 'AAAA', lifetime=30, raise_on_no_answer=False, search=False)
            if dns_response_v6:
                 for ipv6 in dns_response_v6:
                     exploded_ipv6 = ipaddress.ip_address(ipv6.address).exploded
                     logging.info(f"{subdomain} ({dns_server}) --------> {exploded_ipv6}")
                     resolve_ipv6_list.append(exploded_ipv6)

        except (dns.name.LabelTooLong, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoAnswer, dns.exception.DNSException, dns.exception.Timeout) as e:
            logging.error(f"Error resolving {subdomain} with {dns_server}: {e}")
            continue

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
                pass

    return resolved_ipv4_list, resolved_ipv6_list

