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

from tracker_utils import validate_url

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
