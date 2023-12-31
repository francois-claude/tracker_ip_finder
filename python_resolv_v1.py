#!/usr/bin/env python3

import os
import sys
import re
import requests
import shutil
import subprocess
from time import sleep

URL_WHITELIST = "https://static.fclaude.net/whitelist-master.txt"
URL_SUBDOM    = "https://static.fclaude.net/whitelist-subdoms.txt"
URL_IPADDR    = "https://static.fclaude.net/whitelist-ipaddrs.txt"

TRACKER_IPADDR = '/var/www/static/whitelist-ipaddrs.txt'
TRACKER_SUBDOM = '/var/www/static/whitelist-subdoms.txt'

BIN_FINDOMAIN = '/home/fclaude/.local/bin/findomain'
BIN_SUBFINDER = '/home/fclaude/.local/bin/subfinder'
BIN_AMASS     = '/home/fclaude/.local/bin/amass'

SLEEP_RSLV = 0.10
SLEEP_ENUM = 10.00

URL_REGEX = re.compile(r"[^\n]+")
IP_REGEX  = re.compile(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")

def check_env():
    if shutil.which('findomain') is None:
        print("ERROR :: Findomain not found in path")
        sys.exit(1)

    if shutil.which('amass') is None:
        print("ERROR :: Amass not found in path")
        sys.exit(1)

    if shutil.which('subfinder') is None:
        print("ERROR :: Subfinder not found in path")
        sys.exit(1)

def dedupe_sort(input_list):
    deduped_list = []
    for element in input_list:
        if element not in deduped_list and element != '127.0.0.1' and element != '0.0.0.0':
            deduped_list.append(element)
    return sorted(deduped_list)

def resolve(subdomains):
    ips = []
    new_ips = []

    for subdomain in subdomains:
        # pihole
        print("resolving subdomain with pihole: " + subdomain)
        dig_pihole = os.popen('dig @10.114.27.1 +short +tries=1 timeout=3 ' + subdomain)
        new_ips.extend([new.group() for new in re.finditer(IP_REGEX, dig_pihole.read())])
        sleep(SLEEP_RSLV)

        # quad9
        print("resolving subdomain with quad9: " + subdomain)
        dig_quad9 = os.popen('dig @9.9.9.9 +short +tries=1 timeout=3 ' + subdomain)
        new_ips.extend([new.group() for new in re.finditer(IP_REGEX, dig_quad9.read())])
        sleep(SLEEP_RSLV)

        # opendns
        print("resolving subdomain with opendns: " + subdomain)
        dig_mullvad = os.popen('dig @208.67.222.222 +short +tries=1 timeout=3 ' + subdomain)
        new_ips.extend([new.group() for new in re.finditer(IP_REGEX, dig_mullvad.read())])
        sleep(SLEEP_RSLV)

        # dnswatch
        print("resolving subdomain with cloudflare: " + subdomain)
        dig_dnswatch = os.popen('dig @1.1.1.1 +short +tries=1 timeout=3 ' + subdomain)
        new_ips.extend([new.group() for new in re.finditer(IP_REGEX, dig_dnswatch.read())])
        sleep(SLEEP_RSLV)

        # google
        print("resolving subdomain with google: " + subdomain)
        dig_adguard = os.popen('dig @8.8.8.8 +short +tries=1 timeout=3 ' + subdomain)
        new_ips.extend([new.group() for new in re.finditer(IP_REGEX, dig_adguard.read())])
        sleep(SLEEP_RSLV)

    # dedupe list
    ips = dedupe_sort(new_ips)
    new_ips.clear()
    subdomains.clear()

    # write new masterlist to file
    ip_masterlist = open(TRACKER_IPADDR, "w")
    for ip in ips:
        ip_masterlist.writelines(ip + '\n')
    ip_masterlist.close()

def scan(tlds):
    subdomains = []
    new_subdomains = []

    # import existing url masterlist into array
    response = requests.get(URL_SUBDOM)
    if str(response.status_code).startswith("2"):
        new_subdomains.extend([new.group() for new in re.finditer(URL_REGEX, response.text)])
    
    # enumerate tld subdomains
    for tld in tlds:
        # findomain
        print("enumerating subdomains using findomain: " + tld)
        findomain_cmd = [ BIN_FINDOMAIN, "--rate-limit", "1", "--tcp-connect-threads", "1", "--resolver-timeout", "60", "--quiet", "--target", tld ]
        new_subdomains.extend([new.group() for new in re.finditer(URL_REGEX, subprocess.check_output(findomain_cmd, timeout=300, encoding='utf8'))])
        sleep(SLEEP_ENUM)
        
        # amass
        print("enumerating subdomains using amass: " + tld)
        amass_cmd = [ BIN_AMASS, "enum", "-nocolor", "-passive", "-dns-qps", "1", "-timeout", "10", "-d", tld ]
        new_subdomains.extend([new.group() for new in re.finditer(URL_REGEX, subprocess.check_output(amass_cmd, stderr=subprocess.DEVNULL, timeout=300, encoding='utf8'))])
        sleep(SLEEP_ENUM)

        # subfinder
        print("enumerating subdomains using subfinder: " + tld)
        subfinder_cmd = [ BIN_SUBFINDER, "-no-color", "-silent", "-rate-limit", "1", "-max-time", "30", "-timeout", "120", "-exclude-ip", "-all", "-t", "1", "-d", tld ]
        new_subdomains.extend([new.group() for new in re.finditer(URL_REGEX, subprocess.check_output(subfinder_cmd, timeout=300, encoding='utf8'))])
        sleep(SLEEP_ENUM)

    # dedupe list
    subdomains = dedupe_sort(new_subdomains)
    new_subdomains.clear()
    tlds.clear()

    # write new masterlist to file
    subdom_masterlist = open(TRACKER_SUBDOM, "w")
    for subdomain in subdomains:
        subdom_masterlist.writelines(subdomain + '\n')
    subdom_masterlist.close()

    # pass subdomains to resolver
    resolve(subdomains)

def pull_tlds():
    tlds = []
    response = requests.get(URL_WHITELIST)

    if str(response.status_code).startswith("2"):
        tlds.extend([url.group() for url in re.finditer(URL_REGEX, response.text)])

    scan(tlds)

def main():
    #check_env()
    pull_tlds()

if __name__ == "__main__":
    main()

