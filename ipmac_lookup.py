#!/usr/bin/python
from sh import grep, avahi_resolve_address, wget
import os, sys, re, sh

OUI_FILE = '/usr/share/arp-scan/ieee-oui.txt'

stdout = sys.stdout.write

oui_url = 'https://raw.githubusercontent.com/royhills/arp-scan/master/ieee-oui.txt'

mac_regex = re.compile('(?:[0-9a-fA-F]:?){12}')
ipv4_like_regex = re.compile(r'[0-9]+(?:\.[0-9]+){3}')
valid_ip_octets = lambda ip: all([0<=int(p)<256 for p in ip.split('.')])


def check_oui_file_and_prompt(oui_file):
    tmp_oui_file = '/tmp/ieee-oui.txt'
    home_oui_file = os.path.expanduser('~') + 'ieee-oui.txt'
    paths = [oui_file, tmp_oui_file, home_oui_file]
    for filepath in paths:
        if os.path.exists(filepath):
            return filepath
    stdout('\nCould not find any of {}. Execute this command to download:\n\t{}\n'
           ''.format(paths, 'wget {} -O ~/ieee-oui.txt'.format(oui_url)))
    return None

def extract_first_ip(text):
    dot_matches = re.findall(ipv4_like_regex, text)
    ips = [x for x in dot_matches if valid_ip_octets(x)]
    return ips[0] if ips else None

def sh_host(ip):
    call = sh.host(ip, _ok_code=[0,1])
    if call.exit_code != 0:
        return None
    else:
        host = str(call).split(' pointer ')[1:]
        return host[0] if host else None

def extract_first_mac(text):
    macs = re.findall(mac_regex, text)
    return macs[0] if macs else None

def get_vendor(mac):
    if not mac:
        return None
    grepped = grep(
        mac.upper().replace(':','')[:6],
        OUI_FILE,
        _ok_code=[0,1]
    )
    return str(grepped)[7:] or '<unknown vendor>'

def dict_to_string(d):
    return '{{{}}}'.format(
        ', '.join(
            ["{}: {}".format(k, v) for k, v in d.iteritems()]
        )
    )

def process_stdin():
    lines = sys.stdin.readlines()
    ips = map(extract_first_ip, lines)
    macs = map(extract_first_mac, lines)
    _avahi_call = [(ip, avahi_resolve_address(ip, _iter=True)) for ip in ips if ip]
    avahi = {k:str(v) for (k,v) in _avahi_call}
    for line in lines:
        ip = extract_first_ip(line)
        mac = extract_first_mac(line)
        half_sep = '\t' if '\t' in line else ' '*4
        sep = half_sep * 2
        extra = ''
        if mac:
            extra += sep + get_vendor(mac)
        if ip:
            avahi_host = avahi[ip].split('\t')[1] if avahi.get(ip, False) else ''
            extra += sep + (sh_host(ip) or avahi_host or '<unknown host>')
        if extra:
            sys.stdout.write((line + half_sep + extra).replace('\n', '') + '\n')
        else:
            sys.stdout.write(line)


help_text = ''\
"""
IP&MAC address lookup script
============================
This script will find the the first IP and MAC address in lines
from stdin, and append MAC-vendor and IP hostname to the lines if
found.

Usage:
------
File:
    cat my_ip_and_mac_addresses.txt | ./ipmac_lookup.py

Local subnet:
    sudo arp-scan 192.168.1.0/24 | ./ipmac_lookup.py

Local ip address:
    arp 192.168.1.1 | ./ipmac_lookup.py
 Output:
    Address          HWtype  HWaddress           Flags Mask  Iface
    192.168.122.1    ether   38:2c:4b:aa:bb:cc   C           eth0    ASUSTek COMPUTER INC.   somehostname.local

The script currently processes all stdin at once, because executing
`avahi-resolve-address` on a bunch of IP addresses is a lot faster than
potentially timing out on one IP address after another.

TODO: Rewrite in order to choose if we want to process stdin one line at a
      time, which would make it possible to use the script as a filter-step
      in a tail -f command, for example.

A prerequisite is a ieee-oui.txt file for performing the MAC <--> vendor
lookup.
The official IEEE link is dead slow. A faster mirror can be found at:
https://raw.githubusercontent.com/royhills/arp-scan/master/ieee-oui.txt
"""

if __name__ == '__main__':
    if os.isatty(0):
        stdout(help_text + '\n')
    else:
        OUI_FILE = check_oui_file_and_prompt(OUI_FILE)
        process_stdin()

