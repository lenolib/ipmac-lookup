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

