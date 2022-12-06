#        for every arp packet that comes through, check the following
#        - ping the host and see if there is a response
#        - check if there are multiple answers from ARP-ing host of is-at pkt
#        - check if system arp table contains duplicate MACs for different IPs

# to prevent it use static arp entries


errors = 0

from scapy.all import *
import re

from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
import platform
import time
import os

mac_address_regex = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
broadcast_mac_address = 'ff:ff:ff:ff:ff:ff'
ARPisat = 2

indicators = {"I1": 0, "I2": 0, "I3": 0}


def multiple_arp_answers(pkt):
    """
    - check if there are multiple answers for an ARP request
    """
    if pkt[ARP].op == ARPisat:
        # send who has pkt with psrc from the arp pkt and if there are 2 answers we turn on the indicator
        arp_who_has = Ether(dst=broadcast_mac_address) / ARP(pdst=pkt[ARP].psrc)
        # receiver for response packets
        sniffer = AsyncSniffer(lfilter=lambda p: ARP in p and p[ARP].psrc == arp_who_has[ARP].pdst)
        sniffer.start()
        sendp(arp_who_has, verbose=0)
        time.sleep(2)
        ans = sniffer.stop()
        macs_in_ans = [p[Ether].src for p in ans]

        if len(macs_in_ans) != len(set(macs_in_ans)):
            return True

    return False


def arp_table_contains_duplicates():
    """
    - get ARP table and look for duplicate MAC entries with different IPs
    """
    if platform.system() == "Linux":
        arp_table = open("/proc/net/arp", "r").read()
        arp_table = arp_table.split('\n')
        mac_addresses = []
        for arp_line in arp_table:
            if arp_line == '':
                continue
            arp_line = arp_line.split()
            if re.match(mac_address_regex, arp_line[3]):
                mac_addresses.append(arp_line[3])

        if len(mac_addresses) != len(set(mac_addresses)):
            return True

    elif platform.system() == "Windows":
        arp_table = os.popen("arp -a").read()
        arp_table = arp_table.split("Interface")
        for iface in arp_table:
            mac_addresses = [line for line in re.findall('([-0-9a-f]{17})', iface) if line != "ff-ff-ff-ff-ff-ff"]
            if len(mac_addresses) != len(set(mac_addresses)):
                return True

    return False



def responds_to_ping_request(pkt):
    """
    - check if the host is responding to ping request
    """
    if pkt[ARP].op == ARPisat:
        ping_pkt = Ether(dst=pkt[ARP].hwsrc) / IP(dst=pkt[ARP].psrc) / ICMP()
        res = srp1(ping_pkt, timeout=1, verbose=0)
        if not res:
            return True
    return False


def print_state():
    if platform.system() in ["Linux", "Darwin"]:
        os.system("clear")
    elif platform.system() == "Windows":
        os.system("cls")

    print("The Following indicators are being reported:\n"
          f"Host of Arp is_at packet not responding to a Ping request:  {indicators['I1']}\n"
          f"Receiving multiple responses per one Arp who_has request:   {indicators['I2']}\n"
          f"System Arp cache contains multiple IPs for the same MAC:    {indicators['I3']}\n")
    if sum(indicators.values()) >= 2:
        print("To the best of my knowledge, " + "YOU ARE BEING ARP-SPOOFED")
    else:
        print("To the best of my knowledge, " + "you're fine")


class ArpSpoofDetectSession(DefaultSession):

    def on_packet_received(self, pkt):
        """
        for every arp packet that comes through, check the following
        - ping the host and see if there is a response
        - check if there are multiple answers from ARP-ing host of is-at pkt
        - check if system arp table contains duplicate MACs for different IPs
        """
        # INDICATOR 1: Host machine of is_at pkt not responding to ping req.
        indicators["I1"] += int(responds_to_ping_request(pkt))
        # INDICATOR 2: re-ARPing Host of is-at packet produces 2 responses
        indicators["I2"] += int(multiple_arp_answers(pkt))
        # INDICATOR 3: Arp table contains duplicate MACs for different IPs
        indicators["I3"] += int(arp_table_contains_duplicates())
        print_state()


def main():
    print_state()
    sniff(lfilter=lambda pkt: (ARP in pkt and pkt[ARP].hwsrc != (Ether())[Ether].src),
          session=ArpSpoofDetectSession)


if __name__ == '__main__':
    main()


