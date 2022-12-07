from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
import platform
import time
import os
import re

mac_address_regex = re.compile(r'([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})|([0-9A-Fa-f]{2}-){5}([0-9A-Fa-f]{2})')
broadcast_mac_address = 'ff:ff:ff:ff:ff:ff'
ARPisat = 2

indicators = [False, False, False]


def multiple_arp_answers(pkt):
    if pkt[ARP].op == ARPisat:
        arp_request = Ether(dst=broadcast_mac_address) / ARP(pdst=pkt[ARP].psrc)
        sniffer = AsyncSniffer(lfilter=lambda p: ARP in p and p[ARP].psrc == arp_request[ARP].pdst)
        sniffer.start()
        sendp(arp_request, verbose=0)
        time.sleep(2)
        ans = sniffer.stop()
        macs = [p[Ether].src for p in ans]

        if len(macs) != len(set(macs)):
            return True

    return False

def arp_table_contains_duplicates():
    if platform.system() == "Windows":
        arp_table = os.popen("arp -a").read().split("Interface")
        for iface in arp_table:
            mac_addresses = [line for line in re.findall(mac_address_regex, iface) if
                             line != "ff-ff-ff-ff-ff-ff" and line != broadcast_mac_address]
            if len(mac_addresses) != len(set(mac_addresses)):
                return True

    elif platform.system() == "Linux":
        arp_table = open("/proc/net/arp", "r").read().split('\n')
        mac_addresses = []
        for arp_line in arp_table:
            if arp_line != '':
                mac = arp_line.split()[3]
                if re.match(mac_address_regex, mac) is not None and mac != "ff-ff-ff-ff-ff-ff" and \
                        mac != broadcast_mac_address:
                    mac_addresses.append(mac)

        if len(mac_addresses) != len(set(mac_addresses)):
            return True

    return False


def responds_to_ping_request(pkt):
    if pkt[ARP].op == ARPisat:
        ping_pkt = Ether(dst=pkt[ARP].hwsrc) / IP(dst=pkt[ARP].psrc) / ICMP()
        res = srp1(ping_pkt, timeout=1, verbose=0)
        if not res:
            return True
    return False


def print_state():
    if platform.system() == "Windows":
        os.system("cls")
    elif platform.system() in ["Linux", "Darwin"]:
        os.system("clear")

    print("This is the report:\n"
          f"Not responding to a Ping request:                         {indicators[0]}\n"
          f"Receiving multiple responses per one Arp query:           {indicators[1]}\n"
          f"System Arp cache contains multiple IPs for the same MAC:  {indicators[2]}\n")
    if sum(indicators) >= 2:
        print("As far as i know, YOU ARE BEING ARP-SPOOFED")
    else:
        print("As far as i know, you're fine")


class ArpSpoofDetector(DefaultSession):

    def on_packet_received(self, pkt):
        """
        for every arp packet that comes through, check:
        - is host responding to arp request
        - are there multiple responses to arp request
        - does system arp table contains duplicate MACs for different IPs
        """
        indicators[0] = responds_to_ping_request(pkt)

        indicators[1] = multiple_arp_answers(pkt)

        indicators[2] = arp_table_contains_duplicates()

        print_state()


def main():
    print_state()
    sniff(lfilter=lambda pkt: (ARP in pkt and pkt[ARP].hwsrc != (Ether())[Ether].src),
          session=ArpSpoofDetector)


if __name__ == '__main__':
    main()
