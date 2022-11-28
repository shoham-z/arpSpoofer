# sniff all arp requests (op=2 probably)
# for each packet:
#     if packet in array of past received packets, add it to the array with a timestamp
#     check arp table for duplicate mac/ip
#     check for too many arp REPLAY packets in short time
#     check for duplicated packet - the same IP address with different MAC address.
#     Check if the MAC address is belong to the IP address. (using get_mac function)
# to prevent it use static arp entries

import datetime
import os
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether

packets = []  # constructed of (ip, mac, timestamp)
errors = 0


def get_mac(ip):
    arp_request_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered_list = []
    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)
        print(answered_list)
        return answered_list[0][1].hwsrc
    except:
        print("no machine found with the ip: " + ip)


if __name__ == "__main__":
    errors = 0
    while True:
        # getting arp table
        os.system("arp -a> arpTable")
        with open("arpTable", "r") as f:
            for line in f:
                print(line)
                packets.append(
                    (line.split()[1][1:-1], line.split()[3], datetime.datetime.now().strftime("%H:%M:%S.%f")))

        # getting more info about network

        # check for duplicates
        for packet in packets:
            if get_mac(packet[0]) != packet[1]:
                errors += 1

        if errors > 1:
            print("We are under attack!!\nEveryone into position and prepare to attack!!!")
            exit()
