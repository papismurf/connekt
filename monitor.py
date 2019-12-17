from scapy.all import *

BSSID_FILE = "/root/bssid.txt"
APs = []

def manf(bss):
    file = open(BSSID_FILE, 'r')
    for line in file.read().splitlines():
        if line.split("~")[0][7] == bss[7]:
            return line.split("~")[1].rstrip("\n")
    return "unknown"

def packet_callback(packet):
    if packet.haslayer(Dot11Beacon):
        bss = packet.getlayer(Dot11).addr2.upper()
        if bss not in APs:
            APs.append(bss)

    elif packet.haslayer(Dot11) and packet.getlayer(Dot11).type == 2L and not packet.haslayer(EAPOL):
        # This means it's data frame.
        sn = packet.getlayer(Dot11).addr2.upper()
        rc = packet.getlayer(Dot11).addr1.upper()

        if sn in APs:
            print "AP (%s) [%s] > STA (%s) [%s]" % (sn, manf(sn), rc, manf(rc))
        elif rc in APs:
            print "AP (%s) [%s] < STA (%s) [%s]" % (rc, manf(rc), sn, manf(sn))

if __name__ == "__main__":
    sniff(iface="wlan1mon", prn=packet_callback)