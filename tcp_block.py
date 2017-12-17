#!/usr/bin/python3

from scapy.all import *
import sys, copy

FIN = 0x01
SYN = 0x02
RST = 0x04
ACK = 0x10

requestMethod = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]

def init():
    if len(sys.argv) != 2:
        print ("Usage: ./tcp_block <interface>")
        sys.exit(1)
    global dev, localMac
    dev = sys.argv[1]
    localMac = get_if_hwaddr(dev)


def tcp_block(packet):
    if packet[TCP].flags & (FIN|RST):
        return 
    payload_len = len(packet[TCP].payload);
    if packet[TCP].flags & (SYN | FIN):
        flagAddLen = 1
    else: flagAddLen = 0
    fwd_pkt = copy.deepcopy(packet)
    fwd_pkt[TCP].flags = RST | ACK
    fwd_pkt[TCP].remove_payload()
    fwd_pkt[TCP].seq += payload_len + flagAddLen
    del fwd_pkt[IP].chksum
    del fwd_pkt[TCP].chksum
    del fwd_pkt[IP].len
    fwd_pkt[IP].ttl = 255

    bck_pkt = copy.deepcopy(fwd_pkt)
    bck_pkt[Ether].dst, bck_pkt[Ether].src = bck_pkt[Ether].src, localMac 
    bck_pkt[IP].src, bck_pkt[IP].dst = bck_pkt[IP].dst, bck_pkt[IP].src
    bck_pkt[TCP].sport, bck_pkt[TCP].dport = bck_pkt[TCP].dport, bck_pkt[TCP].sport
    bck_pkt[TCP].seq, bck_pkt[TCP].ack = bck_pkt[TCP].ack, bck_pkt[TCP].seq + payload_len + flagAddLen

    if packet[TCP].payload:
        S = str(packet[TCP].payload)[:10]
        flag = False
        for method in requestMethod:
            if method in S:
                flag = True
        if flag:
            bck_pkt[TCP].flags = FIN | ACK
            bck_pkt[TCP].payload = b'block\r\n'

    #print ("-----------------------------------------------")
    #print (packet.show2())
    #print (fwd_pkt.show2())
    #print (bck_pkt.show2())
    #sys.exit(1)

    sendp(fwd_pkt, iface=dev)
    sendp(bck_pkt, iface=dev)
    print ("send!")






if __name__ == "__main__":
    init()
    sniff(iface=dev, prn=tcp_block, filter="tcp and tcp port 80")
