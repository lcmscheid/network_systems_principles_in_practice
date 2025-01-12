#!/usr/bin/python3
from scapy.all import *


###
# LAB REQUIREMENT
# Implement findMaxBytesInFlight - which takes in the name of a pcap file, and finds
#                                  the maximum number of bytes in flight during the session
#                                  Basically highest sequence number of sent packets minus
#                                  the highest acknowledgement number received
# Note: you only need to look at direction from server to client
# (which you can tell from three way handshake - client will initiate the connection)
# Note: you need to take into account dropped packets and out of order packets
# Note: you can use the data structure and helper functions provided, but don't need to.


# This class captures some information about a unidirectional flow
# startSeqNum - the starting TCP sequence number for data sent in this flow
# ackNumReceived - tracks the highest acknowledgement number received
# highestSeqNum - for data sent, this holds the highest sequence number seen
# pktLenOfHighestSeqNumPacket - for the packet that was the highestSeqNum, this is the length of that packet
# srcIP - the IP address for the source in this flow (the one sending data and the seq num refers to)
# destIP - the IP address for the destination in this flow
# class FlowTracking:
#     def __init__(self, startSeqNum, ackNumReceived, srcIP, dstIP):
#         self.startSeqNum = startSeqNum
#         self.ackNumReceived = ackNumReceived
#         self.highestSeqNum = 0
#         self.pktLenOfHighestSeqNumPacket = 0
#         self.srcIP = srcIP
#         self.dstIP = dstIP
#
# # TASK
# def print_tcp_packets(pcap):
#     packets = rdpcap(pcap)
#     with open("transmission.txt", "w") as f:
#         for packet in packets:
#             # Ethernet layer
#             eth_layer = packet.getlayer(Ether)
#             if eth_layer:
#                 f.write(f"Source MAC: {eth_layer.src}\n")
#                 f.write(f"Destination MAC: {eth_layer.dst}\n")
#
#             # IP layer
#             ip_layer = packet.getlayer(IP)
#             if ip_layer:
#                 f.write(f"Source IP: {ip_layer.src}\n")
#                 f.write(f"Destination IP: {ip_layer.dst}\n")
#
#             # TCP layer
#             tcp_layer = packet.getlayer(TCP)
#             if tcp_layer:
#                 f.write(f"Source Port: {tcp_layer.sport}\n")
#                 f.write(f"Destination Port: {tcp_layer.dport}\n")
#                 f.write(f"TCP Flags: {tcp_layer.flags}\n")
#                 f.write(f"Sequence Number: {tcp_layer.seq}\n")
#                 f.write(f"Acknowledgement Number: {tcp_layer.ack}\n")
#
#             # UDP layer
#             udp_layer = packet.getlayer(UDP)
#             if udp_layer:
#                 f.write(f"Source Port: {udp_layer.sport}\n")
#                 f.write(f"Destination Port: {udp_layer.dport}\n")
#
#             f.write("-" * 20 + "\n")

# Given a pcap file name as a string, this function will return the max number of bytes
# that were in flight (unacknowledge) for this stream.
# Assume - only one TCP session (i.e., one pair of IP address and TCP ports)
#        - the pcap starts with the 3 way handshake as the first 3 packets

# class TCPAnalyzer:
#     def __init__(self):
#         self.sent_packets = {}  # {seq_no: (packet, timestamp)}
#         self.max_bytes_in_flight = 0
#         self.current_bytes_in_flight = 0
#
#     def find_max_bytes_in_flight(self, capture_pcap):
#         packets = rdpcap(capture_pcap)
#         for packet in packets:
#             if TCP in packet:
#                 seq_no = packet[TCP].seq
#                 payload_size = len(packet[TCP].payload)
#
#                 if packet[TCP].flags == 'S':  # SYN packet, start tracking
#                     self.sent_packets = {}
#                     self.max_bytes_in_flight = 0
#                     self.current_bytes_in_flight = 0
#
#                 elif packet[TCP].flags == 'A':  # ACK packet, update tracking
#                     ack_no = packet[TCP].ack
#                     for seq in list(self.sent_packets):
#                         if seq < ack_no:
#                             sent_packet, _ = self.sent_packets.pop(seq)
#                             self.current_bytes_in_flight -= len(sent_packet[TCP].payload)
#
#                 elif packet[TCP].flags == 'R':  # RST, reset
#                     self.sent_packets = {}
#                     self.max_bytes_in_flight = 0
#                     self.current_bytes_in_flight = 0
#
#                 else:  # Data packet
#                     if seq_no in self.sent_packets:
#                         print("potential retransmission detected!")
#                         # Potential retransmission
#                         previous_packet, previous_timestamp = self.sent_packets[seq_no]
#
#                         # Check if it's a different packet (e.g., different timestamp)
#                         if previous_timestamp != time.time():
#                             print("Retransmission detected!")
#
#                             # Adjust bytes in flight (optional, depends on your goal)
#                             self.current_bytes_in_flight -= len(previous_packet[TCP].payload)
#                             self.current_bytes_in_flight += payload_size
#
#                             # Update the stored packet with the newer retransmission
#                             self.sent_packets[seq_no] = (packet, time.time())
#                     else:
#                         # New packet
#                         self.sent_packets[seq_no] = (packet, time.time())
#                         self.current_bytes_in_flight += payload_size
#
#                     self.max_bytes_in_flight = max(self.max_bytes_in_flight, self.current_bytes_in_flight)
#
#
#         return self.max_bytes_in_flight
#
# class TCPAnalyzer:
#     def __init__(self):
#         self.sent_packets = {}  # {seq_no: (packet, timestamp)}
#         self.max_bytes_in_flight = 0
#         self.current_bytes_in_flight = 0
#         self.retransmissions = 0
#         self.out_of_order_packets = 0
#
#     def find_max_bytes_in_flight(self, capture_pcap):
#         packets = rdpcap(capture_pcap)
#         for packet in packets:
#             if TCP in packet:
#                 seq_no = packet[TCP].seq
#                 payload_size = len(packet[TCP].payload)
#
#                 if packet[TCP].flags.S:  # SYN packet, start tracking
#                     self.sent_packets = {}
#                     self.max_bytes_in_flight = 0
#                     self.current_bytes_in_flight = 0
#                     self.retransmissions = 0
#                     self.out_of_order_packets = 0
#
#                 elif packet[TCP].flags.A:  # ACK packet, update tracking
#                     ack_no = packet[TCP].ack
#                     acked_packets = []
#                     for seq in sorted(self.sent_packets):  # Process in order
#                         if seq < ack_no:
#                             acked_packets.append(seq)
#                         else:
#                             print("ACKed packet detected!")
#                             break  # No need to check further
#
#                     for seq in acked_packets:
#                         sent_packet, _ = self.sent_packets.pop(seq)
#                         self.current_bytes_in_flight -= len(sent_packet[TCP].payload)
#
#                 elif packet[TCP].flags.R:  # RST, reset
#                     print("Reset detected!")
#                     self.sent_packets = {}
#                     self.max_bytes_in_flight = 0
#                     self.current_bytes_in_flight = 0
#                     self.retransmissions = 0
#                     self.out_of_order_packets = 0
#
#                 else:  # Data packet
#                     if seq_no in self.sent_packets:
#                         # Potential retransmission
#                         previous_packet, previous_timestamp = self.sent_packets[seq_no]
#                         if previous_timestamp != time.time():
#                             print("Retransmission detected!")
#                             self.retransmissions += 1
#
#                             # Adjust bytes in flight (optional)
#                             self.current_bytes_in_flight -= len(previous_packet[TCP].payload)
#                             self.current_bytes_in_flight += payload_size
#
#                         self.sent_packets[seq_no] = (packet, time.time())  # Update with the latest packet
#                     else:
#                         # Check for out-of-order packets
#                         if self.sent_packets and seq_no < max(self.sent_packets):
#                             print("Out-of-order packet detected!")
#                             self.out_of_order_packets += 1
#
#                         self.sent_packets[seq_no] = (packet, time.time())
#                         self.current_bytes_in_flight += payload_size
#
#                     self.max_bytes_in_flight = max(self.max_bytes_in_flight, self.current_bytes_in_flight)
#
#         return self.max_bytes_in_flight
#
#
# if __name__ == '__main__':
#     analyzer = TCPAnalyzer()
#     # pcap is a server side capture
#     # maxBytesInFlight = analyzer.find_max_bytes_in_flight("simple-tcp-session.pcap")
#     # print("Max: " + str(maxBytesInFlight))
#     # print()
#
#     maxBytesInFlight = analyzer.find_max_bytes_in_flight("out_10m_0p.pcap")
#     print("Max: " + str(maxBytesInFlight))
#     print()

# This class captures some information about a unidirectional flow
# startSeqNum - the starting TCP sequence number for data sent in this flow
# ackNumReceived - tracks the highest acknowledgement number received
# highestSeqNum - for data sent, this holds the highest sequence number seen
# pktLenOfHighestSeqNumPacket - for the packet that was the highestSeqNum, this is the length of that packet
# srcIP - the IP address for the source in this flow (the one sending data and the seq num refers to)
# destIP - the IP address for the destination in this flow
class FlowTracking:
    def __init__(self, startSeqNum, ackNumReceived, srcIP, dstIP):
        self.startSeqNum = startSeqNum;
        self.ackNumReceived = ackNumReceived;
        self.highestSeqNum = 0;
        self.pktLenOfHighestSeqNumPacket = 0;
        self.srcIP = srcIP;
        self.dstIP = dstIP;


# Returns FlowTracking object for the server side
# (client sends the syn, server sends the synack, client sends ack)
def readHandShake(pcap):
    # read syn
    p = pcap.pop(0);
    seqInit = p[TCP].seq;
    srcInit = p[IP].src;
    dstInit = p[IP].dst;

    # read ack
    p = pcap.pop(0);
    if (p[TCP].ack != seqInit + 1):
        print(string("ERROR: seq=" + seqInit + ", ack=" + p[TCP].ack));
    if (p[IP].src != dstInit or p[IP].dst != srcInit):
        print(string(
            "ERROR: srcInit=" + srcInit + ", destInit=" + dstInit + "Resp: src=" + p[IP].src + ",dst=" + p[IP].dst));

    seqOther = p[TCP].seq

    # read synack
    p = pcap.pop(0);
    if (p[TCP].ack != seqOther + 1):
        print(string("ERROR: seq=" + seqInit + ", ack=" + p[TCP].ack));
    if (p[IP].src != srcInit or p[IP].dst != dstInit):
        print(string(
            "ERROR: srcInit=" + srcInit + ", destInit=" + dstInit + "Resp: src=" + p[IP].src + ",dst=" + p[IP].dst));

    return FlowTracking(seqOther, seqOther + 1, dstInit, srcInit)


# Returns true if the packet p is in the direction of the unidirectional
# flow represented by f (FlowTracking)
def isFlowEgress(p, f):
    if (p[IP].src == f.srcIP):
        return True
    return False


# TASK

# Given a pcap file name as a string, this function will return the max number of bytes
# that were in flight (unacknowledge) for this stream.
# Assume - only one TCP session (i.e., one pair of IP address and TCP ports)
#        - the pcap starts with the 3 way handshake as the first 3 packets
from scapy.all import rdpcap, TCP


def findMaxBytesInFlight(pcapfile):
    sent_packets = {}  # Track packets with sequence numbers and payload sizes
    max_bytes_in_flight = 0
    current_bytes_in_flight = 0

    packets = rdpcap(pcapfile)
    for packet in packets:
        if TCP in packet:  # Process only TCP packets
            seq_no = packet[TCP].seq
            payload_size = len(packet[TCP].payload)

            # SYN Packet: Reset tracking structures at the start of a new session
            if packet[TCP].flags.S:  # SYN flag set
                sent_packets = {}
                current_bytes_in_flight = 0
                max_bytes_in_flight = 0

            # ACK Packet: Acknowledge data
            if packet[TCP].flags.A:  # ACK flag set
                ack_no = packet[TCP].ack

                # Remove all packets that have been acknowledged
                for seq in list(sent_packets.keys()):  # List to avoid mutation while iterating
                    if seq < ack_no:  # If this packet is acknowledged:
                        current_bytes_in_flight -= sent_packets.pop(seq)

            # Data Packet: Add new unacknowledged bytes
            if payload_size > 0:  # Only consider packets with payload
                if seq_no not in sent_packets:  # Avoid counting retransmissions
                    sent_packets[seq_no] = payload_size
                    current_bytes_in_flight += payload_size
                    max_bytes_in_flight = max(max_bytes_in_flight, current_bytes_in_flight)

    return max_bytes_in_flight


class ExpectedPacket:
    def __init__(self, ack, seq, length):
        self.ack = ack
        self.seq = seq
        self.length = length


def findMaxBytesInFlight2(pcapfile):
    packets = rdpcap(pcapfile)
    src = None
    dst = None

    p = packets.pop(0)
    if p[TCP].flags != 'S':
        print("ERROR: first packet is not SYN")
        return -1
    src = p[IP].dst
    dst = p[IP].src

    p = packets.pop(0)
    if p[TCP].flags != 'SA':
        print("ERROR: second packet is not SYNACK")
        return -1

    p = packets.pop(0)
    if p[TCP].flags != 'A' and p[IP].src != src:
        print("ERROR: third packet is not ACK for the end of the handshake")
        return -1

    p = packets.pop(0)

    # sender [Seq, Len, Ack]
    # receiver [Ack, Seq + Len,
    bytes_in_flight = 0
    counter_bytes_in_flight = 0
    counter = []
    data_transfer_state = False
    ack_data_transfer_state = False
    found_expected_packet = False
    for packet in packets:
        if TCP not in packet:
            return -1
        if packet[IP].src == src:
            if len(counter) == 0:
                bytes_in_flight = max(bytes_in_flight, counter_bytes_in_flight)
                counter_bytes_in_flight = 0
            # sender
            tcp = packet[TCP]
            expected_packet = ExpectedPacket(tcp.ack, tcp.seq + len(tcp.payload), len(tcp.payload))
            if expected_packet.length == 0:
                continue
            counter.append(expected_packet)
            continue
        if packet[IP].src == dst:
            # receiver
            tcp = packet[TCP]
            # found_expected_packet = False
            for p in counter:
                if p.ack == tcp.seq and p.seq == tcp.ack:
                    counter_bytes_in_flight += p.length
                    counter.remove(p)
                    continue



    return bytes_in_flight

def findMaxBytesInFlight3(pcapfile):
    sent_packets = {}  # Track packets by seq_no (key) and payload size (value)
    max_bytes_in_flight = 0
    current_bytes_in_flight = 0
    initial_seq = None
    seq_wrap_count = 0

    packets = rdpcap(pcapfile)
    for i, packet in enumerate(packets):
        if TCP in packet:
            seq_no = packet[TCP].seq
            ack_no = packet[TCP].ack
            payload_size = len(packet[TCP].payload)
            flags = packet[TCP].flags

            if initial_seq is None and flags.S:
                initial_seq = seq_no

            # Handle sequence number wrapping
            if initial_seq is not None:
                seq_no = (seq_no - initial_seq + seq_wrap_count * 2**32) % 2**32
                ack_no = (ack_no - initial_seq + seq_wrap_count * 2**32) % 2**32

            # Handle SYN Packet
            if flags.S and not flags.A:
                sent_packets.clear()
                current_bytes_in_flight = 0
                continue

            # Handle Data Packet
            if payload_size > 0:
                end_seq = seq_no + payload_size
                for s in range(seq_no, end_seq):
                    if s not in sent_packets:
                        sent_packets[s] = 1
                        current_bytes_in_flight += 1

                max_bytes_in_flight = max(max_bytes_in_flight, current_bytes_in_flight)

            # Handle ACK Packet
            if flags.A:
                for seq in list(sent_packets.keys()):
                    if seq < ack_no:
                        current_bytes_in_flight -= sent_packets.pop(seq)

            # Check for sequence number wrap
            if seq_no < 1000 and max(sent_packets.keys(), default=0) > 4294967000:
                seq_wrap_count += 1

    return max_bytes_in_flight




if __name__ == '__main__':
    # pcap is a server side capture
    maxBytesInFlight = findMaxBytesInFlight3("simple-tcp-session.pcap")
    print("Max: " + str(maxBytesInFlight))
    print()

    maxBytesInFlight = findMaxBytesInFlight3("out_10m_0p.pcap")
    print("Max: " + str(maxBytesInFlight))
    print()
