import csv
import os
import time
import scapy.all as scapy


class Analyzer:
    def __init__(self):
        self.packets = []
        self.filename = "vector.csv"

    # RECEBE PACOTES (callback)
    def receive_packet(self, packet):
        if scapy.Ether in packet and scapy.IP in packet:
            self.packets.append([
                packet[scapy.IP].src,
                packet[scapy.IP].dst,
                packet[scapy.IP].proto,
                len(packet)
            ])

    # CAPTURA ONLINE (alert_system)
    def capture_window(self, time_window=3, interface=None, fltr=""):
        self.packets = []

        sniffer = scapy.AsyncSniffer(
            iface=interface,
            filter=fltr,
            prn=self.receive_packet,
            store=False
        )

        sniffer.start()
        time.sleep(time_window)
        sniffer.stop()

        packets = self.packets.copy()
        self.packets = []
        return packets

    # GERA VETOR (memória)
    def compute_vector(self, packets):
        if not packets:
            return None

        num_packets = len(packets)
        total_bytes = sum(p[3] for p in packets)
        unique_src_ips = len(set(p[0] for p in packets))
        unique_dst_ips = len(set(p[1] for p in packets))

        tcp_count = sum(1 for p in packets if p[2] == 6)
        udp_count = sum(1 for p in packets if p[2] == 17)
        icmp_count = sum(1 for p in packets if p[2] == 1)

        return [
            num_packets,
            total_bytes,
            unique_src_ips,
            unique_dst_ips,
            tcp_count,
            udp_count,
            icmp_count
        ]

    # OFFLINE (treino)
    def close_window(self):
        vector = self.compute_vector(self.packets)
        if vector is None:
            return

        file_exists = os.path.isfile(self.filename)
        with open(self.filename, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow([
                    "num_packets",
                    "total_bytes",
                    "unique_src_ips",
                    "unique_dst_ips",
                    "tcp_count",
                    "udp_count",
                    "icmp_count"
                ])
            writer.writerow(vector)

        self.packets = []
