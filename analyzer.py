import csv
import os
import time
import scapy.all as scapy
from config import settings

class Analyzer:
    def __init__(self):
        self.packets = []
        self.filename = settings.vector_csv

    # RECEBE PACOTES (callback)
    def receive_packet(self, packet):
        if scapy.Ether in packet and scapy.IP in packet:
            # flags TCP (0 se não for TCP)
            tcp_flags = packet[scapy.TCP].flags if scapy.TCP in packet else 0
            # porta de destino (None se não tiver)
            dst_port = None
            if scapy.TCP in packet:
                dst_port = packet[scapy.TCP].dport
            elif scapy.UDP in packet:
                dst_port = packet[scapy.UDP].dport

            self.packets.append([
                packet[scapy.IP].src,   # 0
                packet[scapy.IP].dst,   # 1
                packet[scapy.IP].proto, # 2
                len(packet),            # 3
                packet.time,            # 4
                int(tcp_flags),         # 5
                dst_port,               # 6
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

        tcp_count  = sum(1 for p in packets if p[2] == 6)
        udp_count  = sum(1 for p in packets if p[2] == 17)
        icmp_count = sum(1 for p in packets if p[2] == 1)

        # Taxa
        duration    = max(p[4] for p in packets) - min(p[4] for p in packets)
        duration    = duration if duration > 0 else 1
        packet_rate = num_packets / duration
        byte_rate   = total_bytes / duration

        # Flags TCP
        syn_count = sum(1 for p in packets if p[5] & 0x02)
        fin_count = sum(1 for p in packets if p[5] & 0x01)
        ack_count = sum(1 for p in packets if p[5] & 0x10)

        # Portas e tamanho
        unique_dst_ports = len(set(p[6] for p in packets if p[6] is not None))
        sizes            = [p[3] for p in packets]
        mean_packet_size = sum(sizes) / len(sizes)
        std_packet_size  = (sum((s - mean_packet_size) ** 2 for s in sizes) / len(sizes)) ** 0.5

        return [
            num_packets, total_bytes,
            unique_src_ips, unique_dst_ips,
            tcp_count, udp_count, icmp_count,
            packet_rate, byte_rate,
            syn_count, fin_count, ack_count,
            unique_dst_ports,
            mean_packet_size, std_packet_size
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
                    "num_packets", "total_bytes",
                    "unique_src_ips", "unique_dst_ips",
                    "tcp_count", "udp_count", "icmp_count",
                    "packet_rate", "byte_rate",
                    "syn_count", "fin_count", "ack_count",
                    "unique_dst_ports",
                    "mean_packet_size", "std_packet_size"
                ])
            writer.writerow(vector)

        self.packets = []
