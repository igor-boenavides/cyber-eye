import csv
import logging
import os
import time
from datetime import datetime

from scapy.all import AsyncSniffer, Ether, ICMP, IP, TCP, UDP, get_if_list

from analyzer import Analyzer
from config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


class PacketCapture:
    """Criação da classe da captura de pacotes."""

    def __init__(self, interface, capture_filter, filename, duration, analyzer=None):
        self.interface = interface
        self.capture_filter = capture_filter
        self.filename = filename
        self.iteration = 0
        self.duration = duration
        self.analyzer = analyzer

    def capture_and_save(self):
        logging.info("Capturando por %ss na interface %s...", self.duration, self.interface)

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.capture_filter,
            prn=self._packet_handler,
            store=False,
        )
        sniffer.start()
        time.sleep(self.duration)
        sniffer.stop()

        if self.analyzer:
            self.analyzer.close_window()

        logging.info("Captura finalizada.")

    def _packet_handler(self, packet):
        if Ether in packet and IP in packet:
            packet_data = self.extract_universal_fields(packet)

            file_exists = os.path.isfile(self.filename)
            with open(self.filename, "a", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                if not file_exists:
                    writer.writerow(
                        [
                            "timestamp",
                            "src_mac",
                            "dst_mac",
                            "src_ip",
                            "dst_ip",
                            "protocol_name",
                            "packet_len",
                            "sport",
                            "dport",
                            "tcp_flags",
                        ]
                    )
                writer.writerow(packet_data)

            self.iteration += 1
            logging.debug("Pacote %s capturado", self.iteration)

            if self.analyzer:
                self.analyzer.receive_packet(packet_data)

    @staticmethod
    def extract_universal_fields(packet):
        timestamp = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")

        if TCP in packet:
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)
        elif UDP in packet:
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            tcp_flags = ""
        elif ICMP in packet:
            protocol = "ICMP"
            sport = None
            dport = None
            tcp_flags = ""
        else:
            protocol = "OTHER"
            sport = None
            dport = None
            tcp_flags = ""

        return [
            timestamp,
            packet[Ether].src,
            packet[Ether].dst,
            packet[IP].src,
            packet[IP].dst,
            protocol,
            len(packet),
            sport,
            dport,
            tcp_flags,
        ]


def main():
    logging.info("Interfaces disponíveis:")
    for i, iface in enumerate(get_if_list(), 1):
        logging.info("%s. %s", i, iface)

    interface = settings.interface
    capture_filter = settings.capture_filter
    filename = "packets.csv"

    duration = settings.capture_duration
    try:
        duration = int(duration) if duration else 30
    except ValueError:
        logging.warning("Valor inválido para duração. Usando padrão de 30 segundos.")
        duration = 30

    analyzer = Analyzer()
    pc = PacketCapture(interface, capture_filter, filename, duration, analyzer)
    pc.capture_and_save()

    logging.info("%s pacotes gravados em '%s'.", pc.iteration, pc.filename)


if __name__ == "__main__":
    main()
