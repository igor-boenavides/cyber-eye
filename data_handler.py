import os
import csv
from datetime import datetime
import scapy.all as scapy
from analyzer import Analyzer

class PacketCapture:
    def __init__(self, interface, fltr, filename, count):
        self.interface = interface
        self.filter = fltr
        self.filename = filename
        self.capture = []
        self.iteration = 0
        self.count = count
        self.analyzer = Analyzer()

    def capture_and_save(self):
        file_exists = os.path.isfile(self.filename)

        try:
            # Adicionado newline="" e encoding="utf-8" para evitar problemas no CSV
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
                        ]
                    )

                capture = scapy.sniff(
                    iface=self.interface, count=self.count, filter=self.filter
                )

                for packet in capture:
                    if scapy.Ether in packet and scapy.IP in packet:
                        packet_data = self.extract_universal_fields(packet)
                        writer.writerow(packet_data)
                        self.iteration += 1

                        # Analisar em tempo real
                        resultado = self.analyzer.predict(packet_data)
                        if resultado == -1:
                            print("🚨 Pacote suspeito detectado!")


        except PermissionError:
            print(f"Erro: Sem permissão para escrever em '{self.filename}'")
        except scapy.Scapy_Exception as e:
            print(f"Erro na captura: {e}")
        except Exception as e:
            print(f"Erro inesperado: {e}")

    def extract_universal_fields(self, packet):
        # Timestamp com data e hora
        timestamp = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")

        # Definir protocolos
        if scapy.TCP in packet:
            protocol = "TCP"
            sport = packet[scapy.TCP].sport
            dport = packet[scapy.TCP].dport
        elif scapy.UDP in packet:
            protocol = "UDP"
            sport = packet[scapy.UDP].sport
            dport = packet[scapy.UDP].dport
        elif scapy.ICMP in packet:
            protocol = "ICMP"
            sport = None
            dport = None
        else:
            protocol = "OTHER"
            sport = None
            dport = None

        # Adicionar flags TCP se disponível
        tcp_flags = ""
        if scapy.TCP in packet:
            tcp_flags = str(packet[scapy.TCP].flags)

        packet_data = [
            timestamp,
            packet[scapy.Ether].src,
            packet[scapy.Ether].dst,
            packet[scapy.IP].src,
            packet[scapy.IP].dst,
            protocol,
            len(packet),
            sport,
            dport,
            tcp_flags  # Nova coluna
        ]

        return packet_data


def main():
    print("Interfaces disponíveis:")
    for i, iface in enumerate(scapy.get_if_list(), 1):
        print(f"{i}. {iface}")

    interface = input("Interface de captura (padrão enp1s0): ") or "enp1s0"
    fltr = input("Protocolo de captura (ex: udp, tcp, icmp): ") or ""
    filename = (
        input("Arquivo CSV para salvar pacotes (padrão packets.csv): ") or "packets.csv"
    )
    count = input("Quantos pacotes capturar (padrão 10): ")

    # Trata count padrão
    if count == "":
        count = 10

    count = int(count)

    pc = PacketCapture(interface, fltr, filename, count)
    pc.capture_and_save()

    print(f"{pc.iteration} pacotes gravados em '{pc.filename}'.")


if __name__ == "__main__":
    main()