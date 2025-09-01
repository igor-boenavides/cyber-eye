import os
import csv
from datetime import datetime
import scapy.all as scapy
from analyzer import Analyzer

class PacketCapture:
    def __init__(self, interface, fltr, filename, count, analyzer=None):
        self.interface = interface
        self.filter = fltr
        self.filename = filename
        self.capture = []
        self.iteration = 0
        self.count = count
        self.analyzer = analyzer

    def capture_and_save(self):
        # Verifica se o arquivo existe
        file_exists = os.path.isfile(self.filename)

        try:
            # Abre/cria o arquivo
            with open(self.filename, "a", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)

                # Se o arquivo não existe, são adicionados os cabeçalhos apropriados
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

                # Define os parâmetros do sniff dos pacotes capturados
                capture = scapy.sniff(
                    iface=self.interface, count=self.count, filter=self.filter
                )

                # Análise individual dos pacotes
                for packet in capture:
                    if scapy.Ether in packet and scapy.IP in packet:
                        packet_data = self.extract_universal_fields(packet)
                        writer.writerow(packet_data)
                        self.iteration += 1

                        # Enviar para analyzer
                        from analyzer import Analyzer
                        analyzer = Analyzer()

                        analyzer.receive_packet(packet_data)


        # Levantando excessões
        except PermissionError:
            print(f"Erro: Sem permissão para escrever em '{self.filename}'")
        except scapy.Scapy_Exception as e:
            print(f"Erro na captura: {e}")
        except Exception as e:
            print(f"Erro inesperado: {e}")

    # Extrai os campos universais dos pacotes
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

        # Preenche as linhas dos pacotes
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
            tcp_flags
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

    # Criar instância de analyzer
    from analyzer import Analyzer
    analyzer = Analyzer()

    pc = PacketCapture(interface, fltr, filename, count, analyzer)
    pc.capture_and_save()

    print(f"{pc.iteration} pacotes gravados em '{pc.filename}'.")



if __name__ == "__main__":
    main()