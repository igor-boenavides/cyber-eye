# `os` e `csv` para manipulação/criação de arquivos
import os
import csv
# `datetime` fazer timestamp e formatar
from datetime import datetime
# `scapy.all` sniffing de rede
import scapy.all as scapy
# para conexão com o analisador de pacotes
from analyzer import Analyzer
# `time` para fazer a captura em um intervalo de tempo definido
import time

"""
Criação da classe da captura de pacotes
"""
class PacketCapture:
    """
    Méto|do de inicialização
    """
    def __init__(self, interface, fltr, filename, duration, analyzer=None):
        self.interface = interface
        self.filter = fltr
        self.filename = filename
        self.iteration = 0
        self.duration = duration
        self.analyzer = analyzer


    """
    Realiza a captura e grava os dados dos pacotes capturados no arquivo específicado 
    """
    def capture_and_save(self):
        print(f'Capturando por {self.duration}s na inteface {self.interface}...')

        # sniffer assíncrono: você controla quando parar
        sniffer = scapy.AsyncSniffer(
            iface=self.interface,
            filter=self.filter,
            prn=self._packet_handler,
            store=False
        )
        sniffer.start()
        time.sleep(self.duration)  # espera a janela terminar
        sniffer.stop()  # para imediatamente

        # fecha a janela (gera 1 linha no vector.csv)
        if self.analyzer:
            self.analyzer.close_window()

        print("Captura finalizada.")

    """
    Grava os pacotes e manda para o analizador
    """
    def _packet_handler(self, packet):
        if scapy.Ether in packet and scapy.IP in packet:
            packet_data = self.extract_universal_fields(packet)

            # grava no CSV bruto
            file_exists = os.path.isfile(self.filename)
            with open(self.filename, "a", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                if not file_exists:  # primeira vez → cabeçalho
                    writer.writerow([
                        "timestamp", "src_mac", "dst_mac", "src_ip", "dst_ip",
                        "protocol_name", "packet_len", "sport", "dport", "tcp_flags"
                    ])
                writer.writerow(packet_data)

            self.iteration += 1
            print(f"Pacote {self.iteration} capturado")

            # envia pro analyzer (ele só acumula)
            if self.analyzer:
                self.analyzer.receive_packet(packet_data)

    """
    Extrai os campos que aparecem em todos os pacotes
    """
    @staticmethod
    def extract_universal_fields(packet):
        timestamp = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")

        if scapy.TCP in packet:
            protocol = "TCP"
            sport = packet[scapy.TCP].sport
            dport = packet[scapy.TCP].dport
            tcp_flags = str(packet[scapy.TCP].flags)
        elif scapy.UDP in packet:
            protocol = "UDP"
            sport = packet[scapy.UDP].sport
            dport = packet[scapy.UDP].dport
            tcp_flags = ""
        elif scapy.ICMP in packet:
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

"""
Chama os métodos
"""
def main():
    print("Interfaces disponíveis:")
    for i, iface in enumerate(scapy.get_if_list(), 1):
        print(f"{i}. {iface}")

    interface = input("Interface de captura (padrão enp1s0): ") or "enp1s0"
    fltr = input("Protocolo de captura (ex: udp, tcp, icmp): ") or ""
    filename = input("Arquivo CSV para salvar pacotes (padrão packets.csv): ") or "packets.csv"

    duration_input = input("Duração da captura em segundos (padrão 30): ")
    try:
        duration = int(duration_input) if duration_input else 30
    except ValueError:
        print("Valor inválido para duração. Usando padrão de 30 segundos.")
        duration = 30

    analyzer = Analyzer()
    pc = PacketCapture(interface, fltr, filename, duration, analyzer)
    pc.capture_and_save()

    print(f"{pc.iteration} pacotes gravados em '{pc.filename}'.")


if __name__ == "__main__":
    main()
