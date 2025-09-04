import os
import csv
from datetime import datetime
import scapy.all as scapy
from analyzer import Analyzer
import threading
import time


class PacketCapture:
    def __init__(self, interface, fltr, filename, duration, analyzer=None):
        self.interface = interface
        self.filter = fltr
        self.filename = filename
        self.capture = []
        self.iteration = 0
        self.duration = duration
        self.analyzer = analyzer
        self.stop_sapture = False


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

                # Função para processar cada pacote
                def packet_handler(packet):
                    if scapy.Ether in packet and scapy.IP in packet:
                        packet_data = self.extract_universal_fields(packet)
                        writer.writerow(packet_data)
                        file.flush()  # Força a escrita imediata no arquivo
                        self.iteration += 1
                        print(f"Pacote {self.iteration} capturado")

                        # Enviar para analyzer
                        if self.analyzer:
                            self.analyzer.receive_packet(packet_data)

                # Timer para parar a captura
                def stop_timer():
                    time.sleep(self.duration)
                    self.stop_capture = True
                    print(f"\nTempo de captura ({self.duration}s) esgotado. Parando...")

                # Inicia o timer em uma thread separada
                timer_thread = threading.Thread(target=stop_timer)
                timer_thread.daemon = True
                timer_thread.start()

                print(f"Iniciando captura por {self.duration} segundos na interface {self.interface}...")
                print("Pressione Ctrl+C para parar manualmente")

                # Define os parâmetros do sniff dos pacotes capturados
                # Com stop_filter para parar quando self.stop_capture for True
                scapy.sniff(
                    iface=self.interface,
                    filter=self.filter,
                    prn=packet_handler,
                    stop_filter=lambda x: self.stop_capture
                )


        # Levantando excessões
        except PermissionError:
            print(f"Erro: Sem permissão para escrever em '{self.filename}'")
        except scapy.Scapy_Exception as e:
            print(f"Erro na captura: {e}")
        except KeyboardInterrupt:
            print(f"\nCaptura interrompida pelo usuário")
        except Exception as e:
            print(f"Erro inesperado: {e}")

    # Extrai os campos universais dos pacotes
    @staticmethod
    def extract_universal_fields(packet):
        # Timestamp com data e hora
        timestamp = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")

        # Definir protocolos
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

    # Input do tempo de captura
    duration_input = input("Duração da captura em segundos (padrão 30): ")

    # Trata duration padrão
    if duration_input == "":
        duration = 30
    else:
        try:
            duration = int(duration_input)
        except ValueError:
            print("Valor inválido para duração. Usando padrão de 30 segundos.")
            duration = 30

    # Criar instância de analyzer
    analyzer = Analyzer()

    pc = PacketCapture(interface, fltr, filename, duration, analyzer)
    pc.capture_and_save()

    print(f"{pc.iteration} pacotes gravados em '{pc.filename}'.")


if __name__ == "__main__":
    main()