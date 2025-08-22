import os
import csv
from datetime import datetime
import scapy.all as scapy


class PacketCapture:
    def __init__(self, interface, fltr, filename, count):
        self.interface = interface
        self.filter = fltr
        self.filename = filename
        self.capture = []
        self.iteration = 0
        self.count = count

    def capture_and_save(self):
        file_exists = os.path.isfile(self.filename)

        # Abrir o CSV para acrescentar dados
        with open(self.filename, 'a') as file:
            writer = csv.writer(file)

            # Escrever cabeçalho apenas caso o arquivo seja novo
            if not file_exists:
                writer.writerow(['src_ip', 'dst_ip', 'len', 'sport_udp', 'dport_udp', 'timestamp'])

            # Captura de pacotes
            capture = scapy.sniff(iface=self.interface, count=self.count, filter=self.filter)


            for packet in capture:
                if scapy.IP in packet:
                    timestamp = datetime.fromtimestamp(packet.time).strftime('%H:%M:%S')

                    self.iteration += 1

                    # Verifica se é UDP antes de pegar portas
                    if scapy.UDP in packet:
                        sport = packet[scapy.UDP].sport
                        dport = packet[scapy.UDP].dport
                    else:
                        sport = ''
                        dport = ''

                    packet_data = [
                        packet[scapy.IP].src,
                        packet[scapy.IP].dst,
                        len(packet),
                        sport,
                        dport,
                        timestamp
                    ]


                    writer.writerow(packet_data)


def main():
    interface = input('Interface de captura (padrão enp1s0): ') or 'enp1s0'
    fltr = input('Protocolo de captura (ex: udp, tcp, icmp): ') or ''
    filename = input('Arquivo CSV para salvar pacotes (padrão packets.csv): ') or 'packets.csv'
    count = int(input('Quantos pacotes capturar (padrão 10): ' or 10))

    pc = PacketCapture(interface, fltr, filename, count)
    pc.capture_and_save()


    print(f"{pc.iteration} pacotes gravados em '{pc.filename}'.")


if __name__ == '__main__':
    main()
