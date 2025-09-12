import csv
import os


class Analyzer:
    def __init__(self):
        self.packets = []
        self.filename = 'vector.csv'

    def receive_packet(self, packet_data):
        # Recebe os dados do pacote
        self.packets.append(packet_data)


    def close_window(self):
        # Métricas de janela
        if not self.packets:
            return

        num_packets = len(self.packets) # Quantidade de pacotes capturados
        total_bytes = sum(int(p[6]) for p in self.packets) # Tamanho total dos pacotes em bytes
        unique_src_ips = len(set(p[3] for p in self.packets)) # Quantidade de IPs de origem
        unique_dst_ips = len(set(p[4] for p in self.packets)) # Quantidade de IPs de destino

        # Contagem de protocolos
        tcp_count = sum(1 for p in self.packets if p[5] == 'TCP')
        udp_count = sum(1 for p in self.packets if p[5] == 'UDP')
        icmp_count = sum(1 for p in self.packets if p[5] == 'ICMP')

        # Vetor final da janela de captura
        vector = [
            num_packets,
            total_bytes,
            unique_src_ips, unique_dst_ips,
            tcp_count, udp_count, icmp_count
        ]

        # Gravar no CSV
        file_exists = os.path.isfile(self.filename)

        with open(self.filename, "a", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)

            # Se o arquivo não existe, são adicionados os cabeçalhos apropriados
            if not file_exists:
                writer.writerow([
                        "num_packets",
                        "total_bytes",
                        "unique_src_ips", "unique_dst_ips",
                        "tcp_count", "udp_count", "icmp_count"
                    ])
            writer.writerow(vector)

            # Limpa pacotes para próxima janela de captura
            self.packets = []