import csv
import os

class Analyzer:
    def __init__(self):
        self.packets = []
        self.filename = 'vector.csv'


    def receive_packet(self, packet_data):
        # Recebe os dados do pacote
        self.packets.append(packet_data)
        print(f"Pacote recebido: {packet_data}")


    @staticmethod
    def vector_packet(packet_data):
        # Formatar packet_data
        packet_length = packet_data[6]
        sport = packet_data[7] or 0
        dport = packet_data[8] or 0
        tcp_flags = packet_data[9] or 0


        # Protocolo
        protocol_name = packet_data[5]
        match protocol_name:
            case 'TCP': protocol_num = 1
            case 'UDP': protocol_num = 2
            case 'ICMP': protocol_num = 3
            case _: protocol_num = 0


        # TCP Flags
        tcp_flags_vector = [0, 0, 0, 0]
        if 'S' in tcp_flags: tcp_flags_vector[0] = 1
        if 'A' in tcp_flags: tcp_flags_vector[1] = 1
        if 'F' in tcp_flags: tcp_flags_vector[2] = 1
        if 'R' in tcp_flags: tcp_flags_vector[3] = 1


        # IPs
        src_ip_octets = [int(o) for o in packet_data[3].split('.')]
        dst_ip_octets = [int(o) for o in packet_data[4].split('.')]


        # Compor e retornar vetor
        vector = src_ip_octets + dst_ip_octets + [protocol_num, packet_length, sport, dport] + tcp_flags_vector
        return vector

    def save_file(self, packet_data):
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
                            "src1", "src2", "src3", "src4",
                            "dst1", "dst2", "dst3", "dst4",
                            "protocol_num",
                            "packet_length",
                            "sport",
                            "dport",
                            "flag_S", "flag_A", "flag_F", "flag_R"
                        ]
                    )

                # Gravar no arquivo
                vector = self.vector_packet(packet_data)
                writer.writerow(vector)

        # Levantando excessões
        except PermissionError:
            print(f"Erro: Sem permissão para escrever em '{self.filename}'")
        except Exception as e:
            print(f"Erro inesperado: {e}")