from samba.dcerpc.smbXsrv import tconB


class Analyzer:
    def __init__(self):
        self.packets = []


    def receive_packet(self, packet_data):
        """Recebe os dados do pacote"""
        self.packets.append(packet_data)
        print(f"Pacote recebido: {packet_data}")


    def vector_packet(self, packet_data):


        # Formatar packet_data
        packet_length = packet_data[6]
        sport = packet_data[7]
        dport = packet_data[8]
        tcp_flags = packet_data[9]


        # Protocolo
        protocol_name = packet_data[5]
        if protocol_name == 'TCP':
            protocol_num = 1
        elif protocol_name == 'UDP':
            protocol_num = 2
        elif protocol_name == 'ICMP':
            protocol_num = 3
        else:
            protocol_num = 0


        # TCP Flags
        tcp_flags_vector = [0, 0, 0, 0]

        if 'S' in tcp_flags:
            tcp_flags_vector[0] = 1
        if 'A' in tcp_flags:
            tcp_flags_vector[1] = 1
        if 'F' in tcp_flags:
            tcp_flags_vector[2] = 1
        if 'R' in tcp_flags:
            tcp_flags_vector[3] = 1


        # IP de origem
        src_ip = packet_data[3]
        src_ip_octets = [int(octet) for octet in src_ip.split('.')]

        # IP de destino
        dst_ip = packet_data[4]
        dst_ip_octets = [int(octet) for octet in dst_ip.split('.')]

        vector = src_ip_octets + dst_ip_octets + [protocol_num, packet_length, sport, dport] + tcp_flags_vector