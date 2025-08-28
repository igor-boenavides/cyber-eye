# analyzer.py
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

class Analyzer:
    def __init__(self):
        # Inicializa o modelo (aqui ainda sem treino real)
        self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.is_trained = False

    def preprocess(self, packet_data):
        """
        Transforma os dados do pacote em um vetor numérico.
        packet_data é uma lista que vem do data_handler.extract_universal_fields()
        """
        try:
            timestamp, src_mac, dst_mac, src_ip, dst_ip, protocol, length, sport, dport, flags = packet_data

            # Converter protocolo para número
            protocol_map = {"TCP": 1, "UDP": 2, "ICMP": 3, "OTHER": 0}
            protocol_num = protocol_map.get(protocol, 0)

            # Converter portas None → -1
            sport = int(sport) if sport else -1
            dport = int(dport) if dport else -1

            # Converter flags em número (placeholder simples)
            flags_num = len(flags) if flags else 0

            features = [
                protocol_num,
                int(length),
                sport,
                dport,
                flags_num,
            ]

            return np.array(features).reshape(1, -1)

        except Exception as e:
            print(f"Erro no preprocessamento: {e}")
            return None

    def train(self, data):
        """
        Treina o modelo com dados normais.
        data deve ser um DataFrame ou array já processado.
        """
        self.model.fit(data)
        self.is_trained = True

    def predict(self, packet_data):
        """
        Faz a predição: -1 = anomalia, 1 = normal
        """
        features = self.preprocess(packet_data)
        if features is not None and self.is_trained:
            return self.model.predict(features)[0]
        return 1  # se não está treinado, assume normal