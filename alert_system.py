import time
import joblib
import numpy as np
import pandas as pd
from analyzer import Analyzer


# Carrega artefatos
MODEL_PATH = "anomaly_model.pkl"
SCALER_PATH = "scaler.pkl"
THRESHOLD_PATH = "threshold.txt"

INTERFACE = "Ethernet"
WINDOW_TIME = 3

# Define colunas do vetor de características
FEATURE_COLUMNS = [
    "num_packets",
    "total_bytes",
    "unique_src_ips",
    "unique_dst_ips",
    "tcp_count",
    "udp_count",
    "icmp_count"
]

print("[INFO] Carregando artefatos...")
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
with open(THRESHOLD_PATH) as f:
    threshold = float(f.read().strip())

print(f"[OK] Threshold = {threshold:.4f}")

# Inicia monitoramento
analyzer = Analyzer()
columns = [
    "num_packets",
    "total_bytes",
    "unique_src_ips",
    "unique_dst_ips",
    "tcp_count",
    "udp_count",
    "icmp_count"
]

print("[INFO] Monitoramento iniciado\n")

# Loop principal
while True:
    try:
        packets = analyzer.capture_window(
            time_window=WINDOW_TIME,
            interface=INTERFACE
        )

        vector = analyzer.compute_vector(packets)
        if vector is None:
            print("[INFO] Nenhum pacote capturado")
            continue

        df = pd.DataFrame([vector], columns=columns)
        X_scaled = scaler.transform(df)
        score = model.decision_function(X_scaled)[0]

        if score < threshold:
            print(f"🚨 ANOMALIA DETECTADA | score={score:.4f}")
        else:
            print(f"✓ Normal | score={score:.4f}")

    except KeyboardInterrupt:
        print("\n[INFO] Encerrado pelo usuário")
        break

    except Exception as e:
        print(f"[ERRO] {e}")

    time.sleep(1)
