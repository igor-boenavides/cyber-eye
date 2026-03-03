import time
import joblib
import numpy as np
import pandas as pd
from analyzer import Analyzer
from config import settings

# Carrega artefatos
MODEL_PATH = settings.model_path
SCALER_PATH = settings.scaler_path
THRESHOLD_PATH = settings.threshold_path

INTERFACE = settings.interface
WINDOW_TIME = settings.window_time

# Define colunas do vetor de características
FEATURE_COLUMNS = settings.feature_columns

print("[INFO] Carregando artefatos...")
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
with open(THRESHOLD_PATH) as f:
    threshold = float(f.read().strip())

print(f"[OK] Threshold = {threshold:.4f}")

# Inicia monitoramento
analyzer = Analyzer()
columns = settings.feature_columns

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
