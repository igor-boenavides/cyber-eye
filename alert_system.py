import time
import joblib
import numpy as np
import pandas as pd

from analyzer import Analyzer
from config import settings
from logger import log_event


INTERFACE = settings.interface
WINDOW_TIME = settings.window_time

# Define colunas do vetor de características
FEATURE_COLUMNS = list(settings.feature_columns)

print("[INFO] Carregando artefatos...")
model = joblib.load(settings.model_path)
scaler = joblib.load(settings.scaler_path)
with open(settings.threshold_path) as f:
    threshold = float(f.read().strip())

print(f"[OK] Threshold = {threshold:.4f}")

# Inicia monitoramento
analyzer = Analyzer()

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

        df = pd.DataFrame([vector], columns=FEATURE_COLUMNS)
        X_scaled = scaler.transform(df)
        score = model.decision_function(X_scaled)[0]
        log_event(score, threshold, vector)  # ← adiciona essa linha

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
