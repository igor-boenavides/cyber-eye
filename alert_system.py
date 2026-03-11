import logging
import time

import joblib
import pandas as pd

from analyzer import Analyzer
from config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def main() -> None:
    logging.info("Carregando artefatos...")
    model = joblib.load(settings.model_path)
    scaler = joblib.load(settings.scaler_path)
    with open(settings.threshold_path, encoding="utf-8") as f:
        threshold = float(f.read().strip())

    logging.info("Threshold = %.4f", threshold)

    analyzer = Analyzer()
    columns = list(settings.feature_columns)

    logging.info("Monitoramento iniciado")

    while True:
        try:
            packets = analyzer.capture_window(
                time_window=settings.window_time,
                interface=settings.interface,
                fltr=settings.capture_filter,
            )

            vector = analyzer.compute_vector(packets)
            if vector is None:
                logging.info("Nenhum pacote capturado")
                continue

            df = pd.DataFrame([vector], columns=columns)
            x_scaled = scaler.transform(df)
            score = model.decision_function(x_scaled)[0]

            if score < threshold:
                logging.warning("ANOMALIA DETECTADA | score=%.4f", score)
            else:
                logging.info("Normal | score=%.4f", score)

        except KeyboardInterrupt:
            logging.info("Encerrado pelo usuário")
            break
        except Exception as exc:
            logging.exception("Erro no monitoramento: %s", exc)

        time.sleep(1)


if __name__ == "__main__":
    main()
