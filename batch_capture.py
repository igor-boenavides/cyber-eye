import logging

from analyzer import Analyzer
from config import settings

# parâmetros fixos
INTERFACE = settings.interface
FILTER = settings.capture_filter
FILENAME = "packets.csv"
DURATION = settings.capture_duration  # segundos por janela
NUM_RUNS = settings.num_runs

    logging.info("Capturas finalizadas")


if __name__ == "__main__":
    main()
