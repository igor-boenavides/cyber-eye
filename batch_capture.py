import logging

from analyzer import Analyzer
from config import settings
from data_handler import PacketCapture

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def main() -> None:
    analyzer = Analyzer()

    for run in range(settings.num_runs):
        logging.info("Execução %s/%s", run + 1, settings.num_runs)
        pc = PacketCapture(
            settings.interface,
            settings.capture_filter,
            "packets.csv",
            settings.capture_duration,
            analyzer,
        )
        pc.capture_and_save()

    logging.info("Capturas finalizadas")


if __name__ == "__main__":
    main()
