import csv
import os
from datetime import datetime
from pathlib import Path


# Diretórios para logs
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "alerts.csv"


# Cabeçalho do CSV de logs
HEADER = ["timestamp", "classification", "score", "num_packets", "total_bytes",
          "unique_src_ips", "unique_dst_ips", "tcp_count", "udp_count", "icmp_count"]


# Garante ou cria arquivo de log com o cabeçalho
def _ensure_log_file():
    LOG_DIR.mkdir(exist_ok=True)
    if not LOG_FILE.exists():
        with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(HEADER)


# Registra evento no arquivo de log
def log_event(score: float, threshold: float, vector: list):
    _ensure_log_file()

    classification = "ANOMALIA" if score < threshold else "NORMAL"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    row = [timestamp, classification, f"{score:.6f}"] + vector

    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(row)