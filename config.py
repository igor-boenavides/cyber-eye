from dataclasses import dataclass, field
from pathlib import Path
from typing import Tuple

FEATURE_COLUMNS: Tuple[str, ...] = (
    "num_packets",
    "total_bytes",
    "unique_src_ips",
    "unique_dst_ips",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "packet_rate",
    "byte_rate",
    "syn_count",
    "fin_count",
    "ack_count",
    "unique_dst_ports",
    "mean_packet_size",
    "std_packet_size",
)

@dataclass(frozen=True)
class Settings:
    # Captura
    interface: str = "\\Device\\NPF_{D62F6733-6477-44B8-8154-2317C032EE56}"
    window_time: int = 3
    capture_duration: int = 60
    capture_filter: str = ""
    num_runs: int = 30
    capture_filename: str = "packets.csv"

    # Modelo
    threshold_percentile: float = 97.5

    # Artefatos
    vector_csv: Path = Path("artifacts/vector.csv")
    model_path: Path = Path("artifacts/anomaly_model.pkl")
    scaler_path: Path = Path("artifacts/scaler.pkl")
    threshold_path: Path = Path("artifacts/threshold.txt")

    # Features
    feature_columns: Tuple[str, ...] = field(default_factory=lambda: FEATURE_COLUMNS)

    # Logs
    log_dir: Path = Path("logs")
    log_file: Path = Path("logs/alerts.csv")

    # Dataset
    dataset_dir: Path = Path("dataset/MachineLearningCVE")
    use_dataset: bool = True

settings = Settings()