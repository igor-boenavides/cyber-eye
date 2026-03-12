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
)

@dataclass(frozen=True)
class Settings:
    # Captura
    interface: str = "Ethernet"
    window_time: int = 3
    capture_duration: int = 240
    capture_filter: str = ""
    num_runs: int = 100
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

settings = Settings()