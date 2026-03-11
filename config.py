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
    interface: str = "Ethernet"
    window_time: int = 3
    capture_duration: int = 240
    capture_filter: str = ""
    num_runs: int = 100

    vector_csv: Path = Path("vector.csv")
    model_path: Path = Path("anomaly_model.pkl")
    scaler_path: Path = Path("scaler.pkl")
    threshold_path: Path = Path("threshold.txt")
    feature_columns: Tuple[str, ...] = field(default=FEATURE_COLUMNS)


settings = Settings()
