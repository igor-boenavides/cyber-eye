# Centralizador de parâmetros operacionais

from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
    interface: str = "Ethernet"
    window_time: int = 3
    capture_duration: int = 240
    capture_filter: str = ""
    num_runs: int = 100

    feature_columns = [
    "num_packets",
    "total_bytes",
    "unique_src_ips",
    "unique_dst_ips",
    "tcp_count",
    "udp_count",
    "icmp_count"
    ]

    model_path: str = r"artifacts\anomaly_model.pkl"
    scaler_path: str = r"artifacts\scaler.pkl"
    threshold_path: str = r"artifacts\threshold.txt"

settings = Settings()
