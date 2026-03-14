import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

LOG_FILE = Path("logs/alerts.csv")
OUTPUT_DIR = Path("logs")
THRESHOLD = -0.1985

# Paleta de cores
COR_NORMAL    = "#2196F3"
COR_ICMP      = "#9C27B0"
COR_SYN       = "#E91E63"
COR_SCAN      = "#00BCD4"
COR_THRESHOLD = "#FF9800"


def load_log():
    df = pd.read_csv(LOG_FILE, parse_dates=["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def label_scenarios(df):
    """Rotula cada janela com o cenário correspondente baseado no tipo de tráfego."""
    conditions = [
        (df["icmp_count"] > 1000),
        (df["tcp_count"] > 1000),
        (df["num_packets"] > 50) & (df["tcp_count"] < 100) & (df["icmp_count"] < 100),
    ]
    labels = ["ICMP Flood", "SYN Flood", "Port Scan"]
    df["scenario"] = np.select(conditions, labels, default="Normal")
    return df


def plot_scores_timeline(df):
    """Gráfico 1: Score ao longo do tempo com threshold e cenários destacados."""
    fig, ax = plt.subplots(figsize=(14, 5))

    scenario_colors = {
        "ICMP Flood": COR_ICMP,
        "SYN Flood":  COR_SYN,
        "Port Scan":  COR_SCAN,
        "Normal":     None
    }

    # Fundo colorido por cenário
    for _, row in df.iterrows():
        if row["scenario"] != "Normal":
            ax.axvspan(row.name - 0.5, row.name + 0.5,
                       alpha=0.15, color=scenario_colors[row["scenario"]])

    # Pontos coloridos por cenário
    cores = df["scenario"].map({
        "ICMP Flood": COR_ICMP,
        "SYN Flood":  COR_SYN,
        "Port Scan":  COR_SCAN,
        "Normal":     COR_NORMAL
    })

    ax.plot(df.index, df["score"], color="#aaa", linewidth=1, zorder=2)
    ax.scatter(df.index, df["score"], c=cores, s=40, zorder=3)
    ax.axhline(y=THRESHOLD, color=COR_THRESHOLD, linestyle="--",
               linewidth=1.5, label=f"Threshold ({THRESHOLD:.4f})")

    patches = [
        mpatches.Patch(color=COR_NORMAL,    label="Normal"),
        mpatches.Patch(color=COR_ICMP,      label="ICMP Flood"),
        mpatches.Patch(color=COR_SYN,       label="SYN Flood"),
        mpatches.Patch(color=COR_SCAN,      label="Port Scan"),
        mpatches.Patch(color=COR_THRESHOLD, label=f"Threshold ({THRESHOLD:.4f})"),
    ]
    ax.legend(handles=patches, loc="lower right", fontsize=9)

    ax.set_title("Score de Anomalia por Janela de Captura", fontsize=13, fontweight="bold")
    ax.set_xlabel("Janela")
    ax.set_ylabel("Score (Isolation Forest)")
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "grafico_timeline.png", dpi=150)
    plt.close()
    print("[OK] grafico_timeline.png")


def plot_score_histogram(df):
    """Gráfico 2: Histograma de scores separado por cenário."""
    fig, ax = plt.subplots(figsize=(10, 5))

    bins = np.linspace(df["score"].min() - 0.01, df["score"].max() + 0.01, 25)

    grupos = [
        ("Normal",     COR_NORMAL),
        ("ICMP Flood", COR_ICMP),
        ("SYN Flood",  COR_SYN),
        ("Port Scan",  COR_SCAN),
    ]

    for label, cor in grupos:
        sub = df[df["scenario"] == label]["score"]
        if len(sub):
            ax.hist(sub, bins=bins, alpha=0.6, color=cor, label=label)

    ax.axvline(x=THRESHOLD, color=COR_THRESHOLD, linestyle="--",
               linewidth=1.5, label=f"Threshold ({THRESHOLD:.4f})")

    ax.set_title("Distribuição dos Scores por Cenário", fontsize=13, fontweight="bold")
    ax.set_xlabel("Score (Isolation Forest)")
    ax.set_ylabel("Frequência")
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "grafico_histograma.png", dpi=150)
    plt.close()
    print("[OK] grafico_histograma.png")


def plot_feature_comparison(df):
    """Gráfico 3: Comparação de features médias por cenário (escala log)."""
    features   = ["num_packets", "total_bytes", "tcp_count", "udp_count", "icmp_count"]
    labels_pt  = ["Nº Pacotes", "Total Bytes", "TCP", "UDP", "ICMP"]
    cenarios   = ["Normal", "ICMP Flood", "SYN Flood", "Port Scan"]
    cores_bar  = [COR_NORMAL, COR_ICMP, COR_SYN, COR_SCAN]

    medias = []
    for c in cenarios:
        sub = df[df["scenario"] == c]
        medias.append(sub[features].mean().values if len(sub) else np.zeros(len(features)))

    x     = np.arange(len(features))
    width = 0.2
    fig, ax = plt.subplots(figsize=(12, 5))

    for i, (cenario, media, cor) in enumerate(zip(cenarios, medias, cores_bar)):
        ax.bar(x + i * width, media + 1, width, label=cenario, color=cor, alpha=0.8)

    ax.set_yscale("log")
    ax.set_title("Média das Features por Cenário (escala log)", fontsize=13, fontweight="bold")
    ax.set_xlabel("Feature")
    ax.set_ylabel("Valor Médio (log)")
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(labels_pt)
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3, axis="y")

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "grafico_features.png", dpi=150)
    plt.close()
    print("[OK] grafico_features.png")


def print_summary(df):
    print("\n===== RESUMO DOS TESTES =====")
    for cenario in ["Normal", "ICMP Flood", "SYN Flood", "Port Scan"]:
        sub = df[df["scenario"] == cenario]
        if not len(sub):
            continue
        detectados = (sub["score"] < THRESHOLD).sum()
        print(f"\n{cenario} ({len(sub)} janelas):")
        print(f"  Score médio : {sub['score'].mean():.4f}")
        print(f"  Score mín   : {sub['score'].min():.4f}")
        print(f"  Detectados  : {detectados}/{len(sub)} ({100*detectados/len(sub):.0f}%)")
    print(f"\nThreshold: {THRESHOLD:.4f}")
    print("=============================\n")


def main():
    df = load_log()
    df = label_scenarios(df)
    print_summary(df)
    plot_scores_timeline(df)
    plot_score_histogram(df)
    plot_feature_comparison(df)
    print("[INFO] Gráficos salvos em logs/")


if __name__ == "__main__":
    main()