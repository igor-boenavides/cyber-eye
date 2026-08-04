# Cyber Eye 🔍

Sistema de Detecção de Intrusão (IDS) baseado em Machine Learning não-supervisionado. O Cyber Eye monitora o tráfego de rede em tempo real, extrai features estatísticas por janelas de captura e utiliza um modelo **Isolation Forest** para identificar comportamentos anômalos.

Desenvolvido como Trabalho de Conclusão de Curso (TCC) em Ciência da Computação.

---

## Como funciona

O sistema opera em três etapas:

1. **Captura** - pacotes de rede são capturados em janelas de tempo fixas usando Scapy
2. **Vetorização** - 15 features estatísticas são extraídas de cada janela
3. **Classificação** - o modelo Isolation Forest atribui um score de anomalia; janelas abaixo do threshold disparam um alerta

---

## Features utilizadas

| Feature | Descrição |
|---|---|
| `num_packets` | Total de pacotes na janela |
| `total_bytes` | Volume total em bytes |
| `unique_src_ips` | IPs de origem únicos |
| `unique_dst_ips` | IPs de destino únicos |
| `tcp_count` | Pacotes TCP |
| `udp_count` | Pacotes UDP |
| `icmp_count` | Pacotes ICMP |
| `packet_rate` | Taxa de pacotes por segundo |
| `byte_rate` | Taxa de bytes por segundo |
| `syn_count` | Pacotes com flag SYN |
| `fin_count` | Pacotes com flag FIN |
| `ack_count` | Pacotes com flag ACK |
| `unique_dst_ports` | Portas de destino únicas |
| `mean_packet_size` | Tamanho médio dos pacotes |
| `std_packet_size` | Desvio padrão do tamanho dos pacotes |

---

## Requisitos

- Python 3.10+
- [Npcap](https://npcap.com/#download) (Windows) ou permissões de captura (Linux)

Instale as dependências:

```bash
pip install scapy scikit-learn pandas numpy matplotlib joblib
```

---

## Estrutura do projeto

```
cyber-eye/
├── alert_system.py      # Monitoramento em tempo real
├── analyzer.py          # Extração de features e vetorização
├── batch_capture.py     # Captura de baseline para retreinamento
├── config.py            # Configurações centralizadas
├── data_handler.py      # Captura e gravação de pacotes brutos
├── evaluate.py          # Geração de métricas e gráficos
├── logger.py            # Registro de eventos em CSV
├── train_model.py       # Treinamento do modelo
├── artifacts/           # Modelo, scaler e threshold (gerados)
├── dataset/             # Dataset CIC-IDS-2017 (não versionado)
└── logs/                # Logs de alertas e gráficos
```

---

## Fluxo de uso

### 1. Configuração inicial

Edite `config.py` e ajuste:

```python
interface: str = "wlo1"        # Interface de rede (Linux) ou nome/GUID (Windows)
use_dataset: bool = True        # True = CIC-IDS-2017 | False = captura local
```

Para descobrir as interfaces disponíveis:

```bash
python test_interface.py
```

### 2. Treinamento do modelo

**Modo dataset (CIC-IDS-2017):**

Baixe o dataset em [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html) e extraia os CSVs em `dataset/MachineLearningCVE/`. Configure `use_dataset: True` no `config.py` e rode:

```bash
python train_model.py
```

**Modo captura local:**

Configure `use_dataset: False` e capture o baseline da sua rede:

```bash
python batch_capture.py
python train_model.py
```

### 3. Monitoramento em tempo real

```bash
python alert_system.py
```

O sistema classifica cada janela de 3 segundos e exibe:
- `✓ Normal | score= 0.0821`
- `🚨 ANOMALIA DETECTADA | score= -0.1923`

Todos os eventos são gravados em `logs/alerts.csv`.

### 4. Análise dos resultados

```bash
python evaluate.py
```

Gera três gráficos em `logs/`:
- `grafico_timeline.png` - score ao longo do tempo
- `grafico_histograma.png` - distribuição dos scores por cenário
- `grafico_features.png`  comparação de features entre cenários

---

## Resultados obtidos

Modelo treinado com 2.27 milhões de registros benignos do CIC-IDS-2017 e testado em ambiente controlado (VM Kali Linux como atacante, host como vítima):

| Cenário de ataque | Taxa de detecção |
|---|---|
| ICMP Flood (hping3) | 100% |
| SYN Flood (hping3) | 100% |
| Port Scan (nmap -sS) | 89% |

---

## Configurações principais

Todos os parâmetros ficam em `config.py`:

| Parâmetro | Padrão | Descrição |
|---|---|---|
| `interface` | `"wlo1"` | Interface de rede monitorada |
| `window_time` | `3` | Duração de cada janela (segundos) |
| `threshold_percentile` | `99.0` | Percentil para definição do threshold |
| `use_dataset` | `False` | Modo de treinamento |
| `num_runs` | `30` | Número de janelas para captura de baseline |
| `capture_duration` | `420` | Duração de cada janela de captura (segundos) |

---

## Dataset

O projeto suporta treinamento com o **CIC-IDS-2017** (Canadian Institute for Cybersecurity). O dataset não está incluído no repositório. Para obtê-lo:

1. Acesse [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)
2. Solicite acesso via formulário
3. Baixe os arquivos `MachineLearningCSV.zip`
4. Extraia em `dataset/MachineLearningCVE/`

---

## Autor

Igor Boenavides - Trabalho de Conclusão de Curso, Ciência da Computação
