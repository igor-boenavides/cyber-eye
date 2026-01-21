# 🔒 CYBER EYE

Sistema de Detecção de Intrusão com Inteligência Artificial Integrada

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## 📋 Sobre o Projeto

Cyber Eye é um Sistema de Detecção de Intrusão (IDS) que utiliza Machine Learning para identificar anomalias em tráfego de rede em tempo real. Desenvolvido como Trabalho de Conclusão de Curso.

### Funcionalidades

- 🔍 Captura de pacotes em tempo real
- 🤖 Detecção de anomalias usando Isolation Forest
- 📊 Análise estatística de tráfego de rede
- 🚨 Sistema de alertas para atividades suspeitas
- 📈 Geração de vetores de características

## 🏗️ Arquitetura

┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   Captura   │───>│   Análise    │───>│   Alertas   │
│  (Scapy)    │    │ (ML Model)   │    │  (Logging)  │
└─────────────┘    └──────────────┘    └─────────────┘

## 🚀 Instalação

### Pré-requisitos

- Python 3.8+
- Privilégios de root/sudo (para captura de pacotes)
- Sistema Linux (recomendado) ou Windows com WinPcap/Npcap

### Passo a Passo

1. Clone o repositório:
```bash
git clone https://github.com/igor-boenavides/cyber-eye.git
cd cyber-eye
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

3. Configure as permissões (Linux):
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

## 💻 Uso

### 1. Treinar o Modelo
```bash
python train_model.py
```

### 2. Capturar Tráfego de Rede
```bash
sudo python batch_capture.py --interface eth0 --duration 60
```

### 3. Sistema de Alertas em Tempo Real
```bash
sudo python alert_system.py --interface eth0
```

### 4. Análise de Dados
```bash
python data_handler.py
```

## 📊 Métricas do Modelo

- **Algoritmo**: Isolation Forest
- **Contamination**: 0.05 (5% de anomalias esperadas)
- **Threshold**: Calculado automaticamente
- **Performance**: [A ser atualizado após testes]

## 📁 Estrutura do Projeto

CyberEye
│   .gitignore
│   alert_system.py
│   analyzer.py
│   anomaly_model.pkl
│   batch_capture.py
│   data_handler.py
│   README.md
│   scaler.pkl
│   test_interface.py
│   threshold.txt
│   train_model.py
│   
├───.idea
│   │   .gitignore
│   │   misc.xml
│   │   modules.xml
│   │   TCC - CyberEye.iml
│   │   vcs.xml
│   │   
│   └───inspectionProfiles
│           profiles_settings.xml
│           Project_Default.xml
│
└───__pycache__
        analyzer.cpython-312.pyc
        data_handler.cpython-312.pyc

## 🔧 Configuração

Edite `config/config.yaml`:
```yaml
network:
  interface: "eth0"
  timeout: 3
  packet_count: 100

model:
  contamination: 0.05
  n_estimators: 100
  random_state: 42

alerts:
  log_file: "logs/alerts.log"
  threshold_file: "models/threshold.txt"
```

## 🧪 Testes
```bash
# Executar todos os testes
pytest tests/

# Executar com cobertura
pytest --cov=src tests/
```

## 📝 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## 👤 Autor

**Igor Boenavides**

- GitHub: [@igor-boenavides](https://github.com/igor-boenavides)

## 🙏 Agradecimentos

- Orientador: [Nome do Orientador]
- Instituição: [Nome da Universidade]