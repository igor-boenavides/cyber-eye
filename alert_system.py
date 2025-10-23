# 1. Importar bibliotecas necessárias
#    - pandas, numpy, joblib, e o Analyzer (para gerar vetores)
#    - talvez time, caso queira rodar em loop contínuo

# 2. Definir caminhos dos arquivos de artefatos
#    MODEL_PATH = "anomaly_model.pkl"
#    SCALER_PATH = "scaler.pkl"
#    THRESHOLD_PATH = "threshold.txt"

# 3. Carregar o modelo, scaler e threshold
#    - model = joblib.load(MODEL_PATH)
#    - scaler = joblib.load(SCALER_PATH)
#    - threshold = ler o valor do arquivo THRESHOLD_PATH

# 4. Iniciar o objeto Analyzer para capturar pacotes
#    - analyzer = Analyzer()

# 5. Loop principal de monitoramento
#    enquanto o sistema estiver ativo:
#        a) Capturar uma janela de pacotes (por tempo ou quantidade)
#        b) Gerar o vetor correspondente (igual ao que vai pro vector.csv)
#        c) Converter o vetor para DataFrame com as mesmas colunas do treino

# 6. Pré-processar o vetor
#    - Garantir que todas as colunas estão presentes e na mesma ordem
#    - Aplicar o scaler com scaler.transform(vetor)

# 7. Rodar o modelo de detecção
#    - score = model.decision_function(vetor_escalado)

# 8. Comparar o score com o threshold
#    se score < threshold:
#        # Anomalia detectada
#        gerar alerta (exibir mensagem ou gravar em log)
#    senão:
#        # Normal
#        opcionalmente registrar “tudo ok”

# 9. Esperar alguns segundos antes de repetir (se for contínuo)
#    - ex: time.sleep(3)

# 10. (Opcional) permitir encerrar com Ctrl+C
#     - tratar KeyboardInterrupt e fechar o loop com elegância
