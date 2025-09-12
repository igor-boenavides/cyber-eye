import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
import joblib
import os
from analyzer import Analyzer

# CONSTANTES
analyzer = Analyzer()
VECTOR_CSV = analyzer.filename
MODEL_PATH = 'anomaly_model.pkl'
SCALER_PATH = 'scaler.pkl'
THRESHOLD_PATH = 'threshold.txt'

# PROCENTO PARA THRESHOLD (Ajustar de acordo)
THRESHOLD_PERCENTILE = 97.5 # # exemplo: 97.5% dos pontos do baseline são considerados "normais"


# Carrega o CSV com a captura vetorizada
def load_data(path):
    # Verifica se o arquivo e existe e levanta erro se não
    if not os.path.isfile(path):
        raise FileNotFoundError(f'{path} não encontrado. Gerar o arquivo com a captura vetorizada.')
    # Lê o arquivo .CSV com pandas na variável `df` (dataframe)
    df = pd.read_csv(path)
    return df


# Carrega o arquivo e seleciona somente os campos necessários para a análise
def select_features(df):
    cols = [
        'num_packets', 'total_bytes',
        'unique_src_ips', 'unique_dst_ips',
        'tcp_count', 'udp_count', 'icmp_count'
    ]

    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise ValueError(f'As colunas faltanos no CSV: {missing}')
    x = df[cols].copy()
    return x


# Tratar os dados capturados
def preprocess(x):
    # Trata valores nulos ou 0 (NaNs)
    x = x.fillna(0)

    # Remover valores absurdos (packet_length negativo)
    x = x[(x >= 0).all(axis=1)]

    # Padronizar
    scaler = RobustScaler()
    x_scaled = scaler.fit_transform(x)
    return x_scaled, scaler


# Treinar o modelo IsolationForest
def train_model(x_scaled):
    # Ajustar `contamination` se souber a fração esperada de anomalias no baseline
    clf = IsolationForest(
                n_estimators=200, # Quantas árvores o modelo vai criar, Mais árvores = Mais robusto e mais lento
                max_samples='auto', # Quantos pontos de dados cada árvore vai usar, auto = 256
                contamination='auto', # Estima a fração do dataset que é anomala, auto = ajuste automático com base nos dados
                random_state=42, # Semente aleatória para reproduzir os resultados
                n_jobs=-1 # Diz para usar todos os núcleos da CPU disponíveis.
    )

    # Treina o modelo usando o dataset escalado
    clf.fit(x_scaled)
    return clf


# Diz se é anomalia ou não
def compute_threshold(clf, x_scaled, percentile=THRESHOLD_PERCENTILE):
    # Sistema de pontuação: mais alto = mais "normal"
    scores = clf.decision_function(x_scaled)

    # Definir o threshold
    thr = np.percentile(scores, 100 - percentile)
    return thr, scores


# Salva o modelo treinado
def save_artifacts(clf, scaler, thr):
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    with open(THRESHOLD_PATH, 'w') as f:
        f.write(str(thr))
    print(f'Salvo: {MODEL_PATH}, {SCALER_PATH}, {THRESHOLD_PATH}')


# Imprime o resumo do treinameto do modelo
def quick_report(scores, thr):
    print('Resumo dos scores: ')
    print(f'Min: {np.min(scores):.6f}\n Max: {np.max(scores):.6f}\n Mean: {np.mean(scores):.6f}')
    print(f'Threshold utilizado {thr:.6f}')
    # Salvar como histograma em PNG (matplotlib)?


# Chama as funções
def main():
    df = load_data(VECTOR_CSV)
    x = select_features(df)
    x_scaled, scaler = preprocess(x)
    clf = train_model(x_scaled)
    thr, scores = compute_threshold(clf, x_scaled)
    quick_report(scores, thr)
    save_artifacts(clf, scaler, thr)


if __name__ == '__main__':
    main()