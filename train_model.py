import logging
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from analyzer import Analyzer
from config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# CONSTANTES
analyzer = Analyzer()
VECTOR_CSV = str(settings.vector_csv)
MODEL_PATH = settings.model_path
SCALER_PATH = settings.scaler_path
THRESHOLD_PATH = settings.threshold_path
FEATURE_COLUMNS = list(settings.feature_columns)

# PROCENTO PARA THRESHOLD (Ajustar de acordo)
THRESHOLD_PERCENTILE = 97.5


# Carrega o CSV com a captura vetorizada
def load_data(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"{path} não encontrado. Gerar o arquivo com a captura vetorizada.")
    return pd.read_csv(path)


# Carrega o arquivo e seleciona somente os campos necessários para a análise
def select_features(df):
    missing = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"As colunas faltantes no CSV: {missing}")
    return df[FEATURE_COLUMNS].copy()


# Tratar os dados capturados
def preprocess(x):
    x = x.fillna(0)
    x = x[(x >= 0).all(axis=1)]

    scaler = RobustScaler()
    x_scaled = scaler.fit_transform(x)
    return x_scaled, scaler


# Treinar o modelo IsolationForest
def train_model(x_scaled):
    clf = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(x_scaled)
    return clf


# Diz se é anomalia ou não
def compute_threshold(clf, x_scaled, percentile=THRESHOLD_PERCENTILE):
    scores = clf.decision_function(x_scaled)
    thr = np.percentile(scores, 100 - percentile)
    return thr, scores


# Salva o modelo treinado
def save_artifacts(clf, scaler, thr):
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    with open(THRESHOLD_PATH, "w", encoding="utf-8") as f:
        f.write(str(thr))
    logging.info("Salvo: %s, %s, %s", MODEL_PATH, SCALER_PATH, THRESHOLD_PATH)


# Imprime o resumo do treinameto do modelo
def quick_report(scores, thr):
    logging.info("Resumo dos scores:")
    logging.info("Min: %.6f | Max: %.6f | Mean: %.6f", np.min(scores), np.max(scores), np.mean(scores))
    logging.info("Threshold utilizado %.6f", thr)


# Chama as funções
def main():
    df = load_data(VECTOR_CSV)
    x = select_features(df)
    x_scaled, scaler = preprocess(x)
    clf = train_model(x_scaled)
    thr, scores = compute_threshold(clf, x_scaled)
    quick_report(scores, thr)
    save_artifacts(clf, scaler, thr)


if __name__ == "__main__":
    main()
