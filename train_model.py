# Módulo de análise de dados
import pandas as pd
# SkLearn = Módulo de Machine Learning
# StandardScaler = Função de Padronização
from sklearn.preprocessing import StandardScaler
# IsolationForest = Modelo de Machile Learning
from sklearn.ensemble import IsolationForest
# Módulo para salvar o modelo de ML treinado
import joblib

# Carregar só uma parte no começo (dataset é grande!)
df = pd.read_csv("cic.csv", nrows=50000)

print(df.head())
print(df.columns)
print(df['Label'].value_counts())

# Treino com tráfego benigno (normal/do bem)
df_benign = df[df['Label'] == "BENIGN"]

# Limitar quais colunas serão utilizadas
features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Flow Bytes/s",
    "Flow Packets/s"
]

X = df_benign[features].fillna(0)  # tira NaN

# Normalizar a escala/Padronizar tudo
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Treinar o modelo de Machine Learn (Isolation Forest)
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
model.fit(X_scaled)

# Teste com pacotes de ataque
df_attack = df[df['Label'] != "BENIGN"].sample(2000, random_state=42)

X_attack = scaler.transform(df_attack[features].fillna(0))

preds = model.predict(X_attack)  # -1 = anomalia, 1 = normal

print((preds == -1).mean())  # porcentagem de ataques detectados

# Salvar modelo de ML (descomentar depois de treinar)
# joblib.dump((model, scaler, features), "isolation_forest.pkl")