import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
import joblib
import os

from analyzer import Analyzer
from config import settings

# CONSTANTES
analyzer = Analyzer()
VECTOR_CSV = settings.vector_csv
MODEL_PATH = settings.model_path
SCALER_PATH = settings.scaler_path
THRESHOLD_PATH = settings.threshold_path

# PROCENTO PARA THRESHOLD (Ajustar de acordo)
THRESHOLD_PERCENTILE = settings.threshold_percentile # # exemplo: 97.5% dos pontos do baseline são considerados "normais"


def load_data(path):
    """
    Este script é responsável por treinar o modelo de detecção de anomalias usando o dataset ou os dados capturados. Ele inclui as seguintes etapas:
    1. Carregar os dados do arquivo CSV (se use_dataset for False) ou do dataset
    2. Selecionar as features relevantes para o modelo
    3. Pré-processar os dados (tratar valores nulos, remover outliers, padronizar)
    4. Treinar o modelo IsolationForest
    5. Calcular o threshold para classificar anomalias
    6. Salvar os artefatos do modelo (modelo treinado, scaler e threshold)
    7. Imprimir um resumo dos scores do modelo e do threshold utilizado
    Essas etapas são essenciais para garantir que o modelo de detecção de anomalias seja treinado com dados limpos e padronizados, o que pode melhorar a performance do modelo e a precisão na detecção de anomalias.
    """
    if not settings.use_dataset:
        # Lê o vector.csv da captura
        if not os.path.exists(path):
            raise FileNotFoundError(f'{path} não encontrado.')
        return pd.read_csv(path)

    # Lê o dataset
    dataset_dir = settings.dataset_dir
    if not dataset_dir.exists():
        raise FileNotFoundError(f'{dataset_dir} não encontrado.')   
    
    arquivos = list(dataset_dir.glob('*.csv'))
    if not arquivos:
        raise FileNotFoundError(f'Nenhum arquivo CSV encontrado em {dataset_dir}.')

    print(f'[INFO] Carregando {len(arquivos)} arquivos do dataset...')
    frames = []
    for arq in arquivos:
        print(f'  ->{arq.name}')
        df = pd.read_csv(arq, low_memory=False)
        df.columns = df.columns.str.strip()  # Remove espaços extras dos nomes das colunas
        frames.append(df)

    df = pd.concat(frames, ignore_index=True)
    print(f'[INFO] Total de registros: {len(df)}')
    return df


def map_dataset_features(df):
    """
    Mapeia as colunas do dataset para as features esperadas pelo modelo. Ele verifica se todas as colunas necessárias estão presentes no DataFrame e, em seguida, seleciona apenas as colunas relevantes para o modelo. Se alguma coluna estiver faltando, a função levanta um erro indicando quais colunas estão ausentes. Essa etapa é crucial para garantir que o modelo seja treinado com os dados corretos e que as features estejam alinhadas com o que o modelo espera, o que pode melhorar a performance do modelo na detecção de anomalias.
    As features selecionadas são definidas na configuração (config.py) e incluem métricas como número de pacotes, total de bytes, contagem de protocolos, taxas de pacotes e bytes, entre outras. Essas features são essenciais para o modelo de detecção de anomalias, pois fornecem informações sobre o comportamento do tráfego de rede, permitindo que o modelo identifique padrões normais e anômalos.
    """
    # Filtra apenas os registros benignos para o baseline
    df = df[df['Label'] == 'BENIGN'].copy()  # Filtra apenas os registros benignos para o baseline
    print(f'[INFO] Registros BENIGN: {len(df)}')

    # Mapeia colunas do dataset para as features esperadas pelo modelo
    df['num_packets']      = df['Total Fwd Packets'] + df['Total Backward Packets']
    df['total_bytes']      = df['Total Length of Fwd Packets'] + df['Total Length of Bwd Packets']
    df['unique_src_ips']   = 1  # não disponível no dataset, proxy conservador
    df['unique_dst_ips']   = 1  # não disponível no dataset, proxy conservador
    df['tcp_count']        = 0  # não disponível no dataset
    df['udp_count']        = 0  # não disponível no dataset
    df['icmp_count']       = 0  # não disponível no dataset
    df['packet_rate']      = df['Flow Packets/s']
    df['byte_rate']        = df['Flow Bytes/s']
    df['syn_count']        = df['SYN Flag Count']
    df['fin_count']        = df['FIN Flag Count']
    df['ack_count']        = df['ACK Flag Count']
    df['unique_dst_ports'] = df['Destination Port']
    df['mean_packet_size'] = df['Packet Length Mean']
    df['std_packet_size']  = df['Packet Length Std']

    return df


def select_features(df):
    """
    Seleciona as features relevantes para o modelo. Verifica se todas as colunas necessárias estão presentes no DataFrame.
    Se alguma coluna estiver faltando, levanta um erro indicando quais colunas estão ausentes. Retorna um DataFrame contendo apenas as colunas selecionadas.
    As features selecionadas são definidas na configuração (config.py) e incluem métricas como número de pacotes, total de bytes, contagem de protocolos, taxas de pacotes e bytes, entre outras.
    Essas features são essenciais para o modelo de detecção de anomalias, pois fornecem informações sobre o comportamento do tráfego de rede, permitindo que o modelo identifique padrões normais e anômalos.
    """
    cols = list(settings.feature_columns)

    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise ValueError(f'As colunas faltanos no CSV: {missing}')
    x = df[cols].copy()
    return x


def preprocess(x):
    """
    Pré-processa os dados antes de treinar o modelo. Ele realiza as seguintes etapas:
    1. Trata valores nulos ou 0 (NaNs) preenchendo-os com 0
    2. Remove valores absurdos, como packet_length negativo, filtrando as linhas onde todas as colunas têm valores maiores ou iguais a 0
    3. Padroniza os dados usando RobustScaler, que é menos sensível a outliers do que outros métodos de escalonamento. O scaler é ajustado aos dados e retorna os dados escalados e o objeto scaler para uso posterior.
    Essas etapas são essenciais para garantir que o modelo de detecção de anomalias seja treinado com dados limpos e padronizados, o que pode melhorar a performance do modelo e a precisão na detecção de anomalias.
    """
    # Substituir infinitos por NaN, depois tratar Nans
    x = x.replace([np.inf, -np.inf], np.nan)
    x = x.fillna(0)

    # Remover valores absurdos (packet_length negativo)
    x = x[(x >= 0).all(axis=1)]

    # Padronizar
    scaler = RobustScaler()
    x_scaled = scaler.fit_transform(x)
    return x_scaled, scaler



def train_model(x_scaled):
    """
    Treina o modelo de detecção de anomalias usando o algoritmo IsolationForest. Ele recebe os dados pré-processados e ajusta o modelo com os seguintes parâmetros:
    - n_estimators: número de árvores a serem criadas (200)
    - max_samples: número de amostras a serem usadas para treinar cada árvore (auto, que é 256 ou o número total de amostras, o que for menor)
    - contamination: fração do dataset que é anomala (auto, que ajusta automaticamente com base nos dados)
    - random_state: semente aleatória para garantir a reproducibilidade dos resultados (42)
    - n_jobs: número de núcleos da CPU a serem usados para o treinamento (todos os núcleos disponíveis, -1)
    O modelo é treinado usando o método fit() e retorna o modelo treinado. O IsolationForest é um algoritmo de detecção de anomalias que isola as amostras ao construir árvores de decisão, onde as amostras anômalas tendem a ser isoladas mais rapidamente do que as amostras normais, o que o torna eficaz para detectar anomalias em conjuntos de dados.
    """
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


def compute_threshold(clf, x_scaled, percentile=THRESHOLD_PERCENTILE):
    """
    Calcula o threshold para classificação de anomalias com base nos scores do modelo.
    O sistema de pontuação do IsolationForest atribui scores onde valores mais altos indicam amostras mais 'normais'.
    A função recebe o modelo treinado, os dados escalados e o percentil para definir o threshold. Ela calcula os scores usando o método decision_function() do modelo e, em seguida, determina o threshold como o valor correspondente ao percentil especificado (por exemplo, 97.5%), onde 100 - percentile é usado para considerar a fração de amostras normais.
    Retorna o threshold calculado e os scores para análise posterior.
    """
    # Sistema de pontuação: mais alto = mais "normal"
    scores = clf.decision_function(x_scaled)

    # Definir o threshold
    thr = np.percentile(scores, 100 - percentile)
    return thr, scores


def save_artifacts(clf, scaler, thr):
    """
    Salva os artefatos do modelo, incluindo o modelo treinado, o scaler e o threshold. Ele usa a biblioteca joblib para salvar o modelo e o scaler em arquivos especificados pelos caminhos definidos na configuração. O threshold é salvo em um arquivo de texto. Após salvar os artefatos, a função imprime uma mensagem indicando os arquivos onde os artefatos foram salvos.
    Salvar os artefatos do modelo é essencial para que o modelo treinado possa ser carregado posteriormente para fazer previsões em novos dados, sem a necessidade de treinar o modelo novamente. O scaler também é salvo para garantir que os novos dados sejam pré-processados da mesma forma que os dados usados para treinar o modelo, mantendo a consistência na detecção de anomalias.
    """
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    with open(THRESHOLD_PATH, 'w') as f:
        f.write(str(thr))
    print(f'Salvo: {MODEL_PATH}, {SCALER_PATH}, {THRESHOLD_PATH}')


def quick_report(scores, thr):
    """
    Imprime um resumo dos scores do modelo e do threshold utilizado. Ele exibe o valor mínimo, máximo e médio dos scores, bem como o threshold calculado. Esses valores fornecem uma visão geral da distribuição dos scores do modelo e ajudam a entender onde o threshold está localizado em relação aos scores, o que pode ser útil para avaliar a eficácia do modelo na detecção de anomalias.
    Além disso, a função pode ser expandida para salvar um histograma dos scores em um arquivo PNG usando a biblioteca matplotlib, o que pode fornecer uma visualização mais clara da distribuição dos scores e ajudar a identificar padrões ou outliers nos dados. Essa visualização pode ser especialmente útil para ajustar o threshold e melhorar a performance do modelo de detecção de anomalias.
    """
    print('Resumo dos scores: ')
    print(f'Min: {np.min(scores):.6f}\n Max: {np.max(scores):.6f}\n Mean: {np.mean(scores):.6f}')
    print(f'Threshold utilizado {thr:.6f}')
    # Salvar como histograma em PNG (matplotlib)?


def main():
    """
    Função principal que executa o processo de treinamento do modelo de detecção de anomalias. Ela segue as etapas definidas anteriormente:
    1. Carrega os dados do arquivo CSV ou do dataset usando a função load_data()
    2. Seleciona as features relevantes para o modelo usando a função select_features()
    3. Pré-processa os dados usando a função preprocess()
    4. Treina o modelo usando a função train_model()
    5. Calcula o threshold usando a função compute_threshold()
    6. Imprime um resumo dos resultados usando a função quick_report()
    7. Salva os artefatos do modelo usando a função save_artifacts()
    Essa função é o ponto de entrada do script e coordena todo o processo de treinamento do modelo, garantindo que cada etapa seja executada na ordem correta e que os resultados sejam salvos para uso futuro.
    """
    df = load_data(VECTOR_CSV)
    if settings.use_dataset:
        df = map_dataset_features(df)
    x = select_features(df)
    x_scaled, scaler = preprocess(x)
    clf = train_model(x_scaled)
    thr, scores = compute_threshold(clf, x_scaled)
    quick_report(scores, thr)
    save_artifacts(clf, scaler, thr)


if __name__ == '__main__':
    main()