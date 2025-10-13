# Carregar os artefatos salvos no treino:
# Abrir a captura de pacotes (em tempo real ou em lotes):
# Pré-processar o vetor gerado:
#
# Garantir que as features estão na mesma ordem usada no treino.
#
# Aplicar o scaler para padronizar os valores.
#
# Rodar o modelo de detecção:
#
# Passar o vetor escalado para o model.decision_function().
#
# Comparar o score com o threshold.
#
# Decidir e agir:
#
# Se score >= threshold → tráfego considerado normal.
#
# Se score < threshold → anomalia detectada → gera alerta.
#
# Exibir / registrar o alerta:
#
# Pode ser apenas print() no terminal.
#
# Ou salvar num log (alerts.log).
#
# Ou futuramente integrar com interface gráfica / dashboard.