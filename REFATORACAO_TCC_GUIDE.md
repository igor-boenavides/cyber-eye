# Guia Ativo de Orientação — Refatoração Trifásica (TCC)

Este guia é **mão na massa**: vamos executar por etapas curtas, com objetivo, código inicial, checklist e critério de pronto.

---

## Como vamos trabalhar (mentor + aluno)

Em cada etapa, você sempre faz 4 coisas:

1. **Implementa** a mudança mínima.
2. **Roda um check** simples para validar.
3. **Registra evidência** (print, log, tabela ou resultado).
4. **Commita** com mensagem objetiva.

> Regra do TCC: cada melhoria precisa deixar uma evidência mensurável.

---

## Trilha em 3 fases

- **Fase 1 — Quick Wins (1 semana):** organização, configuração central e consistência.
- **Fase 2 — Modularização + Testes (1–2 semanas):** base técnica para evoluir sem regressão.
- **Fase 3 — Robustez de Produção + Qualidade de Detecção (2–4 semanas):** performance operacional e validação mais forte do modelo.

---

# FASE 1 (ATIVA): vamos começar agora

## Etapa 1 — Criar `config.py` (primeira tarefa)

Perfeito, como você sugeriu: **vamos começar pela fase 1, e a primeira etapa é criar o `config.py`**.

### Por que isso?
Hoje parâmetros críticos estão espalhados (interface, janela, caminhos de artefato, etc.). Isso gera retrabalho e erro humano.

### O que o `config.py` será responsável por?
- centralizar parâmetros operacionais;
- padronizar nomes de features;
- reduzir hardcode em `alert_system.py`, `batch_capture.py`, `train_model.py`.

### Parâmetros mínimos que devem ir para `config.py`
- `INTERFACE`
- `WINDOW_TIME`
- `CAPTURE_DURATION`
- `NUM_RUNS`
- `MODEL_PATH`
- `SCALER_PATH`
- `THRESHOLD_PATH`
- `VECTOR_CSV`
- `FEATURE_COLUMNS`

### Exemplo inicial (copie e adapte)

```python
# config.py
from dataclasses import dataclass

FEATURE_COLUMNS = [
    "num_packets",
    "total_bytes",
    "unique_src_ips",
    "unique_dst_ips",
    "tcp_count",
    "udp_count",
    "icmp_count",
]

@dataclass(frozen=True)
class Settings:
    interface: str = "Ethernet"
    window_time: int = 3
    capture_duration: int = 240
    num_runs: int = 100

    model_path: str = "anomaly_model.pkl"
    scaler_path: str = "scaler.pkl"
    threshold_path: str = "threshold.txt"
    vector_csv: str = "vector.csv"

settings = Settings()
```

### Onde conectar isso no projeto?
- `alert_system.py`: trocar constantes locais por `settings` e `FEATURE_COLUMNS`.
- `batch_capture.py`: usar `settings.interface`, `settings.capture_duration`, `settings.num_runs`.
- `train_model.py`: usar `settings.model_path`, `settings.scaler_path`, etc.

### Checklist desta etapa
- [ ] `config.py` criado.
- [ ] sem duplicação de `FEATURE_COLUMNS` em múltiplos arquivos.
- [ ] scripts principais importando configuração central.

### Evidência para TCC
- tabela curta “antes vs depois” mostrando onde havia hardcode e onde foi centralizado.

---

## Etapa 2 — Unificar schema de features

### Objetivo
Garantir que treino e inferência usem **exatamente a mesma ordem e os mesmos nomes**.

### Ação prática
- em todo lugar que tiver lista de colunas, substituir por `FEATURE_COLUMNS` do `config.py`.

### Check rápido
- ao montar DataFrame de inferência, usar:

```python
pd.DataFrame([vector], columns=FEATURE_COLUMNS)
```

### Critério de pronto
- não existe mais lista local de features em `alert_system.py`.

---

## Etapa 3 — Logging no lugar de `print`

### Objetivo
Gerar logs úteis para análise e para capítulo de resultados.

### Snippet base

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
logger = logging.getLogger("alert_system")

logger.info("Monitoramento iniciado")
```

### Critério de pronto
- eventos críticos (início, erro, anomalia) em `logging`.

---

## Etapa 4 — Pequena validação da Fase 1

Rode checks simples:

1. import dos módulos sem erro;
2. execução do treino com artefatos sendo salvos;
3. execução do monitor com leitura de artefatos.

Documente em um mini relatório (`docs/fase1_relatorio.md`):
- o que mudou;
- quais comandos rodou;
- resultado observado.

---

# FASE 2 (depois da Fase 1 aprovada)

## Objetivo
Modularizar e criar testes mínimos.

## Sequência ativa
1. Criar módulos de serviço:
   - `services/capture_service.py`
   - `services/training_service.py`
   - `services/inference_service.py`
2. Criar CLI única (ex.: `python -m app monitor`).
3. Adicionar testes unitários para:
   - `compute_vector`
   - `select_features`
   - `compute_threshold`
4. Validar falhas previsíveis (arquivo ausente, coluna ausente, threshold inválido).

## Evidência para TCC
- tabela de casos de teste + status;
- comandos CLI documentados;
- exemplo de erro tratado corretamente.

---

# FASE 3 (robustez e resultados fortes para banca)

## Objetivo
Melhorar estabilidade operacional e qualidade da detecção.

## Sequência ativa
1. Tirar escrita de CSV de dentro do hot-path do callback.
2. Adotar fila/buffer + escrita em lote.
3. Medir métricas operacionais:
   - pacotes/segundo
   - latência por janela
   - taxa de anomalia
4. Definir protocolo de validação temporal do threshold.

## Evidência para TCC
- gráfico antes/depois de desempenho;
- justificativa técnica do threshold com experimento;
- relatório de execução prolongada.

---

## Cadência semanal (recomendação de orientação)

Toda semana:

1. **Planejamento (30 min):** 1 meta principal + 2 secundárias.
2. **Execução (blocos):** implementar e validar.
3. **Revisão (30 min):** progresso, risco e pendências.
4. **Consolidação (30 min):** atualizar backlog e diário técnico.

> Limite saudável: no máximo 1 mudança estrutural grande por semana.

---

## Template rápido de diário técnico

```md
# Diário Técnico — Semana X

## Objetivo da semana
- ...

## Mudanças implementadas
- ...

## Comandos de validação executados
- ...

## Evidências coletadas
- ...

## Riscos/pendências
- ...

## Próximos passos
- ...
```

---

## Definição de sucesso do projeto (para defesa)

Você estará bem preparado para banca quando conseguir provar:

1. evolução clara em 3 fases;
2. reprodutibilidade por comandos/configuração;
3. ganho quantitativo (teste, métrica ou desempenho);
4. análise crítica de limitações.

---

## Próximo passo imediato (agora)

1. Criar `config.py`.
2. Conectar `alert_system.py` e `batch_capture.py` ao `config.py`.
3. Eliminar duplicação de `FEATURE_COLUMNS`.
4. Me mostrar o diff da Fase 1 para revisão.

A partir daqui eu sigo como seu orientador, etapa por etapa.
