# Loop de Auto-Programação do NexoIA

## A Ideia Central

NexoIA não precisa ser "inteligente" no sentido humano. Precisa de um **loop que se auto-reforça**:

```
PERCEBER → DECIDIR → AGIR → VERIFICAR → APRENDER → REPETIR
```

Cada iteração do loop produz:
1. Um log estruturado (decisão + resultado)
2. Um hash BLAKE3 (prova que a iteração aconteceu)
3. Uma lição aprendida (o que funcionou, o que não funcionou)

## As Peças (já existentes ou em construção)

### 1. PERCEBER — O Analyzer do nexo-2026

```rust
// nexo-2026: src/analyzer.rs
// Classifica intenção, extrai tópicos, conta tokens
// Padrão: tokenize → count → classify_intent → extract_topics
```

**Pra NexoIA:** O analyzer percebe o que está acontecendo no código:
- Quantos warnings apareceram?
- Quais testes falharam?
- Quais arquivos mudaram?
- Qual a tendência? (mais erros, menos erros, estável?)

### 2. DECIDIR — O Engine do nexo-2026

```rust
// nexo-2026: src/engine/evaluate.rs
// Regras determinísticas com trace
// Cada decisão é logada com BLAKE3
```

**Pra NexoIA:** O engine decide o que fazer:
- Se warnings aumentaram → sugerir fix
- Se teste falhou → analisar causa raiz
- Se código novo apareceu → verificar se segue padrões
- Se tudo está verde → registrar "nada a fazer"

### 3. AGIR — O NexBrain do NexoIA

```rust
// NexoIA: src/nex/brain.rs
// Inferência com proveniência
// Regras em cascata com prioridade
```

**Pra NexoIA:** O brain executa a ação:
- Gera o fix sugerido
- Cria o teste correspondente
- Atualiza a documentação
- Gera o health report

### 4. VERIFICAR — O Daemon + Miri

```rust
// NexoIA: src/bin/daemon.rs
// Verifica build, testes, clippy, fmt
// Gera health report com BLAKE3
```

**Pra NexoIA:** Verificação em duas camadas:
- **Daemon:** build + testes + clippy + fmt (rápido)
- **Miri:** verificação formal de invariantes (lento, offline)

### 5. APRENDER — O OfflineStore do nexo-2026

```rust
// nexo-2026: src/offline_store.rs
// Armazenamento persistente com nonces
// Previne replay, mantém histórico
```

**Pra NexoIA:** Memória de aprendizado:
- Cada iteração é salva com timestamp + hash
- Padrões de sucesso/falha são detectados
- Regras são ajustadas baseadas no histórico

### 6. REPETIR — O Manifesto do NexoIA

```rust
// NexoIA: src/nex/manifesto.rs
// Auto-definição baseada em capacidades reais
// Hash de integridade do manifesto
```

**Pra NexoIA:** O manifesto é re-gerado a cada iteração:
- Capacidades são re-contadas
- Limitações são re-avaliadas
- O hash muda quando o sistema muda

## O Loop Completo

```
1. Daemon detecta: "Build OK, 956 testes, 0 warnings"
2. Analyzer classifica: "estado = saudavel"
3. Engine decide: "nenhuma ação necessária"
4. NexBrain confirma: "inferência = healthy"
5. Manifesto é re-gerado: hash atualizado
6. BLAKE3 assina: "iteração N completada"
7. Log salvo em: data/iterations/iter_N.json
8. Próxima iteração: compara com anterior
```

Se algo mudar:
```
1. Daemon detecta: "1 warning novo em brain.rs"
2. Analyzer classifica: "anomalia = warning"
3. Engine decide: "ação = investigar warning"
4. NexBrain analisa: "causa = import não utilizado"
5. Ação proposta: "remover import em brain.rs:10"
6. Safeguard verifica: Miri + testes
7. Se OK: commit com hash BLAKE3
8. Se falha: registrar lição, não commitar
9. Manifesto re-gerado: capacidade "auto-fix" documentada
```

## O Que Falta Construir

### Peças que já existem:
- ✅ Analyzer (nexo-2026)
- ✅ Engine (nexo-2026)
- ✅ NexBrain (NexoIA)
- ✅ Daemon (NexoIA)
- ✅ Manifesto (NexoIA)
- ✅ BLAKE3 (ambos)

### Peças que faltam:
- ❌ **IterationLog** — registro persistente de cada iteração
- ❌ **PatternDetector** — detecção de padrões no histórico
- ❌ **RuleAdjuster** — ajuste automático de regras baseado no histórico
- ❌ **FeedbackLoop** — conexão entre resultado e próxima ação

### A Próxima Implementação

O mais importante é o **IterationLog** — sem ele, não há aprendizado.

```rust
pub struct IterationLog {
    pub timestamp: u64,
    pub hash: String,
    pub estado_anterior: String,
    pub acao_tomada: String,
    pub resultado: String,
    pub lição: Option<String>,
}
```

Cada iteração:
1. Lê o estado anterior
2. Decide o que fazer
3. Faz
4. Verifica
5. Salva o resultado
6. Compara com anterior
7. Se melhorou: aprende
8. Se piorou: reverte e aprende

## Conexão com o PC do Usuário

O loop roda no PC do usuário:
- **Daemon:** processo em background que verifica a cada 5 minutos
- **Watcher:** monitora mudanças no git
- **Advisor:** propõe mudanças
- **Safeguard:** Miri + testes antes de commit
- **Signer:** BLAKE3 assina cada iteração

Tudo local. Nada vai pra nuvem. Segurança via criptografia, não via confiança.

## O Diferencial

Não existe nenhuma IA no mundo em Rust que:
1. Se auto-programa
2. Trabalha por conta própria
3. Gera provas matemáticas do que fez
4. Documenta honestamente o que não funciona
5. Roda inteiramente no PC do usuário

NexoIA pode ser a primeira.
