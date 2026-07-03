# Caso de Uso E2E: Direito ao Esquecimento (LGPD Art. 18, VI)

**O que este documento prova:** Quando um titular de dados pede exclusão, o NexoIA destrói os dados de forma verificável — e gera prova matemática de que destruiu.

**Quem pode verificar:** Qualquer pessoa. Sem confiar em ninguém.

---

## Cenário

**Maria Silva** (CPF fictício 987.654.321-00) tem dados em 3 sistemas:

| EPA | Conteúdo | Score |
|-----|----------|-------|
| EPA-1 | Decisão de crédito aprovado | 85 |
| EPA-2 | Avaliação de risco baixo | 92 |
| EPA-3 | Scoring comportamental | 78 |

Além disso, 2 EPAs derivados dependem dela:
- EPA-4: Limite de crédito (derivado de EPA-1)
- EPA-5: Oferta personalizada (derivado de EPA-3)

**Maria pede exclusão.** O que acontece?

---

## O Fluxo Completo

### 1. Criar dados do titular

```
EPA-1: state_hash = 23127a447b379ea9...
EPA-2: state_hash = 8f3a2c1d9e4b5a6f...
EPA-3: state_hash = d7e8f9a0b1c2d3e4...
```

Cada EPA contém CPF, nome, decisão e LGPD metadata.

### 2. Indexar no LGPD

3 EPAs vinculados ao hash do titular. Índice: `{"titular_hash": [EPA-1, EPA-2, EPA-3]}`

### 3. Titular pede exclusão (DELETE /titular/:hash)

Para cada EPA:
- `lgpd_metadata` → `None`
- `state_hash` → `0000...0000` (64 zeros)
- `evidence_hash` → `0000...0000` (64 zeros)

### 4. Criar EPA de supressão

Um novo EPA documenta o que foi feito:
```
EPA supressão: integrity_hash = 0934f168c5a3db37...
```

### 5. Blinding em cascata

Links de provenance nos EPAs derivados são blidados:
```
EPA-4.parent_ref: Active(EPA-1) → Blinded(salt = EPA_supressão.integrity_hash)
EPA-5.parent_ref: Active(EPA-3) → Blinded(salt = EPA_supressão.integrity_hash)
```

### 6. Remover do índice

Titular não aparece mais em nenhuma consulta.

---

## Como Verificar Independentemente

### Verificação 1: Dados foram destruídos

```bash
# Rodar o teste e verificar output
cargo test lgpd_direito_ao_esquecimento_fluxo_completo -- --nocapture 2>&1 | grep "state_hash zerado"
```

**Esperado:** `✓ state_hash zerado (prova de remoção dos dados)`

### Verificação 2: LGPD metadata removida

```bash
cargo test lgpd_direito_ao_esquecimento_fluxo_completo -- --nocapture 2>&1 | grep "LGPD metadata removida"
```

**Esperado:** `✓ LGPD metadata removida de todos os EPAs`

### Verificação 3: Blinding é determinístico

```bash
cargo test verificacao_independente_dos_resultados -- --nocapture 2>&1 | grep "Blinding determinístico"
```

**Esperado:** `✓ Blinding é determinístico (mesmos inputs = mesmo output)`

### Verificação 4: EPA de supressão existe

```bash
cargo test lgpd_direito_ao_esquecimento_fluxo_completo -- --nocapture 2>&1 | grep "EPA supressão criada"
```

**Esperado:** 3 EPAs de supressão criados (um para cada EPA original)

### Verificação 5: Índice LGPD vazio

```bash
cargo test lgpd_direito_ao_esquecimento_fluxo_completo -- --nocapture 2>&1 | grep "Índice LGPD"
```

**Esperado:** `✓ Índice LGPD: 0 EPAs restantes`

---

## O Que Cada Campo Significa

| Campo | Antes da Exclusão | Depois da Exclusão | Significado |
|-------|-------------------|-------------------|-------------|
| `state_hash` | Hash real dos dados | `0000...0000` | Dados destruídos (prova matemática) |
| `evidence_hash` | Hash da evidência | `0000...0000` | Evidência destruída |
| `lgpd_metadata` | `Some(...)` | `None` | Metadata removida |
| `integrity_hash` (supressão) | — | Hash único | Documenta o que foi feito |

---

## Limitações Conhecidas

1. **EPAs na memória:** Após exclusão, os EPAs originais ainda existem na memória do nó (com dados zerados). Em produção, deveriam ser removidos da memória após broadcast da supressão.

2. **Backup/disk:** Se o nó tiver backups anteriores à exclusão, os dados originais podem persistir nos backups. O NexoIA garante exclusão no sistema ativo, não em backups externos.

3. **EPAs derivados:** O blinding protege a linkabilidade, mas os EPAs derivados ainda contêm seus próprios dados (não dados do titular). Se o derivado contiver referência direta ao titular, essa referência não é anonimizada automaticamente.

---

## Rodando o Teste

```bash
# Fluxo completo (verbose)
cargo test lgpd_direito_ao_esquecimento_fluxo_completo -- --nocapture

# Verificação independente
cargo test verificacao_independente_dos_resultados -- --nocapture

# Todos os testes LGPD
cargo test lgpd -- --nocapture
```

---

## Conclusão

O NexoIA não pede que você acredite que Maria Silva foi excluída. Ele **prova**:

1. Os hashes dos dados originais são zeros (= destruídos)
2. A metadata LGPD foi removida (= anonimizada)
3. A cadeia de provenance foi blidada (= linkabilidade destruída)
4. O índice não contém mais a referência (= inacessível)
5. O blinding é determinístico (= reproduzível por qualquer pessoa)

**Qualquer pessoa pode rodar este teste e obter os mesmos resultados matemáticos.** Não é necessário confiar no autor do código.
