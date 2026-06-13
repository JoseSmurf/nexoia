# nexoia

NexoIA e um projeto Rust pequeno que gera artefatos deterministas de decisao.
Ele calcula hashes canonicos com BLAKE3, registra evidencias em JSONL e monta um manifest com os hashes dos arquivos gerados.
A saida foi desenhada para ser previsivel, auditavel e facil de inspecionar.

## Como rodar

```bash
cargo run
```

## Arquivos gerados

- `state.json` - estado de entrada normalizado usado na execucao.
- `evidence.jsonl` - trilha de evidencias com hash deterministico por linha.
- `decisions.jsonl` - registro das decisoes produzidas pela avaliacao.
- `manifest.json` - resumo final com status, motivo e hashes dos artefatos.

## Frase

> "Uma EPA é um objeto que consegue lembrar por que acredita no que acredita."
