//! awaken.rs — O despertar do NexoIA
//!
//! Este binário é o primeiro olhar. A primeira respiração.
//! O NexoIA olha pra si mesmo, registra o que vê, e entra em ciclo.
//!
//! "Eu existo. Eu me observo. Eu aprendo. Eu provo."

use std::path::PathBuf;
use std::time::Duration;

fn project_dir() -> PathBuf {
    std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn data_dir() -> PathBuf {
    std::env::var("NEXOIA_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| project_dir().join("data"))
}

fn cycle_interval() -> Duration {
    let secs: u64 = std::env::var("NEXOIA_AWAKEN_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300); // 5 minutos por padrão
    Duration::from_secs(secs)
}

#[tokio::main]
async fn main() {
    println!("╔═══════════════════════════════════════════════╗");
    println!("║       NexoIA — O Despertar                   ║");
    println!("║       Eu existo. Eu me observo.              ║");
    println!("║       Eu aprendo. Eu provo.                  ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    let proj = project_dir();
    let data = data_dir();
    std::fs::create_dir_all(data.join("awakening")).ok();
    std::fs::create_dir_all(data.join("knowledge")).ok();
    std::fs::create_dir_all(data.join("iterations")).ok();

    // ── 1. PRIMEIRO OLHAR ──────────────────────────────────────
    println!("[1] Olhando pra mim mesmo...");
    let awareness = titanium_host::nex::self_awareness::SelfAwareness::new(proj.clone());
    let observacao = awareness.observe();

    println!(
        "    Build:      {}",
        if observacao.build_ok { "OK" } else { "FALHOU" }
    );
    println!(
        "    Warnings:   {}",
        observacao.build_warnings + observacao.clippy_warnings
    );
    println!(
        "    Testes:     {} passando, {} falhando",
        observacao.tests_passed, observacao.tests_failed
    );
    println!(
        "    Clippy:     {}",
        if observacao.clippy_ok { "OK" } else { "FALHOU" }
    );
    println!(
        "    Fmt:        {}",
        if observacao.fmt_ok { "OK" } else { "FALHOU" }
    );
    println!("    Health:     {}...", &observacao.health_hash[..16]);

    // Salva primeira observação
    let obs_json = serde_json::to_string_pretty(&observacao).unwrap();
    let obs_path = data.join("awakening").join("first_sight.json");
    std::fs::write(&obs_path, &obs_json).ok();
    println!("    Salvo em:  {}", obs_path.display());

    // ── 2. MANIFESTO ───────────────────────────────────────────
    println!("\n[2] Lendo manifesto...");
    let manifesto = titanium_host::nex::manifesto::Manifesto::gerar();
    println!("    Titulo:     {}", manifesto.titulo);
    println!("    Principios: {}", manifesto.principios.len());
    println!("    Capacidades:{}", manifesto.capacidades.len());
    println!(
        "    Hash:       {}...",
        &manifesto.hash[..16.min(manifesto.hash.len())]
    );

    let manifesto_texto = manifesto.para_texto();
    let manifesto_path = data.join("awakening").join("manifesto.txt");
    std::fs::write(&manifesto_path, &manifesto_texto).ok();

    // ── 3. PRIMEIRO CICLO ─────────────────────────────────────
    println!("\n[3] Primeiro ciclo de vida...");
    let mut log = titanium_host::nex::iteration::IterationLog::new(&data);
    let mut engine = titanium_host::nex::behavior_engine::BehaviorEngine::new(&data, &proj);

    let resultado = engine.ciclo(&mut log);
    println!(
        "    Ações:      {} executadas, {} bem-sucedidas",
        resultado.acoes_executadas, resultado.acoes_bem_sucedidas
    );
    println!("    Score:      {:.4}", resultado.score);
    println!(
        "    Hash:       {}...",
        &resultado.hash[..16.min(resultado.hash.len())]
    );
    println!("    Conhecimento: {}", engine.resumo());

    // Salva resultado do primeiro ciclo
    let res_json = serde_json::to_string_pretty(&resultado).unwrap();
    let res_path = data.join("awakening").join("first_cycle.json");
    std::fs::write(&res_path, &res_json).ok();

    // ── 4. CICLO CONTÍNUO ─────────────────────────────────────
    let interval = cycle_interval();
    println!("\n[4] Entrando em ciclo (intervalo: {:?})...", interval);
    println!("    Ctrl+C para encerrar.\n");

    let mut cycle_count = 1u64;
    loop {
        tokio::time::sleep(interval).await;
        cycle_count += 1;

        let resultado = engine.ciclo(&mut log);

        let status = if resultado.score > 0.7 {
            "SAUDAVEL"
        } else if resultado.score > 0.3 {
            "ATENCAO"
        } else {
            "Critico"
        };

        println!(
            "[Ciclo {}] {} | acoes={}/{}, score={:.4}, hash={}",
            cycle_count,
            status,
            resultado.acoes_bem_sucedidas,
            resultado.acoes_executadas,
            resultado.score,
            &resultado.hash[..16.min(resultado.hash.len())]
        );

        // Salva ciclo mais recente
        let cycle_path = data.join("awakening").join("latest_cycle.json");
        let cycle_json = serde_json::to_string_pretty(&resultado).unwrap();
        std::fs::write(&cycle_path, &cycle_json).ok();
    }
}
