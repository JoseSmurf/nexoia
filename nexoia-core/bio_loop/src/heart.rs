use crossbeam_channel::Sender;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crate::Event;

/// Intervalo alvo entre batimentos: 1ms = 1 000 Hz.
pub const TICK_INTERVAL: Duration = Duration::from_millis(1);

/// Stack size da thread do Coração.
/// 32 KB é suficiente para um loop simples. O padrão do OS (8 MB) seria
/// desperdiçado num loop que não aprofunda a pilha de chamadas.
const HEART_STACK_BYTES: usize = 32 * 1024;

/// Inicializa e executa o Coração em uma thread isolada.
///
/// # Garantias
/// - A thread nunca bloqueia esperando o canal: usa `try_send`. Se o canal
///   estiver cheio durante um pico, o batimento é **silenciosamente descartado**
///   — o coração não para por pressão externa.
/// - O loop usa `sleep` calibrado para atingir ~1000 Hz sem busy-spin,
///   respeitando o escalonador do OS.
/// - Retorna o `JoinHandle` para que o chamador possa aguardar a parada
///   graciosamente via `running.store(false, Relaxed)`.
pub fn spawn_heart(tx: Sender<Event>, running: Arc<AtomicBool>) -> std::thread::JoinHandle<u64> {
    std::thread::Builder::new()
        .name("nexoia-heart".to_string())
        .stack_size(HEART_STACK_BYTES)
        .spawn(move || {
            let mut tick: u64 = 0;

            while running.load(Ordering::Relaxed) {
                // Marca o início deste batimento para medir drift de scheduling.
                let beat_start = Instant::now();

                // Hot path: tenta enviar sem bloquear.
                // Se o canal estiver cheio (digestão sobrecarregada), descarta.
                // `try_send` é zero-allocation e lock-free.
                let _ = tx.try_send(Event::Heartbeat(tick));

                tick = tick.wrapping_add(1);

                // Calcula quanto tempo ainda resta até o próximo batimento.
                // Compensamos o tempo gasto em `try_send` e no overhead da iteração.
                let elapsed = beat_start.elapsed();
                if let Some(remaining) = TICK_INTERVAL.checked_sub(elapsed) {
                    // `sleep` entrega a thread ao escalonador sem busy-spin.
                    // Para drift < 50μs em sistemas normais; aceito para 1 kHz bio.
                    std::thread::sleep(remaining);
                }
                // Se elapsed >= TICK_INTERVAL, estamos atrasados — iteração
                // imediata sem sleep para tentar recuperar o ritmo.
            }

            // Retorna o total de ticks para diagnóstico
            tick
        })
        .expect("Falha crítica ao criar thread do Coração — sem recursos de OS")
}
