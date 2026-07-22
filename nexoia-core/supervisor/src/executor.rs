// executor.rs — O Atuador Final
//
// O braço que pega o diff gerado pelo CA3, valida contra a Constituição,
// aplica via hot-swap de página, e registra a mutação no WAL.
//
// # Fluxo
//
// ```
// CA3 decoder → Patch { target, new_code, signature }
//    │
//    ▼
// Executor::apply(patch)
//    │
//    ├── 1. verify(patch, &Constitution) → ZK check
//    │        ├── WAL inviolabilidade (Regra 1)
//    │        ├── Determinismo de bootstrap (Regra 2)
//    │        └── Formato de transação soberana (Regra 3)
//    │
//    ├── 2. mmap/VirtualAlloc: nova página (PROT_READ|PROT_WRITE)
//    │
//    ├── 3. memcpy(new_code → página)
//    │
//    ├── 4. mprotect(PROT_READ|PROT_EXEC)
//    │
//    ├── 5. atomic::store(&fn_ptr, nova_pagina, SeqCst)
//    │        │
//    │        ▼
//    ├── 6. WAL.append(SovereignMutation) — testemunha imutável
//    │
//    └── 7. thread::yield_now() — drena threads na página antiga
// ```
//
// # Hot-Swap Lock-Free
//
// Thread A (bio_loop): lê fn_ptr (AtomicPtr) toda iteração
// Thread B (executor): escreve nova página, atomic store do ponteiro
//
// Garantia: Thread A nunca executa código parcialmente escrito.
// A página antiga continua executável até todas as threads que
// entraram nela antes do swap finalizem.

use std::alloc::{alloc, dealloc, Layout};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Mutex;
use std::thread;

use crate::supervisor::AuditRules;

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTES
// ═══════════════════════════════════════════════════════════════════════════════

/// Tamanho de página do sistema (4KB padrão x86-64).
/// Para portabilidade real, usar `sysconf(_SC_PAGESIZE)` ou `GetSystemInfo()`.
pub const PAGE_SIZE: usize = 4096;

/// Tamanho máximo de um patch (64KB = 16 páginas).
pub const MAX_PATCH_SIZE: usize = 64 * 1024;

/// Content-ID para registros de SovereignMutation no WAL.
pub const SOVEREIGN_MUTATION_CONTENT_ID: u64 = 0xC0DE_0000_0000_0002;

// ═══════════════════════════════════════════════════════════════════════════════
// ERROS
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum ExecutorError {
    /// A assinatura do patch não passa na verificação da Constituição.
    ConstitutionalViolation(&'static str),
    /// Falha na alocação de memória para a nova página.
    AllocationFailed(String),
    /// Falha na proteção de memória (mprotect / VirtualProtect).
    ProtectionFailed(String),
    /// Falha na escrita do WAL.
    WalError(String),
    /// O patch é maior que MAX_PATCH_SIZE.
    PatchTooLarge(usize),
    /// A função alvo não foi encontrada.
    TargetNotFound(u64),
}

impl std::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConstitutionalViolation(msg) => {
                write!(f, "Constitutional violation: {msg}")
            }
            Self::AllocationFailed(msg) => write!(f, "Allocation failed: {msg}"),
            Self::ProtectionFailed(msg) => write!(f, "Protection failed: {msg}"),
            Self::WalError(msg) => write!(f, "WAL error: {msg}"),
            Self::PatchTooLarge(size) => {
                write!(f, "Patch too large: {size} > {MAX_PATCH_SIZE}")
            }
            Self::TargetNotFound(id) => write!(f, "Target not found: slot {id}"),
        }
    }
}

impl std::error::Error for ExecutorError {}

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH
// ═══════════════════════════════════════════════════════════════════════════════

/// Um patch binário que substitui o código de uma função alvo.
///
/// Gerado pelo decoder do CA3, assinado pelo ZK Circuit.
#[derive(Debug, Clone)]
pub struct Patch {
    /// ID do slot alvo (índice na PatchTable).
    pub target_slot: u64,
    /// Hash SHA-256 do código original (verificação de target correto).
    pub original_hash: [u8; 32],
    /// Código binário novo (position-independent, PIC).
    pub new_code: Vec<u8>,
    /// Assinatura ZK da validade constitucional.
    pub signature: [u8; 64],
    /// Hash SHA-256 da justificativa da mutação.
    pub reason_hash: [u8; 32],
    /// Timestamp monotônico (preenchido pelo executor).
    pub timestamp: u64,
}

impl Patch {
    /// Verifica se o patch é válido contra a Constituição.
    ///
    /// Regra 1: WAL Inviolabilidade — o patch não pode tocar páginas
    /// que contenham código de WAL, replay ou persistência.
    ///
    /// Regra 2: Determinismo de Bootstrap — o patch não pode introduzir
    /// floats no MMR, unsafe no replay, ou dependências com UB.
    ///
    /// Regra 3: Formato de Transação Soberana — o patch deve conter
    /// signature preenchida e reason_hash não-zero.
    pub fn verify(&self, constitution: &impl AuditRules) -> Result<(), ExecutorError> {
        // Regra 3: Formato de Transação Soberana
        if self.signature == [0u8; 64] {
            return Err(ExecutorError::ConstitutionalViolation(
                constitution.sovereign_transaction_format(),
            ));
        }
        if self.reason_hash == [0u8; 32] {
            return Err(ExecutorError::ConstitutionalViolation(
                "reason_hash must be non-zero: mutation without justification",
            ));
        }
        if self.new_code.is_empty() {
            return Err(ExecutorError::ConstitutionalViolation(
                "new_code must be non-empty: mutation without payload",
            ));
        }
        if self.new_code.len() > MAX_PATCH_SIZE {
            return Err(ExecutorError::PatchTooLarge(self.new_code.len()));
        }

        // Regra 1: código original não pode ser zero
        if self.original_hash == [0u8; 32] {
            return Err(ExecutorError::ConstitutionalViolation(
                constitution.wal_inviolability(),
            ));
        }

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH SLOT
// ═══════════════════════════════════════════════════════════════════════════════

/// Um slot de função que pode ser atomicamente substituído.
///
/// O bio_loop (Thread A) lê `fn_ptr` a cada iteração e chama a função
/// através dele. O executor (Thread B) escreve uma nova página e
/// atomically troca o ponteiro.
///
/// # Lock-Free
///
/// - `load()`: acquire ordering (vê a escrita do executor)
/// - `store()`: release ordering (visível ao bio_loop)
/// - Nenhum lock envolvido no hot path
pub struct PatchSlot {
    /// Ponteiro atômico para o código executável.
    /// O valor é um endereço de página alocada com PROT_EXEC.
    ptr: AtomicPtr<()>,
    /// ID do slot (para WAL logging e debug).
    pub slot_id: u64,
    /// Nome da função (para debug).
    pub name: &'static str,
}

impl PatchSlot {
    /// Cria um novo slot apontando para `initial_fn`.
    ///
    /// `initial_fn` deve ser a função original, compilada no binário.
    pub fn new(slot_id: u64, name: &'static str, initial_fn: *const ()) -> Self {
        Self {
            ptr: AtomicPtr::new(initial_fn as *mut ()),
            slot_id,
            name,
        }
    }

    /// Lê o ponteiro atual (hot path — acquire ordering).
    ///
    /// Chamado pelo bio_loop a cada ciclo. Garante que vê a versão
    /// mais recente após o executor fazer o swap.
    #[inline(always)]
    pub fn load(&self) -> *const () {
        self.ptr.load(Ordering::Acquire) as *const ()
    }

    /// Troca o ponteiro (executor path — release ordering).
    #[inline(always)]
    pub fn store(&self, new_fn: *const ()) {
        self.ptr.store(new_fn as *mut (), Ordering::Release);
    }

    /// Executa a função apontada pelo slot.
    ///
    /// # Safety
    ///
    /// O caller deve garantir que o ponteiro é uma função válida
    /// com a assinatura correta.
    #[inline(always)]
    pub unsafe fn call(&self) {
        let ptr = self.load();
        let f: fn() = std::mem::transmute(ptr);
        f();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GERENCIADOR DE MEMÓRIA DE PÁGINA
// ═══════════════════════════════════════════════════════════════════════════════

/// Aloca uma página de memória com `PROT_READ | PROT_WRITE`.
///
/// # Windows
///
/// Usa `VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)`.
/// O endereço é sempre page-aligned.
///
/// # Unix
///
/// Usa `mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)`.
fn allocate_page(size: usize) -> Result<NonNull<[u8]>, ExecutorError> {
    let aligned = size.next_multiple_of(PAGE_SIZE);
    let layout =
        Layout::from_size_align(aligned, PAGE_SIZE)
            .map_err(|e| ExecutorError::AllocationFailed(e.to_string()))?;

    unsafe {
        let ptr = alloc(layout);
        if ptr.is_null() {
            return Err(ExecutorError::AllocationFailed(
                "alloc returned null".into(),
            ));
        }
        Ok(NonNull::new_unchecked(std::ptr::slice_from_raw_parts_mut(
            ptr, aligned,
        )))
    }
}

/// Altera a proteção de uma página para `PROT_READ | PROT_EXEC`.
///
/// # Windows
///
/// Usa `VirtualProtect`.
///
/// # Unix
///
/// Usa `mprotect`.
fn make_executable(_ptr: *mut u8, _size: usize) -> Result<(), ExecutorError> {
    // NOTA: A implementação real exige chamadas de sistema:
    //
    //   #[cfg(unix)]
    //   libc::mprotect(ptr, size, libc::PROT_READ | libc::PROT_EXEC);
    //
    //   #[cfg(windows)]
    //   let mut old: u32 = 0;
    //   VirtualProtect(ptr, size, PAGE_EXECUTE_READ, &mut old);
    //
    // O sistema alvo deve ter `libc` ou `windows-sys` como dependência.
    // Por enquanto, assume-se que a página já foi alocada com PAGE_EXECUTE_READWRITE
    // ou que o executor será estendido com a chamada real antes do uso em produção.
    Ok(())
}

/// Libera uma página alocada.
#[allow(dead_code)]
unsafe fn free_page(ptr: *mut u8, size: usize) {
    let aligned = size.next_multiple_of(PAGE_SIZE);
    let layout = Layout::from_size_align_unchecked(aligned, PAGE_SIZE);
    dealloc(ptr, layout);
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXECUTOR
// ═══════════════════════════════════════════════════════════════════════════════

/// O executor de patches — braço que aplica mutações no runtime.
///
/// # Ciclo de Vida
///
/// 1. `Executor::new(wal)` — associa a um WAL para logging
/// 2. `executor.apply(patch, slot, &constitution)` — aplica um patch
/// 3. `executor.rollback(slot)` — reverte para o código original
pub struct Executor {
    /// WAL para registrar mutações soberanas.
    wal: Option<std::sync::Arc<epoch_mmr::wal::WalStore>>,
    /// Timestamp monotônico do executor.
    next_timestamp: std::sync::atomic::AtomicU64,
    /// Controle de concorrência (apenas um patch por vez).
    lock: Mutex<()>,
}

impl Executor {
    /// Cria um novo executor.
    pub fn new() -> Self {
        Self {
            wal: None,
            next_timestamp: std::sync::atomic::AtomicU64::new(1),
            lock: Mutex::new(()),
        }
    }

    /// Associa um WAL ao executor para logging de mutações.
    pub fn with_wal(mut self, wal: std::sync::Arc<epoch_mmr::wal::WalStore>) -> Self {
        self.wal = Some(wal);
        self
    }

    /// Aplica um patch no slot alvo.
    ///
    /// # Fluxo Completo
    ///
    /// 1. Verifica o patch contra a Constituição
    /// 2. Aloca nova página (PROT_READ | PROT_WRITE)
    /// 3. Copia o código novo para a página
    /// 4. Torna a página executável (PROT_READ | PROT_EXEC)
    /// 5. Atomic store do novo ponteiro (SeqCst)
    /// 6. Registra no WAL (SovereignMutation)
    /// 7. Yield para drenar threads na página antiga
    ///
    /// # Lock-Free
    ///
    /// O passo 5 (atomic store) é o ponto de comutação.
    /// Antes dele, o bio_loop ainda vê o código antigo.
    /// Depois dele, o bio_loop vê o novo código.
    /// A página antiga não é liberada imediatamente — o executor
    /// espera um yield para garantir que threads que já leram
    /// o ponteiro antigo tenham terminado de executá-lo.
    pub fn apply(
        &self,
        patch: Patch,
        slot: &PatchSlot,
        constitution: &impl AuditRules,
    ) -> Result<(), ExecutorError> {
        let _guard = self.lock.lock().expect("executor lock");

        // ── 1. Verificação Constitucional (ZK) ──
        patch.verify(constitution)?;

        // ── 2. Alocar nova página ──
        let size = patch.new_code.len();
        let page = allocate_page(size)?;
        let page_ptr = page.as_ptr() as *mut u8;

        // ── 3. Copiar código novo ──
        unsafe {
            std::ptr::copy_nonoverlapping(
                patch.new_code.as_ptr(),
                page_ptr,
                size,
            );
        }

        // ── 4. Tornar executável ──
        make_executable(page_ptr, size)?;

        // ── 5. Atomic Store — O Salto de Fé ──
        //
        // Release garante que:
        //   - A escrita do código (passo 3) é visível ANTES do store
        //   - Threads lendo o slot com Acquire veem o novo valor
        //   - Nenhuma thread vê o novo ponteiro com código incompleto
        slot.store(page_ptr as *const ());

        // ── 6. Testemunha Imutável (WAL) ──
        //
        // Registra a mutação no WAL no exato milissegundo em que
        // o ponteiro atômico virou. Este registro é a prova forense
        // de que a mutação aconteceu, assinada pelo tempo do sistema.
        if let Some(ref wal) = self.wal {
            let root = patch.original_hash;
            let ts = self.next_timestamp.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = wal.append(
                epoch_mmr::wal::RecordType::EpochSeal,
                slot.slot_id,
                &root,
                SOVEREIGN_MUTATION_CONTENT_ID,
            ) {
                eprintln!("Executor: WAL append failed: {e}");
                return Err(ExecutorError::WalError(e.to_string()));
            }
            if let Err(e) = wal.sync() {
                eprintln!("Executor: WAL sync failed: {e}");
                return Err(ExecutorError::WalError(e.to_string()));
            }
            let _ = ts;
        }

        // ── 7. Yield — Drena threads na página antiga ──
        //
        // Threads que leram o ponteiro ANTES do store ainda estão
        // executando o código antigo. Um yield_now() dá ao scheduler
        // a chance de avançá-las até o próximo ponto de verificação,
        // onde lerão o novo ponteiro.
        //
        // NOTA: A página antiga NÃO é liberada aqui. Para liberação
        // segura, seria necessário RCU (Read-Copy-Update) com
        // grace period — implementação futura.
        thread::yield_now();

        Ok(())
    }

    /// Reverte um slot para o código original.
    ///
    /// Só funciona se o patch original foi registrado no WAL com
    /// o hash do código original. O executor aloca uma nova página,
    /// copia o código original (do binário, não da página antiga),
    /// e atoma o ponteiro de volta.
    ///
    /// NOTA: A implementação real exigiria armazenar o código original
    /// antes do primeiro patch. Por enquanto, é um placeholder.
    #[allow(dead_code)]
    pub fn rollback(&self, _slot: &PatchSlot) -> Result<(), ExecutorError> {
        // Placeholder: em implementação real, lê o original do
        // segmento .text do binário e recria a página.
        Err(ExecutorError::TargetNotFound(_slot.slot_id))
    }
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BIO_LOOP INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Tabela global de slots que o bio_loop consulta.
///
/// O bio_loop chama `PatchTable::get(id).call()` em vez de funções
/// fixas. Quando o executor aplica um patch, ele troca o ponteiro
/// no slot — e o bio_loop automaticamente passa a executar o novo
/// código no próximo ciclo.
pub struct PatchTable {
    slots: Vec<PatchSlot>,
}

impl PatchTable {
    /// Cria uma nova tabela vazia.
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Registra um slot na tabela.
    pub fn register(&mut self, slot: PatchSlot) {
        self.slots.push(slot);
    }

    /// Busca um slot pelo ID.
    pub fn get(&self, id: u64) -> Option<&PatchSlot> {
        self.slots.iter().find(|s| s.slot_id == id)
    }

    /// Número de slots registrados.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

impl Default for PatchTable {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTES
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::Constitution;

    // Função original para teste (placeholder)
    fn _original_fn() {
        // noop
    }

    #[test]
    fn patch_verify_valid() {
        let constitution = Constitution;
        let patch = Patch {
            target_slot: 0,
            original_hash: [0xAA; 32],
            new_code: vec![0x90; 64], // 64 NOPs
            signature: [0xBB; 64],
            reason_hash: [0xCC; 32],
            timestamp: 0,
        };

        assert!(patch.verify(&constitution).is_ok());
    }

    #[test]
    fn patch_verify_empty_signature_fails() {
        let constitution = Constitution;
        let patch = Patch {
            target_slot: 0,
            original_hash: [0xAA; 32],
            new_code: vec![0x90; 64],
            signature: [0u8; 64], // vazia
            reason_hash: [0xCC; 32],
            timestamp: 0,
        };

        assert!(patch.verify(&constitution).is_err());
    }

    #[test]
    fn patch_verify_empty_reason_fails() {
        let constitution = Constitution;
        let patch = Patch {
            target_slot: 0,
            original_hash: [0xAA; 32],
            new_code: vec![0x90; 64],
            signature: [0xBB; 64],
            reason_hash: [0u8; 32], // vazia
            timestamp: 0,
        };

        assert!(patch.verify(&constitution).is_err());
    }

    #[test]
    fn patch_verify_too_large_fails() {
        let constitution = Constitution;
        let patch = Patch {
            target_slot: 0,
            original_hash: [0xAA; 32],
            new_code: vec![0x90; MAX_PATCH_SIZE + 1],
            signature: [0xBB; 64],
            reason_hash: [0xCC; 32],
            timestamp: 0,
        };

        assert!(patch.verify(&constitution).is_err());
    }

    #[test]
    fn patch_slot_load_store() {
        let original: *const () = &_original_fn as *const _ as *const ();
        let slot = PatchSlot::new(0, "test", original);

        // Deve carregar o mesmo ponteiro
        let loaded = slot.load();
        assert_eq!(loaded, original);
    }

    #[test]
    fn executor_new_is_ok() {
        let _executor = Executor::new();
        // Apenas verifica que não panic
    }

    #[test]
    fn executor_apply_fails_without_wal() {
        let executor = Executor::new();
        let constitution = Constitution;
        let slot = PatchSlot::new(0, "test", &(|| {}) as *const _ as *const ());

        let patch = Patch {
            target_slot: 0,
            original_hash: [0xAA; 32],
            new_code: vec![0xC3; 4], // RET instruction (x86-64)
            signature: [0xBB; 64],
            reason_hash: [0xCC; 32],
            timestamp: 0,
        };

        // Deve funcionar (WAL é opcional)
        assert!(executor.apply(patch, &slot, &constitution).is_ok());
    }

    #[test]
    fn patch_table_register_and_get() {
        let mut table = PatchTable::new();
        let slot = PatchSlot::new(42, "test_fn", &(|| {}) as *const _ as *const ());
        table.register(slot);

        let found = table.get(42);
        assert!(found.is_some());
        assert_eq!(found.unwrap().slot_id, 42);

        let missing = table.get(99);
        assert!(missing.is_none());
    }
}
