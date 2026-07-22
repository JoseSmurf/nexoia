use bio_loop::digest::Digestor;
use bio_loop::{create_membrane, Event};
use crossbeam_channel::{bounded, Sender};
use epoch_mmr::wal::WalStore;
use epoch_mmr::Mmr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

pub struct EpochSeal {
    pub epoch: u64,
    pub root: [u8; 32],
    pub leaf_count: u64,
}

pub struct ProvenanceBridge {
    #[allow(dead_code)]
    pub membrane_tx: Sender<Event>,
    digestor_handle: Option<thread::JoinHandle<()>>,
    mmr_handle: Option<thread::JoinHandle<()>>,
    running: Arc<AtomicBool>,
    mmr: Arc<Mutex<Mmr>>,
}

impl ProvenanceBridge {
    pub fn spawn(data_path: &Path) -> Self {
        let running = Arc::new(AtomicBool::new(true));

        let (membrane_tx, membrane_rx) = create_membrane();

        let (hash_tx, hash_rx) = bounded::<bio_loop::digest::MmrMessage>(1024);

        let mmr: Arc<Mutex<Mmr>> = Arc::new(Mutex::new(Mmr::new()));

        let wal_path = data_path.join("provenance.wal");
        let wal = WalStore::open(&wal_path).expect("open WAL");

        let recovered = wal.replay(&mmr).expect("WAL replay");
        if recovered > 0 {
            println!("Provenance WAL: recovered {recovered} records from disk");
        }

        let wal_c = Arc::new(wal);
        let running_d = Arc::clone(&running);
        let hash_tx_d = hash_tx.clone();
        let digestor_handle = thread::Builder::new()
            .name("bio-digestor".into())
            .spawn(move || {
                let mut digestor = Digestor::new(membrane_rx, running_d);
                digestor.set_hash_channel(hash_tx_d);
                digestor.run();
            })
            .expect("spawn bio-digestor thread");

        let mmr_c = Arc::clone(&mmr);
        let wal_m = Arc::clone(&wal_c);
        let mmr_handle = thread::Builder::new()
            .name("mmr-consumer".into())
            .spawn(move || {
                while let Ok(msg) = hash_rx.recv() {
                    if let bio_loop::digest::MmrMessage::Hash(hash) = msg {
                        let mut guard = mmr_c.lock().expect("mmr lock");
                        let idx = guard.leaf_count;
                        guard.append(hash);
                        let _ = wal_m.append_leaf(idx, &hash);
                    }
                }
            })
            .expect("spawn mmr-consumer thread");

        Self {
            membrane_tx,
            digestor_handle: Some(digestor_handle),
            mmr_handle: Some(mmr_handle),
            running,
            mmr,
        }
    }

    pub fn seal_current_epoch(&self) -> Option<EpochSeal> {
        let mut guard = self.mmr.lock().expect("mmr lock");
        if guard.leaf_count == 0 {
            return None;
        }
        let seal = guard.seal_epoch().ok()?;
        Some(EpochSeal {
            epoch: seal.epoch,
            root: seal.root,
            leaf_count: seal.leaf_count,
        })
    }
}

impl Drop for ProvenanceBridge {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.digestor_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.mmr_handle.take() {
            let _ = handle.join();
        }
    }
}
