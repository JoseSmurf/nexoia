use crossbeam_channel::{Receiver, Sender};
use epoch_mmr::EpochSeal;
use std::thread;

use crate::{ProverEngine, StubProver};

pub enum ProverCommand {
    Seal(EpochSeal),
    Shutdown,
}

pub struct ZkWorker {
    command_rx: Receiver<ProverCommand>,
    proof_tx: Sender<crate::ZkProof>,
}

impl ZkWorker {
    pub fn spawn(
        command_rx: Receiver<ProverCommand>,
        proof_tx: Sender<crate::ZkProof>,
    ) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("zk-prover".into())
            .spawn(move || {
                let mut worker = Self {
                    command_rx,
                    proof_tx,
                };
                worker.run();
            })
            .expect("falha ao iniciar thread do zk_prover")
    }

    fn run(&mut self) {
        let mut engine = StubProver::new();

        while let Ok(cmd) = self.command_rx.recv() {
            match cmd {
                ProverCommand::Seal(seal) => {
                    let result = engine.consolidate(seal);
                    if result.ready_to_prove {
                        println!(
                            "\x1b[33m[ZK] Época {} consolidada e pronta para prova no Prover Engine.\x1b[0m",
                            result.epoch
                        );

                        // Generate a stub proof for the epoch root
                        let statement = crate::ZkStatement {
                            epoch_root: result.root,
                            leaf_index: 0,
                            epoch: result.epoch,
                            is_nullified: false,
                        };
                        let proof_bytes = crate::derive_stub_commitment(&statement);
                        let proof = crate::ZkProof {
                            statement,
                            proof_bytes,
                            is_stub: true,
                        };
                        let _ = self.proof_tx.try_send(proof);
                    }
                }
                ProverCommand::Shutdown => {
                    break;
                }
            }
        }
    }
}
