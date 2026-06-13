#![allow(dead_code, unused_imports)]

#[path = "../decision.rs"]
mod decision;
#[path = "../evidence.rs"]
mod evidence;
#[path = "../hash.rs"]
mod hash;
#[path = "../provenance/mod.rs"]
mod provenance;
#[path = "../quality.rs"]
mod quality;
#[path = "../state.rs"]
mod state;
#[path = "../provenance/verify.rs"]
mod verify_core;

use std::error::Error;
use std::io;

fn main() -> Result<(), Box<dyn Error>> {
    let root = std::env::args().nth(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "usage: verify <artifact-dir>")
    })?;

    let report = verify_core::run(root)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    let output = serde_json::to_string_pretty(&report)?;
    println!("{output}");

    Ok(())
}
