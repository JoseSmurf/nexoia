#![allow(dead_code, unused_imports, clippy::upper_case_acronyms)]

#[path = "../decision.rs"]
mod decision;
#[path = "../defense.rs"]
mod defense;
#[path = "../evidence.rs"]
mod evidence;
#[path = "../hash.rs"]
mod hash;
#[path = "../lgpd.rs"]
mod lgpd;
#[path = "../lgpd_rights.rs"]
mod lgpd_rights;
#[path = "../limits.rs"]
mod limits;
#[path = "../network/mod.rs"]
mod network;
#[path = "../nex/mod.rs"]
mod nex;
#[path = "../provenance/mod.rs"]
mod provenance;
#[path = "../quality.rs"]
mod quality;
#[path = "../state.rs"]
mod state;
#[path = "../types.rs"]
mod types;

use std::error::Error;
use std::io;

fn main() -> Result<(), Box<dyn Error>> {
    let root = std::env::args().nth(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "usage: verify <artifact-dir>")
    })?;

    let report = provenance::verify::run(root).map_err(|err| io::Error::other(err.to_string()))?;
    let output = serde_json::to_string_pretty(&report)?;
    println!("{output}");

    Ok(())
}
