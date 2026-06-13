#![allow(dead_code, unused_imports)]

#[path = "../hash.rs"]
mod hash;
#[path = "../nex/mod.rs"]
mod nex;
#[path = "../provenance/mod.rs"]
mod provenance;
#[path = "../quality.rs"]
mod quality;

use std::error::Error;
use std::io;

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "usage: nex <source-file>"))?;

    let source = std::fs::read_to_string(&path)?;
    let program =
        nex::parse(&source).map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    let execution = nex::execute(program)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    let output = serde_json::to_string_pretty(&execution.entries)?;
    println!("{output}");

    Ok(())
}
