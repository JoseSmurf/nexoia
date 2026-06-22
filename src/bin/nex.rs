#![allow(dead_code, unused_imports)]

#[path = "../hash.rs"]
mod hash;
#[path = "../network/mod.rs"]
mod network;
#[path = "../nex/mod.rs"]
mod nex;
#[path = "../provenance/mod.rs"]
mod provenance;
#[path = "../quality.rs"]
mod quality;
#[path = "../types.rs"]
mod types;

use serde::Serialize;
use std::error::Error;
use std::io;
use std::path::Path;

#[derive(Serialize)]
struct Output<'a> {
    nex_version: &'static str,
    nex_grammar_version: u32,
    program_hash: String,
    entries: &'a [nex::TraceEntry],
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "usage: nex <source-file>"))?;

    let input_path = Path::new(&path);
    let base_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
    let source = std::fs::read_to_string(input_path)?;
    let program = nex::parse(&source)?;
    let program = nex::expand_program(program, base_dir)?;
    let program_hash = nex::program_hash(&program);
    let execution = nex::execute(program)?;
    let output = Output {
        nex_version: nex::NEX_VERSION,
        nex_grammar_version: nex::NEX_GRAMMAR_VERSION,
        program_hash,
        entries: &execution.entries,
    };
    let output = serde_json::to_string_pretty(&output)?;
    println!("{output}");

    Ok(())
}
