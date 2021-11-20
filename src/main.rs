use anyhow::{Context, Result};
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::io::stdin;
use std::process;

fn init(wordlist_filepath: &str) -> Result<bip39::Bip39> {
    let wordfile = fs::File::open(wordlist_filepath)?;
    let mut words: Vec<String> = Vec::new();
    for line in io::BufReader::new(wordfile).lines() {
        words.push(line?.trim().to_string());
    }
    bip39::Bip39::new(&words)
}

fn run(command: &str) -> Result<(), Box<dyn Error>> {
    let wordlist_filepath =
        env::var("BIP39_WORDLIST").unwrap_or_else(|_| "/opt/bip39/wordlist.txt".to_string());
    let bip39 =
        init(&wordlist_filepath).with_context(|| format!("reading file {}", wordlist_filepath))?;
    match command {
        "encode" => {
            let mut bytes: Vec<u8> = Vec::new();
            for byte in stdin().bytes() {
                bytes.push(byte?);
            }
            for word in bip39.encode(&bytes)? {
                print!("{} ", word);
            }
            Ok(())
        }
        "decode" => {
            let mut words = String::new();
            stdin().read_to_string(&mut words)?;
            let decoded = bip39.decode(&words)?;
            io::stdout().write_all(&decoded)?;
            Ok(())
        }
        _ => Err("Invalid command".into()),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Missing required parameter.\n\nUsage: {} (decode|encode)",
            args[0]
        );
        process::exit(1);
    }
    let command: &str = &args[1];
    if command != "encode" && command != "decode" {
        eprintln!(
            "Parameter must be 'encode' or 'decode'.\n\nUsage: {} (decode|encode)",
            args[0]
        );
    }
    if let Err(err) = run(command) {
        eprintln!("Could not execute {}: {:?}", command, err);
        process::exit(1)
    }
}
