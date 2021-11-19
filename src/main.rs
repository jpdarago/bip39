use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::error;
use std::fs::File;
use std::io::prelude::*;
use std::io::stdin;
use std::io::{self, BufRead};
use std::primitive::u8;
use std::process;

const BIP39_BITS: u32 = 11;
const BIP39_MASK: u32 = (1 << BIP39_BITS) - 1;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

struct Bip39 {
    pub wordlist: Vec<String>,
    pub wordindex: HashMap<String, u32>,
}

fn message_length_for_words(words: u32) -> u32 {
    return (words * BIP39_BITS / 32) * 32;
}

impl Bip39 {
    fn new(wordlist_filepath: &str) -> Result<Bip39> {
        let mut wordlist: Vec<String> = Vec::new();
        let mut wordindex: HashMap<String, u32> = HashMap::new();
        let wordfile = File::open(wordlist_filepath)?;
        let mut index = 0;
        for line in io::BufReader::new(wordfile).lines() {
            let word = line?.trim().to_string();
            wordlist.push(word.clone());
            wordindex.insert(word.clone(), index);
            index += 1;
        }
        // Bip39 wordlist must be 2048 entries.
        if wordlist.len() != (1 << BIP39_BITS) {
            Err(format!("Invalid wordlist length {}", wordlist.len()).into())
        } else {
            Ok(Bip39 {
                wordlist,
                wordindex,
            })
        }
    }

    fn encode(self: &Bip39) -> Result<Vec<String>> {
        let mut total = 0;

        let mut result: Vec<String> = Vec::new();
        let mut hasher = Sha256::new();

        let mut bytes: Vec<u8> = Vec::new();
        for b in stdin().bytes() {
            let byte = b?;
            total += 8;
            hasher.update([byte]);
            bytes.push(byte);
        }
        bytes.reverse();

        let checksum_bits = total / 32;
        let checksum: u32 = (hasher.finalize()[0] >> (8 - checksum_bits)).into();

        let mut accum: u32 = checksum;
        let mut bits: u32 = checksum_bits;

        for byte in bytes {
            let mask = byte as u32;
            accum = accum | (mask << bits);
            bits += 8;
            while bits >= BIP39_BITS {
                let word = &self.wordlist[(accum & BIP39_MASK) as usize];
                result.push(word.clone());
                accum = accum >> BIP39_BITS;
                bits -= BIP39_BITS;
            }
        }

        result.reverse();
        Ok(result)
    }

    fn decode(self: &Bip39) -> Result<Vec<u8>> {
        let mut buffer = String::new();
        let _ = stdin().read_to_string(&mut buffer)?;
        let mut result: Vec<u8> = Vec::new();
        let mut accum: u32 = 0;
        let mut bits: u32 = 0;
        let mut words = 0;
        let mut last_word = 0;
        for word in buffer.split_ascii_whitespace() {
            words += 1;
            let index = self.wordindex.get(word);
            if index.is_none() {
                return Err(format!("Unknown word {}", word).into());
            }
            let num: u32 = *index.unwrap();
            last_word = num;
            for i in 0..BIP39_BITS {
                if bits == 8 {
                    result.push(accum as u8);
                    accum = 0;
                    bits = 0;
                }
                if num & (1 << (BIP39_BITS - 1 - i)) > 0 {
                    accum = accum | (1 << (7 - bits));
                }
                bits += 1;
            }
        }
        let checksum_bits = message_length_for_words(words) / 32;
        let checksum: u32 = last_word & ((1 << checksum_bits) - 1);
        let mut hasher = Sha256::new();
        hasher.update(&result);
        let result_checksum: u32 = (hasher.finalize()[0] >> (8 - checksum_bits)).into();
        if result_checksum != checksum {
            Err("Invalid checksum!".into())
        } else {
            Ok(result)
        }
    }
}

fn run(command: &str) -> Result<()> {
    let wordlist_filepath = env::var("BIP39_WORDLIST").unwrap_or("/tmp/wordlist.txt".to_string());
    let bip39 = Bip39::new(&wordlist_filepath)?;
    match command {
        "encode" => {
            let mut words = 0;
            for word in bip39.encode()? {
                if words == 4 {
                    print!("\n");
                    words = 0;
                }
                print!("{} ", word);
                words += 1;
            }
            Ok(())
        }
        "decode" => {
            let bytes = bip39.decode()?;
            io::stdout().write(&bytes)?;
            Ok(())
        }
        _ => Err("Invalid comand".into()),
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
        eprintln!("Could not {}: {}", command, err);
        process::exit(1);
    }
}
