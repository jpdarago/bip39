use anyhow::{bail, Result};
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;

pub struct Bip39 {
    pub wordlist: Vec<String>,
    pub wordindex: HashMap<String, u32>,
}

fn message_length_for_words(words: u32) -> u32 {
    return (words * BIP39_BITS / 32) * 32;
}

const BIP39_BITS: u32 = 11;
const BIP39_MASK: u32 = (1 << BIP39_BITS) - 1;

impl Bip39 {
    pub fn new(words: &[String]) -> Result<Bip39> {
        if words.len() != (1 << BIP39_BITS) {
            bail!("Invalid wordlist length: {}", words.len());
        }
        let mut wordlist: Vec<String> = Vec::new();
        let mut wordindex: HashMap<String, u32> = HashMap::new();
        let mut index = 0;
        for word in words {
            wordlist.push(word.to_string());
            wordindex.insert(word.to_string(), index);
            index += 1;
        }
        Ok(Bip39 {
            wordlist,
            wordindex,
        })
    }

    pub fn encode(self: &Bip39, data: &[u8]) -> Result<Vec<String>> {
        let mut total = 0;

        let mut result: Vec<String> = Vec::new();
        let mut hasher = Sha256::new();

        let mut bytes: Vec<u8> = Vec::new();
        for byte in data {
            total += 8;
            hasher.update([*byte]);
            bytes.push(*byte);
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

    pub fn decode(self: &Bip39, words: &str) -> Result<Vec<u8>> {
        let mut result: Vec<u8> = Vec::new();
        let mut accum: u32 = 0;
        let mut bits: u32 = 0;
        let mut num_words = 0;
        let mut last_word = 0;
        for word in words.split_ascii_whitespace() {
            num_words += 1;
            let index = self.wordindex.get(word);
            if index.is_none() {
                bail!("Unknown word {}", word);
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
        let checksum_bits = message_length_for_words(num_words) / 32;
        let checksum: u32 = last_word & ((1 << checksum_bits) - 1);
        let mut hasher = Sha256::new();
        hasher.update(&result);
        let result_checksum: u32 = (hasher.finalize()[0] >> (8 - checksum_bits)).into();
        if result_checksum != checksum {
            bail!("Invalid checksum!")
        } else {
            Ok(result)
        }
    }
}
