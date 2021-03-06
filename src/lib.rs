use anyhow::{bail, Result};
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;

const BIP39_BITS: u32 = 11;
const BIP39_MASK: u32 = (1 << BIP39_BITS) - 1;

pub struct Bip39 {
    wordlist: Vec<String>,
    wordindex: HashMap<String, u32>,
}

impl Bip39 {
    pub fn new(words: &[String]) -> Result<Bip39> {
        if words.len() != (1 << BIP39_BITS) {
            bail!("Invalid wordlist length: {}", words.len());
        }
        let mut wordlist: Vec<String> = Vec::new();
        let mut wordindex: HashMap<String, u32> = HashMap::new();
        for (index, word) in words.iter().enumerate() {
            wordlist.push(word.to_string());
            wordindex.insert(word.to_string(), index as u32);
        }
        Ok(Bip39 {
            wordlist,
            wordindex,
        })
    }

    pub fn encode(self: &Bip39, data: &[u8]) -> Result<Vec<String>> {
        if !matches!(8 * data.len(), 128 | 160 | 192 | 224 | 256) {
            bail!("Invalid data length {} bits. BIP39 only works on 128, 160, 192, 224 and 256 source bits of data", 8 * data.len());
        }

        let mut result: Vec<String> = Vec::new();
        let num_words = match 8 * data.len() {
            128 => 12,
            160 => 15,
            192 => 18,
            224 => 21,
            256 => 24,
            _ => unreachable!("invalid wordlength"),
        };
        result.reserve(num_words);

        let mut hasher = Sha256::new();
        hasher.update(data);

        let checksum_bits: u32 = ((8 * data.len()) / 32).try_into().unwrap();
        let checksum: u32 = (hasher.finalize()[0] >> (8 - checksum_bits)).into();

        let mut accum: u32 = checksum;
        let mut bits: u32 = checksum_bits;

        for byte in data.iter().rev() {
            let mask = *byte as u32;
            accum |= mask << bits;
            bits += 8;
            while bits >= BIP39_BITS {
                let word = &self.wordlist[(accum & BIP39_MASK) as usize];
                result.push(word.clone());
                accum >>= BIP39_BITS;
                bits -= BIP39_BITS;
            }
        }

        result.reverse();
        Ok(result)
    }

    pub fn decode(self: &Bip39, encoded: &str) -> Result<Vec<u8>> {
        let words: Vec<&str> = encoded.split_ascii_whitespace().collect();
        if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
            bail!("Invalid word length {}. BIP39 mnemonics can only be 12, 15, 18, 21 or 24 words long.", words.len());
        }
        let mut result: Vec<u8> = Vec::new();
        let message_length = match words.len() {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            24 => 256,
            _ => unreachable!("invalid wordlength"),
        };
        result.reserve(message_length);
        let mut accum: u32 = 0;
        let mut bits: u32 = 0;
        let mut last_word = 0;
        for word in &words {
            let index = self.wordindex.get(*word);
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
                    accum |= 1 << (7 - bits);
                }
                bits += 1;
            }
        }
        let checksum_bits = message_length / 32;
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

#[cfg(test)]
mod test {
    use super::*;
    use std::io::BufRead;

    struct Case<'a> {
        source: &'a str,
        encoded: &'a str,
    }

    const TEST_VECTORS : &[Case<'static>] = &[Case {
        source: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        encoded: "legal winner thank year wave sausage worth useful legal winner thank yellow",
    }, Case {
        source: "00000000000000000000000000000000",
        encoded: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    }, Case {
        source: "80808080808080808080808080808080",
        encoded: "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    }, Case {
        source: "ffffffffffffffffffffffffffffffff",
        encoded: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    }, Case {
        source: "000000000000000000000000000000000000000000000000",
        encoded: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
    }, Case {
        source: "808080808080808080808080808080808080808080808080",
        encoded: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
    }, Case {
        source: "ffffffffffffffffffffffffffffffffffffffffffffffff",
        encoded: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
    }, Case {
        source: "0000000000000000000000000000000000000000000000000000000000000000",
        encoded: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    }, Case {
        source: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        encoded: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
    }, Case {
        source: "9e885d952ad362caeb4efe34a8e91bd2",
        encoded: "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
    }, Case {
        source: "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
        encoded: "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
    }, Case {
        source: "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        encoded: "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
    }, Case {
        source: "c0ba5a8e914111210f2bd131f3d5e08d",
        encoded: "scheme spot photo card baby mountain device kick cradle pact join borrow",
    },
    Case {
        source: "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
        encoded: "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
    },
    Case {
        source: "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        encoded: "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
    },
    Case {
        source: "23db8160a31d3e0dca3688ed941adbf3",
        encoded: "cat swing flag economy stadium alone churn speed unique patch report train",
    },
    Case {
        source: "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
        encoded: "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
    },
    Case {
        source: "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
        encoded: "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
    },
    Case {
        source: "f30f8c1da665478f49b001d94c5fc452",
        encoded: "vessel ladder alter error federal sibling chat ability sun glass valve picture",
    },
    Case {
        source: "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
        encoded: "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
    },
    Case {
        source: "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        encoded: "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
    }
        ];

    fn test_bip39() -> Result<Bip39> {
        let wordlist_filepath: std::path::PathBuf =
            [env!("CARGO_MANIFEST_DIR"), "resources/wordlist.txt"]
                .iter()
                .collect();
        let wordfile = std::fs::File::open(wordlist_filepath)?;
        let mut words: Vec<String> = Vec::new();
        for line in std::io::BufReader::new(wordfile).lines() {
            words.push(line?.trim().to_string());
        }
        Bip39::new(&words)
    }

    #[test]
    fn encodes() -> Result<()> {
        let bip39 = test_bip39()?;
        for test_vector in TEST_VECTORS {
            match test_vector {
                Case { source, encoded } => {
                    let input_as_bytes = hex::decode(source)?;
                    let result = bip39.encode(&input_as_bytes)?;
                    let output_as_words: Vec<String> = encoded
                        .split_ascii_whitespace()
                        .map(|s| s.to_string())
                        .collect();
                    assert_eq!(result, output_as_words);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn decodes() -> Result<()> {
        let bip39 = test_bip39()?;
        for test_vector in TEST_VECTORS {
            match test_vector {
                Case { source, encoded } => {
                    let result = hex::encode(bip39.decode(&encoded)?);
                    assert_eq!(result, source.to_string());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn validates_encoding() -> Result<()> {
        let bip39 = test_bip39()?;
        for source in ["", "ff", "ffffffffffffff", "ffffffffff"] {
            let input_as_bytes = hex::decode(source)?;
            let result = bip39.encode(&input_as_bytes);
            assert!(result.is_err());
        }
        Ok(())
    }

    #[test]
    fn validates_decoding() -> Result<()> {
        let bip39 = test_bip39()?;
        for encoded in [
            "",
            "foo bar baz",
            "source",
            "source rotate key bar",
            "adfkqkewjrkqwjre",
            "legal winner thank year wave sausage worth useful legal winner thank legal",
        ] {
            let result = bip39.decode(&encoded);
            assert!(result.is_err());
        }
        Ok(())
    }
}
