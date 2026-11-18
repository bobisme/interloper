//! Hex digests for the keys and ids backends derive: an inbox keyed by the
//! md5 of its address, a message id cut from a SHA prefix.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn prefix(mut h: String, len: usize) -> String {
    h.truncate(len);
    h
}

/// MD5 as 32 lowercase hex digits.
pub fn md5_hex(input: &[u8]) -> String {
    hex(&Md5::digest(input))
}

/// The first `len` lowercase hex digits of SHA-1 (all 40 when `len` is
/// larger).
pub fn sha1_hex(input: &[u8], len: usize) -> String {
    prefix(hex(&Sha1::digest(input)), len)
}

/// The first `len` lowercase hex digits of SHA-256 (all 64 when `len` is
/// larger).
pub fn sha256_hex(input: &[u8], len: usize) -> String {
    prefix(hex(&Sha256::digest(input)), len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_the_rfc_1321_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn sha_prefixes_match_the_fips_vectors() {
        assert_eq!(sha1_hex(b"abc", 16), "a9993e364706816a");
        assert_eq!(
            sha1_hex(b"abc", 99),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(sha256_hex(b"abc", 16), "ba7816bf8f01cfea");
        assert_eq!(sha256_hex(b"abc", 64).len(), 64);
    }
}
