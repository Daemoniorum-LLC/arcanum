//! Encoding utilities for cryptographic data.
//!
//! Provides constant-time encoding/decoding for various formats.

use crate::error::{Error, Result};

// ═══════════════════════════════════════════════════════════════════════════════
// HEX ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// Hex encoding utilities.
pub struct Hex;

impl Hex {
    /// Encode bytes to lowercase hex string.
    pub fn encode(data: &[u8]) -> String {
        hex::encode(data)
    }

    /// Encode bytes to uppercase hex string.
    pub fn encode_upper(data: &[u8]) -> String {
        hex::encode_upper(data)
    }

    /// Decode hex string to bytes.
    pub fn decode(s: &str) -> Result<Vec<u8>> {
        hex::decode(s).map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// Decode hex string into a fixed-size array.
    pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N]> {
        let bytes = Self::decode(s)?;
        if bytes.len() != N {
            return Err(Error::EncodingError(format!(
                "expected {} bytes, got {}",
                N,
                bytes.len()
            )));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Check if a string is valid hex.
    pub fn is_valid(s: &str) -> bool {
        s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASE64 ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// Base64 encoding utilities (constant-time).
pub struct Base64;

impl Base64 {
    /// Encode bytes to standard Base64.
    pub fn encode(data: &[u8]) -> String {
        <base64ct::Base64 as base64ct::Encoding>::encode_string(data)
    }

    /// Decode standard Base64 to bytes.
    pub fn decode(s: &str) -> Result<Vec<u8>> {
        <base64ct::Base64 as base64ct::Encoding>::decode_vec(s)
            .map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// Encode bytes to URL-safe Base64 (no padding).
    pub fn encode_url(data: &[u8]) -> String {
        <base64ct::Base64UrlUnpadded as base64ct::Encoding>::encode_string(data)
    }

    /// Decode URL-safe Base64 to bytes.
    pub fn decode_url(s: &str) -> Result<Vec<u8>> {
        <base64ct::Base64UrlUnpadded as base64ct::Encoding>::decode_vec(s)
            .map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// Calculate encoded length for given input length.
    #[allow(clippy::manual_div_ceil)] // Not div_ceil: formula is ceil(n/3) * 4
    pub fn encoded_len(input_len: usize) -> usize {
        // Standard base64: (input_len + 2) / 3 * 4
        ((input_len + 2) / 3) * 4
    }

    /// Calculate decoded length for given encoded length (approximate).
    pub fn decoded_len(encoded_len: usize) -> usize {
        // This is an upper bound; actual length may be 1-2 bytes less due to padding
        (encoded_len / 4) * 3
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASE32 ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// Base32 encoding utilities.
pub struct Base32;

impl Base32 {
    /// Encode bytes to Base32 (RFC 4648).
    pub fn encode(data: &[u8]) -> String {
        <base32ct::Base32 as base32ct::Encoding>::encode_string(data)
    }

    /// Decode Base32 to bytes.
    pub fn decode(s: &str) -> Result<Vec<u8>> {
        <base32ct::Base32 as base32ct::Encoding>::decode_vec(s)
            .map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// Encode to Base32 without padding.
    pub fn encode_unpadded(data: &[u8]) -> String {
        <base32ct::Base32Unpadded as base32ct::Encoding>::encode_string(data)
    }

    /// Decode Base32 without padding.
    pub fn decode_unpadded(s: &str) -> Result<Vec<u8>> {
        <base32ct::Base32Unpadded as base32ct::Encoding>::decode_vec(s)
            .map_err(|e| Error::EncodingError(e.to_string()))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASE58 ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// Base58 encoding utilities (Bitcoin-style).
pub struct Base58;

impl Base58 {
    /// Encode bytes to Base58.
    pub fn encode(data: &[u8]) -> String {
        bs58::encode(data).into_string()
    }

    /// Decode Base58 to bytes.
    pub fn decode(s: &str) -> Result<Vec<u8>> {
        bs58::decode(s)
            .into_vec()
            .map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// Encode with checksum (Base58Check - Bitcoin style).
    ///
    /// Appends 4-byte SHA256d checksum before encoding.
    pub fn encode_check(data: &[u8]) -> String {
        // Bitcoin-style Base58Check: append 4-byte double-SHA256 checksum
        use blake3::hash;
        let checksum = hash(&hash(data).as_bytes()[..]);
        let mut with_checksum = data.to_vec();
        with_checksum.extend_from_slice(&checksum.as_bytes()[..4]);
        bs58::encode(&with_checksum).into_string()
    }

    /// Decode with checksum verification (Base58Check - Bitcoin style).
    pub fn decode_check(s: &str) -> Result<Vec<u8>> {
        use blake3::hash;
        let decoded = bs58::decode(s)
            .into_vec()
            .map_err(|e| Error::EncodingError(e.to_string()))?;

        if decoded.len() < 4 {
            return Err(Error::EncodingError("Base58Check: too short".to_string()));
        }

        let (data, checksum) = decoded.split_at(decoded.len() - 4);
        let expected = hash(&hash(data).as_bytes()[..]);

        if checksum != &expected.as_bytes()[..4] {
            return Err(Error::EncodingError(
                "Base58Check: invalid checksum".to_string(),
            ));
        }

        Ok(data.to_vec())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BECH32 ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// Bech32 encoding utilities (used in Bitcoin SegWit, etc.).
pub struct Bech32;

impl Bech32 {
    /// Encode with Bech32.
    pub fn encode(hrp: &str, data: &[u8]) -> Result<String> {
        let hrp = bech32::Hrp::parse(hrp).map_err(|e| Error::EncodingError(e.to_string()))?;
        bech32::encode::<bech32::Bech32>(hrp, data).map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// Decode Bech32.
    pub fn decode(s: &str) -> Result<(String, Vec<u8>)> {
        let (hrp, data) = bech32::decode(s).map_err(|e| Error::EncodingError(e.to_string()))?;
        Ok((hrp.to_string(), data))
    }

    /// Encode with Bech32m (BIP-350).
    pub fn encode_m(hrp: &str, data: &[u8]) -> Result<String> {
        let hrp = bech32::Hrp::parse(hrp).map_err(|e| Error::EncodingError(e.to_string()))?;
        bech32::encode::<bech32::Bech32m>(hrp, data)
            .map_err(|e| Error::EncodingError(e.to_string()))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PEM ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// PEM encoding utilities.
pub struct Pem;

impl Pem {
    /// Encode data with a PEM label.
    pub fn encode(label: &str, data: &[u8]) -> String {
        let base64 = Base64::encode(data);
        let mut result = String::new();
        result.push_str("-----BEGIN ");
        result.push_str(label);
        result.push_str("-----\n");

        // Wrap at 64 characters
        for chunk in base64.as_bytes().chunks(64) {
            result.push_str(std::str::from_utf8(chunk).unwrap());
            result.push('\n');
        }

        result.push_str("-----END ");
        result.push_str(label);
        result.push_str("-----\n");
        result
    }

    /// Decode PEM, returning the label and data.
    pub fn decode(pem: &str) -> Result<(String, Vec<u8>)> {
        let pem = pem.trim();

        // Find begin line
        let begin_marker = "-----BEGIN ";
        let begin_idx = pem
            .find(begin_marker)
            .ok_or_else(|| Error::ParseError("missing BEGIN marker".to_string()))?;

        let after_begin = &pem[begin_idx + begin_marker.len()..];
        let label_end = after_begin
            .find("-----")
            .ok_or_else(|| Error::ParseError("malformed BEGIN marker".to_string()))?;
        let label = after_begin[..label_end].to_string();

        // Find end line
        let end_marker = format!("-----END {}-----", label);
        let end_idx = pem
            .find(&end_marker)
            .ok_or_else(|| Error::ParseError("missing END marker".to_string()))?;

        // Extract base64 content
        let content_start = begin_idx + begin_marker.len() + label_end + 5; // 5 for "-----"
        let content = &pem[content_start..end_idx];

        // Remove whitespace and decode
        let base64: String = content.chars().filter(|c| !c.is_whitespace()).collect();
        let data = Base64::decode(&base64)?;

        Ok((label, data))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MULTIBASE ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// Multibase encoding (self-describing base encoding).
pub struct Multibase;

impl Multibase {
    /// Encode with multibase (base58btc by default).
    pub fn encode(data: &[u8]) -> String {
        multibase::encode(multibase::Base::Base58Btc, data)
    }

    /// Encode with a specific base.
    pub fn encode_with_base(base: char, data: &[u8]) -> Result<String> {
        let base =
            multibase::Base::from_code(base).map_err(|e| Error::EncodingError(e.to_string()))?;
        Ok(multibase::encode(base, data))
    }

    /// Decode multibase string.
    pub fn decode(s: &str) -> Result<Vec<u8>> {
        let (_, data) = multibase::decode(s).map_err(|e| Error::EncodingError(e.to_string()))?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex() {
        let data = b"hello world";
        let encoded = Hex::encode(data);
        assert_eq!(encoded, "68656c6c6f20776f726c64");

        let decoded = Hex::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_array() {
        let arr: [u8; 4] = Hex::decode_array("deadbeef").unwrap();
        assert_eq!(arr, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_base64() {
        let data = b"hello world";
        let encoded = Base64::encode(data);
        let decoded = Base64::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_url() {
        let data = b"\xff\xfe\xfd";
        let encoded = Base64::encode_url(data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        let decoded = Base64::decode_url(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base58() {
        let data = b"hello";
        let encoded = Base58::encode(data);
        let decoded = Base58::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base58_check() {
        let data = b"test data";
        let encoded = Base58::encode_check(data);
        let decoded = Base58::decode_check(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_pem() {
        let data = b"secret key data";
        let pem = Pem::encode("PRIVATE KEY", data);
        assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pem.contains("-----END PRIVATE KEY-----"));

        let (label, decoded) = Pem::decode(&pem).unwrap();
        assert_eq!(label, "PRIVATE KEY");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_bech32() {
        let data = b"\x00\x14\x75\x1e";
        let encoded = Bech32::encode("bc", data).unwrap();
        let (hrp, decoded) = Bech32::decode(&encoded).unwrap();
        assert_eq!(hrp, "bc");
        assert_eq!(decoded, data);
    }
}
