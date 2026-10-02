//! Minimal block header parsing.
//!
//! Honeybee trusts its own Electrum server, so headers are never validated;
//! only the block time is read. Two layouts are accepted:
//!
//! * the legacy 80-byte header, and
//! * the 164-byte "v2" header of the Bitcoin Knots BLAKE2b proof-of-work
//!   hardfork (bitcoinknots/bitcoin#359), served by the `blake2b` branch of
//!   jasonsopko/electrs. It is flagged by the top bit of the version field,
//!   and its block time may be stored on the wire minus `time_offset`.

pub const HEADER_V1_SIZE: usize = 80;
pub const HEADER_V2_SIZE: usize = 164;

const VERSION_HEADER_V2_FLAG: u32 = 0x8000_0000;
const FLAG_USE_TIME_OFFSET: u8 = 4;

// Offsets of the v2 fields that follow the legacy 80 bytes:
// nonce2 (4) nonce3 (4) extranonce (16) time_offset (4) txcount (2) flags (1) ...
const TIME_OFFSET_POS: usize = 104;
const FLAGS_POS: usize = 110;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderInfo {
    /// Block time in seconds since the epoch.
    pub time: u32,
    /// Whether this is a BLAKE2b (v2) header.
    pub v2: bool,
}

fn le_u32(b: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes(b[pos..pos + 4].try_into().expect("4 bytes"))
}

pub fn parse(header: &[u8]) -> Option<HeaderInfo> {
    if header.len() < HEADER_V1_SIZE {
        return None;
    }
    let version = le_u32(header, 0);
    let mut time = le_u32(header, 68);
    let v2 = version & VERSION_HEADER_V2_FLAG != 0;
    if v2 {
        if header.len() < HEADER_V2_SIZE {
            return None;
        }
        if header[FLAGS_POS] & FLAG_USE_TIME_OFFSET != 0 {
            time = time.wrapping_add(le_u32(header, TIME_OFFSET_POS));
        }
    }
    Some(HeaderInfo { time, v2 })
}

pub fn parse_hex(hex_str: &str) -> Option<HeaderInfo> {
    parse(&hex::decode(hex_str).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mainnet block 1.
    const BLOCK1: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";

    fn v2_header(wire_time: u32, time_offset: u32, flags: u8) -> Vec<u8> {
        let mut h = vec![0u8; HEADER_V2_SIZE];
        h[0..4].copy_from_slice(&(0x2000_0000u32 | VERSION_HEADER_V2_FLAG).to_le_bytes());
        h[68..72].copy_from_slice(&wire_time.to_le_bytes());
        h[TIME_OFFSET_POS..TIME_OFFSET_POS + 4].copy_from_slice(&time_offset.to_le_bytes());
        h[FLAGS_POS] = flags;
        h
    }

    #[test]
    fn legacy_header() {
        let info = parse_hex(BLOCK1).unwrap();
        assert_eq!(info, HeaderInfo { time: 1231469665, v2: false });
    }

    #[test]
    fn v2_header_without_time_offset() {
        let info = parse(&v2_header(1_790_000_000, 1234, 0)).unwrap();
        assert_eq!(info, HeaderInfo { time: 1_790_000_000, v2: true });
    }

    #[test]
    fn v2_header_with_time_offset() {
        let info = parse(&v2_header(1_790_000_000 - 1234, 1234, FLAG_USE_TIME_OFFSET | 1)).unwrap();
        assert_eq!(info, HeaderInfo { time: 1_790_000_000, v2: true });
    }

    #[test]
    fn truncated_headers_rejected() {
        assert!(parse(&[0u8; 79]).is_none());
        assert!(parse(&v2_header(1, 0, 0)[..HEADER_V1_SIZE]).is_none());
    }
}
