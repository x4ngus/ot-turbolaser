//! CRC-16/DNP for the DNP3 data link layer.
//!
//! Supplied by the `crc` crate catalog (poly 0x3d65, refin and refout, xorout
//! 0xffff, check 0xea82). DNP3 transmits the CRC low octet first.

use crc::{Crc, CRC_16_DNP};

const DNP3: Crc<u16> = Crc::<u16>::new(&CRC_16_DNP);

/// CRC-16/DNP over `data`.
pub fn dnp3(data: &[u8]) -> u16 {
    DNP3.checksum(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_catalog_check_value() {
        // The canonical CRC-16/DNP check value for ASCII "123456789".
        assert_eq!(dnp3(b"123456789"), 0xea82);
    }
}
