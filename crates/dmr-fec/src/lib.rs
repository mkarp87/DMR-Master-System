//! DMR Link Control encoding and payload rewriting.
//!
//! The BPTC/Hamming/RS layout follows the GPLv3 dmr_utils3 implementation
//! used by HBlink3, reimplemented here in Rust for the native routing path.

use thiserror::Error;

const LC_OPT_GROUP: [u8; 3] = [0x00, 0x00, 0x20];
const HEADER_MASK: [u8; 3] = [0x96, 0x96, 0x96];
const TERMINATOR_MASK: [u8; 3] = [0x99, 0x99, 0x99];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FecError {
    #[error("DMR payload must be exactly 33 bytes, got {0}")]
    InvalidPayloadLength(usize),
    #[error("talkgroup/source id must fit in 24 bits")]
    InvalidId,
}

fn byte_bits(byte: u8) -> [bool; 8] {
    [
        byte & 0x80 != 0,
        byte & 0x40 != 0,
        byte & 0x20 != 0,
        byte & 0x10 != 0,
        byte & 0x08 != 0,
        byte & 0x04 != 0,
        byte & 0x02 != 0,
        byte & 0x01 != 0,
    ]
}

fn bytes_to_bits(data: &[u8]) -> Vec<bool> {
    let mut out = Vec::with_capacity(data.len() * 8);
    for byte in data {
        out.extend(byte_bits(*byte));
    }
    out
}

fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bits.len().div_ceil(8));
    for chunk in bits.chunks(8) {
        let mut value = 0u8;
        for (i, bit) in chunk.iter().enumerate() {
            if *bit {
                value |= 0x80 >> i;
            }
        }
        out.push(value);
    }
    out
}

fn hamming_15_11(data: &[bool]) -> [bool; 4] {
    [
        data[0] ^ data[1] ^ data[2] ^ data[3] ^ data[5] ^ data[7] ^ data[8],
        data[1] ^ data[2] ^ data[3] ^ data[4] ^ data[6] ^ data[8] ^ data[9],
        data[2] ^ data[3] ^ data[4] ^ data[5] ^ data[7] ^ data[9] ^ data[10],
        data[0] ^ data[1] ^ data[2] ^ data[4] ^ data[6] ^ data[7] ^ data[10],
    ]
}

fn hamming_13_9(data: &[bool]) -> [bool; 4] {
    [
        data[0] ^ data[1] ^ data[3] ^ data[5] ^ data[6],
        data[0] ^ data[1] ^ data[2] ^ data[4] ^ data[6] ^ data[7],
        data[0] ^ data[1] ^ data[2] ^ data[3] ^ data[5] ^ data[7] ^ data[8],
        data[0] ^ data[2] ^ data[4] ^ data[5] ^ data[8],
    ]
}

fn hamming_16_11(data: &[bool]) -> [bool; 5] {
    [
        data[0] ^ data[1] ^ data[2] ^ data[3] ^ data[5] ^ data[7] ^ data[8],
        data[1] ^ data[2] ^ data[3] ^ data[4] ^ data[6] ^ data[8] ^ data[9],
        data[2] ^ data[3] ^ data[4] ^ data[5] ^ data[7] ^ data[9] ^ data[10],
        data[0] ^ data[1] ^ data[2] ^ data[4] ^ data[6] ^ data[7] ^ data[10],
        data[0] ^ data[2] ^ data[5] ^ data[6] ^ data[8] ^ data[9] ^ data[10],
    ]
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80 != 0;
        a <<= 1;
        if high {
            a ^= 0x1d; // primitive polynomial 0x11d with the x^8 bit removed
        }
        b >>= 1;
    }
    product
}

fn rs129(message: &[u8; 9], mask: [u8; 3]) -> [u8; 3] {
    let poly = [64u8, 56u8, 14u8];
    let mut parity = [0u8; 3];
    for byte in message {
        let dbyte = *byte ^ parity[2];
        parity[2] = parity[1] ^ gf_mul(poly[2], dbyte);
        parity[1] = parity[0] ^ gf_mul(poly[1], dbyte);
        parity[0] = gf_mul(poly[0], dbyte);
    }
    [
        parity[2] ^ mask[0],
        parity[1] ^ mask[1],
        parity[0] ^ mask[2],
    ]
}

fn encode_196_96(data: &[u8; 12]) -> Vec<bool> {
    let mut bits = bytes_to_bits(data);
    for _ in 0..4 {
        bits.insert(0, false);
    }

    for row in 0..9 {
        let start = row * 15 + 1;
        let end = start + 11;
        let parity = hamming_15_11(&bits[start..end]);
        for (offset, bit) in parity.iter().enumerate() {
            bits.insert(end + offset, *bit);
        }
    }

    bits.extend(std::iter::repeat(false).take(60));

    for col in 0..15 {
        let mut column = [false; 9];
        let mut pos = col + 1;
        for item in &mut column {
            *item = bits[pos];
            pos += 15;
        }
        let parity = hamming_13_9(&column);
        let mut pos = 136 + col;
        for bit in parity {
            bits[pos] = bit;
            pos += 15;
        }
    }

    bits
}

fn interleave_196_96(bits: &[bool]) -> Vec<bool> {
    let mut out = vec![false; 196];
    for (index, bit) in bits.iter().enumerate().take(196) {
        out[(index * 181) % 196] = *bit;
    }
    out
}

fn lc_word(destination: u32, source: u32) -> Result<[u8; 9], FecError> {
    if destination > 0x00ff_ffff || source > 0x00ff_ffff {
        return Err(FecError::InvalidId);
    }
    Ok([
        LC_OPT_GROUP[0],
        LC_OPT_GROUP[1],
        LC_OPT_GROUP[2],
        ((destination >> 16) & 0xff) as u8,
        ((destination >> 8) & 0xff) as u8,
        (destination & 0xff) as u8,
        ((source >> 16) & 0xff) as u8,
        ((source >> 8) & 0xff) as u8,
        (source & 0xff) as u8,
    ])
}

fn full_lc_bits(lc: &[u8; 9], terminator: bool) -> Vec<bool> {
    let parity = rs129(lc, if terminator { TERMINATOR_MASK } else { HEADER_MASK });
    let mut full = [0u8; 12];
    full[..9].copy_from_slice(lc);
    full[9..].copy_from_slice(&parity);
    interleave_196_96(&encode_196_96(&full))
}

fn csum5(lc: &[u8; 9]) -> [bool; 5] {
    let value = (lc.iter().map(|v| *v as u16).sum::<u16>() % 31) as u8;
    [
        value & 0x10 != 0,
        value & 0x08 != 0,
        value & 0x04 != 0,
        value & 0x02 != 0,
        value & 0x01 != 0,
    ]
}

fn embedded_lc(lc: &[u8; 9]) -> [[bool; 32]; 4] {
    let mut bits = bytes_to_bits(lc);
    let checksum = csum5(lc);
    for (index, bit) in [32usize, 43, 54, 65, 76].into_iter().zip(checksum) {
        bits.insert(index, bit);
    }

    for row in (0..112).step_by(16) {
        let parity = hamming_16_11(&bits[row..row + 11]);
        for (offset, bit) in parity.into_iter().enumerate() {
            bits.insert(row + 11 + offset, bit);
        }
    }

    for col in 0..16 {
        let parity = bits[col]
            ^ bits[col + 16]
            ^ bits[col + 32]
            ^ bits[col + 48]
            ^ bits[col + 64]
            ^ bits[col + 80]
            ^ bits[col + 96];
        bits.insert(col + 112, parity);
    }

    let mut segments = [[false; 32]; 4];
    for segment in 0..4 {
        for column in 0..4 {
            let source_column = segment * 4 + column;
            for row in 0..8 {
                segments[segment][column * 8 + row] = bits[source_column + row * 16];
            }
        }
    }
    segments
}

fn rewrite_bits(payload: &[u8], start: usize, replacement: &[bool]) -> Result<[u8; 33], FecError> {
    if payload.len() != 33 {
        return Err(FecError::InvalidPayloadLength(payload.len()));
    }
    let mut bits = bytes_to_bits(payload);
    bits[start..start + replacement.len()].copy_from_slice(replacement);
    let bytes = bits_to_bytes(&bits);
    let mut out = [0u8; 33];
    out.copy_from_slice(&bytes[..33]);
    Ok(out)
}

pub fn rewrite_group_voice_payload(
    payload: &[u8],
    frame_type: u8,
    data_type: u8,
    destination: u32,
    source: u32,
) -> Result<[u8; 33], FecError> {
    let lc = lc_word(destination, source)?;
    if frame_type == 2 && data_type == 1 {
        let encoded = full_lc_bits(&lc, false);
        let mut bits = bytes_to_bits(payload);
        if bits.len() != 264 {
            return Err(FecError::InvalidPayloadLength(payload.len()));
        }
        bits[..98].copy_from_slice(&encoded[..98]);
        bits[166..264].copy_from_slice(&encoded[98..196]);
        let bytes = bits_to_bytes(&bits);
        let mut out = [0u8; 33];
        out.copy_from_slice(&bytes[..33]);
        return Ok(out);
    }
    if frame_type == 2 && data_type == 2 {
        let encoded = full_lc_bits(&lc, true);
        let mut bits = bytes_to_bits(payload);
        if bits.len() != 264 {
            return Err(FecError::InvalidPayloadLength(payload.len()));
        }
        bits[..98].copy_from_slice(&encoded[..98]);
        bits[166..264].copy_from_slice(&encoded[98..196]);
        let bytes = bits_to_bytes(&bits);
        let mut out = [0u8; 33];
        out.copy_from_slice(&bytes[..33]);
        return Ok(out);
    }
    if (1..=4).contains(&data_type) {
        let embedded = embedded_lc(&lc);
        return rewrite_bits(payload, 116, &embedded[(data_type - 1) as usize]);
    }

    let mut out = [0u8; 33];
    if payload.len() != 33 {
        return Err(FecError::InvalidPayloadLength(payload.len()));
    }
    out.copy_from_slice(payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rs_header_validation_vector() {
        let lc = [0x00, 0x10, 0x20, 0x00, 0x0c, 0x30, 0x2f, 0x9b, 0xe5];
        assert_eq!(rs129(&lc, HEADER_MASK), [0xda, 0x4d, 0x5a]);
    }

    #[test]
    fn full_lc_has_196_bits() {
        let lc = lc_word(1001, 1_234_567).unwrap();
        assert_eq!(full_lc_bits(&lc, false).len(), 196);
    }

    #[test]
    fn embedded_lc_has_four_32_bit_segments() {
        let lc = lc_word(1001, 1_234_567).unwrap();
        let segments = embedded_lc(&lc);
        assert_eq!(segments.len(), 4);
        assert_eq!(segments[0].len(), 32);
    }

    #[test]
    fn payload_translation_changes_voice_header_but_preserves_sync_area() {
        let payload = [0x55u8; 33];
        let rewritten = rewrite_group_voice_payload(&payload, 2, 1, 2001, 1_234_567).unwrap();
        let before = bytes_to_bits(&payload);
        let after = bytes_to_bits(&rewritten);
        assert_ne!(&before[..98], &after[..98]);
        assert_eq!(&before[98..166], &after[98..166]);
    }
}

// -----------------------------------------------------------------------------
// Voice framing helpers used by native IPSC <-> Homebrew translation.
// These routines intentionally operate on encoded AMBE bits; they do not decode
// or synthesize speech.
// -----------------------------------------------------------------------------

const AMBE_RW: [usize; 36] = [
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2,
    0, 2, 0, 2, 0, 2, 0, 2,
];
const AMBE_RX: [usize; 36] = [
    23, 10, 22, 9, 21, 8, 20, 7, 19, 6, 18, 5, 17, 4, 16, 3, 15, 2, 14, 1, 13, 0, 12,
    10, 11, 9, 10, 8, 9, 7, 8, 6, 7, 5, 6, 4,
];
const AMBE_RY: [usize; 36] = [
    0, 2, 0, 2, 0, 2, 0, 2, 0, 3, 0, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3,
    1, 3, 1, 3, 1, 3, 1, 3,
];
const AMBE_RZ: [usize; 36] = [
    5, 3, 4, 2, 3, 1, 2, 0, 1, 13, 0, 12, 22, 11, 21, 10, 20, 9, 19, 8, 18, 7, 17, 6, 16,
    5, 15, 4, 14, 3, 13, 2, 12, 1, 11, 0,
];

const BS_VOICE_SYNC: [u8; 6] = [0x75, 0x5f, 0xd7, 0xdf, 0x75, 0xf7];
const BS_DATA_SYNC: [u8; 6] = [0xdf, 0xf5, 0x7d, 0x75, 0xdf, 0x5d];
const SLOT_TYPE_VOICE_HEAD: [bool; 20] = [
    false, false, false, true, false, false, false, true, true, false, true, true, true, false,
    false, false, true, true, false, false,
];
const SLOT_TYPE_VOICE_TERM: [bool; 20] = [
    false, false, false, true, false, false, true, false, true, false, true, false, false, true,
    false, true, true, false, false, true,
];
const EMB_B: u16 = 0x1391;
const EMB_C: u16 = 0x1774;
const EMB_D: u16 = 0x1774;
const EMB_E: u16 = 0x1507;
const EMB_F: u16 = 0x11e2;

fn golay_23_12(mut word: u32) -> u32 {
    const POLY: u32 = 0x0ae3;
    word &= 0x0fff;
    let data = word;
    for _ in 0..12 {
        if word & 1 != 0 {
            word ^= POLY;
        }
        word >>= 1;
    }
    (word << 12) | data
}

fn word_parity(mut word: u32) -> bool {
    let mut parity = false;
    while word != 0 {
        parity ^= word & 1 != 0;
        word >>= 1;
    }
    parity
}

fn demodulate_ambe(frame: &mut [[bool; 24]; 4]) {
    let mut seed = 0u32;
    for index in (12..=23).rev() {
        seed = (seed << 1) | frame[0][index] as u32;
    }
    let mut value = seed * 16;
    let mut pseudo = [false; 24];
    for item in pseudo.iter_mut().skip(1) {
        value = (173 * value + 13_849) & 0xffff;
        *item = value / 32_768 != 0;
    }
    for (offset, index) in (0..=22).rev().enumerate() {
        frame[1][index] ^= pseudo[offset + 1];
    }
}

/// Convert one raw 49-bit AMBE+2 vocoder frame to the 72-bit DMR on-air form.
pub fn ambe_49_to_72(input: &[bool; 49]) -> [bool; 72] {
    let mut frame = [[false; 24]; 4];

    let mut word = 0u32;
    for index in (0..=11).rev() {
        word = (word << 1) | input[index] as u32;
    }
    word = golay_23_12(word);
    word |= (word_parity(word) as u32) << 23;
    for index in (0..=23).rev() {
        frame[0][index] = word & 1 != 0;
        word >>= 1;
    }

    let mut word = 0u32;
    for index in (12..=23).rev() {
        word = (word << 1) | input[index] as u32;
    }
    word = golay_23_12(word);
    for index in (0..=22).rev() {
        frame[1][index] = word & 1 != 0;
        word >>= 1;
    }

    for index in (0..=10).rev() {
        frame[2][index] = input[34 - index];
    }
    for index in (0..=13).rev() {
        frame[3][index] = input[48 - index];
    }

    demodulate_ambe(&mut frame);
    let mut out = [false; 72];
    for index in 0..36 {
        out[index * 2] = frame[AMBE_RW[index]][AMBE_RX[index]];
        out[index * 2 + 1] = frame[AMBE_RY[index]][AMBE_RZ[index]];
    }
    out
}

/// Convert one 72-bit DMR AMBE+2 frame to the raw 49-bit vocoder form.
pub fn ambe_72_to_49(input: &[bool; 72]) -> [bool; 49] {
    let mut frame = [[false; 24]; 4];
    for index in 0..36 {
        frame[AMBE_RW[index]][AMBE_RX[index]] = input[index * 2];
        frame[AMBE_RY[index]][AMBE_RZ[index]] = input[index * 2 + 1];
    }
    demodulate_ambe(&mut frame);

    let mut out = [false; 49];
    let mut at = 0;
    for index in (12..=23).rev() {
        out[at] = frame[0][index];
        at += 1;
    }
    for index in (11..=22).rev() {
        out[at] = frame[1][index];
        at += 1;
    }
    for index in (0..=10).rev() {
        out[at] = frame[2][index];
        at += 1;
    }
    for index in (0..=13).rev() {
        out[at] = frame[3][index];
        at += 1;
    }
    out
}

fn bits_to_fixed<const N: usize>(bits: &[bool]) -> [u8; N] {
    let bytes = bits_to_bytes(bits);
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[..N]);
    out
}

fn u16_bits(value: u16) -> [bool; 16] {
    let mut out = [false; 16];
    for (index, item) in out.iter_mut().enumerate() {
        *item = value & (1 << (15 - index)) != 0;
    }
    out
}

/// Return the four 32-bit embedded-LC fragments carried by bursts B-E.
pub fn group_embedded_lc(destination: u32, source: u32) -> Result<[[u8; 4]; 4], FecError> {
    let lc = lc_word(destination, source)?;
    let segments = embedded_lc(&lc);
    let mut out = [[0u8; 4]; 4];
    for (index, segment) in segments.iter().enumerate() {
        out[index] = bits_to_fixed::<4>(segment);
    }
    Ok(out)
}

/// Return the RS(12,9) parity bytes used in an IPSC voice header/terminator.
pub fn group_lc_parity(destination: u32, source: u32, terminator: bool) -> Result<[u8; 3], FecError> {
    let lc = lc_word(destination, source)?;
    Ok(rs129(&lc, if terminator { TERMINATOR_MASK } else { HEADER_MASK }))
}

/// Return the 9-byte Group Voice Link Control word.
pub fn group_lc(destination: u32, source: u32) -> Result<[u8; 9], FecError> {
    lc_word(destination, source)
}

/// Construct a complete 33-byte DMR voice header or terminator payload (CC=1).
pub fn build_group_voice_lc_payload(destination: u32, source: u32, terminator: bool) -> Result<[u8; 33], FecError> {
    let lc = lc_word(destination, source)?;
    let encoded = full_lc_bits(&lc, terminator);
    let slot = if terminator { SLOT_TYPE_VOICE_TERM } else { SLOT_TYPE_VOICE_HEAD };
    let sync = bytes_to_bits(&BS_DATA_SYNC);
    let mut bits = Vec::with_capacity(264);
    bits.extend_from_slice(&encoded[..98]);
    bits.extend_from_slice(&slot[..10]);
    bits.extend_from_slice(&sync);
    bits.extend_from_slice(&slot[10..]);
    bits.extend_from_slice(&encoded[98..]);
    Ok(bits_to_fixed::<33>(&bits))
}

/// Extract the three AMBE frames from a DMR voice burst into the 19-byte IPSC
/// layout (49 bits + pad, 49 bits + pad, 49 bits + three pad bits).
pub fn extract_ipsc_ambe(payload: &[u8; 33]) -> [u8; 19] {
    let bits = bytes_to_bits(payload);
    let mut first72 = [false; 72];
    let mut second72 = [false; 72];
    let mut third72 = [false; 72];
    first72.copy_from_slice(&bits[..72]);
    second72[..36].copy_from_slice(&bits[72..108]);
    second72[36..].copy_from_slice(&bits[156..192]);
    third72.copy_from_slice(&bits[192..264]);

    let first49 = ambe_72_to_49(&first72);
    let second49 = ambe_72_to_49(&second72);
    let third49 = ambe_72_to_49(&third72);
    let mut packed = [false; 152];
    packed[..49].copy_from_slice(&first49);
    packed[50..99].copy_from_slice(&second49);
    packed[100..149].copy_from_slice(&third49);
    bits_to_fixed::<19>(&packed)
}

/// Build a 33-byte DMR voice burst from the 19-byte IPSC AMBE payload and a
/// superframe position 0..5 (A..F). Embedded LC is regenerated from src/dst.
pub fn build_group_voice_burst(
    ambe: &[u8; 19],
    position: u8,
    destination: u32,
    source: u32,
) -> Result<[u8; 33], FecError> {
    let packed = bytes_to_bits(ambe);
    let mut first49 = [false; 49];
    let mut second49 = [false; 49];
    let mut third49 = [false; 49];
    first49.copy_from_slice(&packed[..49]);
    second49.copy_from_slice(&packed[50..99]);
    third49.copy_from_slice(&packed[100..149]);
    let first72 = ambe_49_to_72(&first49);
    let second72 = ambe_49_to_72(&second49);
    let third72 = ambe_49_to_72(&third49);

    let position = position % 6;
    let mut embed = [false; 48];
    if position == 0 {
        embed.copy_from_slice(&bytes_to_bits(&BS_VOICE_SYNC));
    } else {
        let emb_word = match position {
            1 => EMB_B,
            2 => EMB_C,
            3 => EMB_D,
            4 => EMB_E,
            _ => EMB_F,
        };
        let emb_bits = u16_bits(emb_word);
        embed[..8].copy_from_slice(&emb_bits[..8]);
        embed[40..].copy_from_slice(&emb_bits[8..]);
        if position <= 4 {
            let segments = group_embedded_lc(destination, source)?;
            embed[8..40].copy_from_slice(&bytes_to_bits(&segments[(position - 1) as usize]));
        }
    }

    let mut out = Vec::with_capacity(264);
    out.extend_from_slice(&first72);
    out.extend_from_slice(&second72[..36]);
    out.extend_from_slice(&embed);
    out.extend_from_slice(&second72[36..]);
    out.extend_from_slice(&third72);
    Ok(bits_to_fixed::<33>(&out))
}

/// Pre-built three-frame AMBE silence in IPSC's 19-byte packed form.
pub fn ipsc_ambe_silence() -> [u8; 19] {
    let silence = [0xac, 0xaa, 0x40, 0x20, 0x00, 0x44, 0x40, 0x80, 0x80];
    let silence_bits = bytes_to_bits(&silence);
    let mut frame72 = [false; 72];
    frame72.copy_from_slice(&silence_bits);
    let frame49 = ambe_72_to_49(&frame72);
    let mut packed = [false; 152];
    packed[..49].copy_from_slice(&frame49);
    packed[50..99].copy_from_slice(&frame49);
    packed[100..149].copy_from_slice(&frame49);
    bits_to_fixed::<19>(&packed)
}

#[cfg(test)]
mod voice_tests {
    use super::*;

    #[test]
    fn ambe_49_72_round_trip() {
        let mut source = [false; 49];
        for (index, bit) in source.iter_mut().enumerate() {
            *bit = index % 3 == 0 || index % 7 == 0;
        }
        let encoded = ambe_49_to_72(&source);
        assert_eq!(ambe_72_to_49(&encoded), source);
    }

    #[test]
    fn ipsc_ambe_round_trip_preserves_voice_bits() {
        let mut payload = [0u8; 33];
        let ambe = ipsc_ambe_silence();
        payload.copy_from_slice(&build_group_voice_burst(&ambe, 0, 1001, 1_234_567).unwrap());
        assert_eq!(extract_ipsc_ambe(&payload), ambe);
    }

    #[test]
    fn header_and_term_are_complete_dmr_payloads() {
        let header = build_group_voice_lc_payload(1001, 1_234_567, false).unwrap();
        let term = build_group_voice_lc_payload(1001, 1_234_567, true).unwrap();
        assert_ne!(header, term);
        let header_bits = bytes_to_bits(&header);
        assert_eq!(&header_bits[108..156], bytes_to_bits(&BS_DATA_SYNC).as_slice());
    }
}
