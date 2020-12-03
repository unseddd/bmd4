/* derived from the RSA Data Security, Inc.
 * MD4 Message-Digest Algorithm
 *
 * See [RFC-1320](docs/rfc1320-md4.txt) and [LICENSE](LICENSE) for full license information
 */

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use core::convert::TryInto;

/// Length of the MD4 digest in bytes
pub const DIGEST_LEN: usize = 16;

// Length of an MD4 word in bytes
const WORD_BYTES_LEN: usize = 4;

// Number of MD4 state words
const STATE_WORDS_LEN: usize = 4;

// Number of MD4 transform words
const TRANSFORM_WORDS_LEN: usize = 16;

// Length of MD4 internal block length in bytes
const BLOCK_BYTES_LEN: usize = 64;

// Number of bytes used to represent the total bit length of the message
const MSG_BITS_LENGTH_LEN: usize = 8;

// Constants for MD4 transform routine
const S11: u32 = 3;
const S12: u32 = 7;
const S13: u32 = 11;
const S14: u32 = 19;
const S21: u32 = 3;
const S22: u32 = 5;
const S23: u32 = 9;
const S24: u32 = 13;
const S31: u32 = 3;
const S32: u32 = 9;
const S33: u32 = 11;
const S34: u32 = 15;

// Initial state words
const INIT_STATE: [u32; STATE_WORDS_LEN] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

// Magic byte starting the pad and length sequence
const PAD_START: u8 = 0x80;

// Minimum length of padding and message bits length
const PAD_AND_LENGTH_LEN: usize = 9;

// Binary representation of square root 2
const ROOT_2: u32 = 0x5a82_7999;

// Binary representation of square root 3
const ROOT_3: u32 = 0x6ed9_eba1;

// Block of all zeroes
const ZERO_BLOCK: [u8; BLOCK_BYTES_LEN] = [0_u8; BLOCK_BYTES_LEN];

// Transform word buffer of all zeroes
const ZERO_TRANSFORM: [u32; TRANSFORM_WORDS_LEN] = [0_u32; TRANSFORM_WORDS_LEN];

/// Errors for MD4 transform
#[derive(Debug)]
pub enum Error {
    InvalidLength,
}

/// Implementation of the MD4 transform
pub struct Md4 {
    /// Internal state of the MD4 transform
    state: [u32; STATE_WORDS_LEN],
    /// Internal block for message processing
    block: [u8; BLOCK_BYTES_LEN],
    /// Current index into the internal block
    index: usize,
    /// Total bit length of the message
    total_len: u64,
}

impl Md4 {
    /// Create a new instance of an MD4 transform
    pub fn new() -> Self {
        Self {
            state: INIT_STATE,
            block: [0_u8; BLOCK_BYTES_LEN],
            index: 0,
            total_len: 0,
        }
    }

    /// Insecure interface to initialize MD4 transform state from a digest
    ///
    /// Only for Cryptopals challenge #30
    ///
    /// NEVER actually do this in practice
    pub fn from_digest(digest: &[u8; DIGEST_LEN]) -> Self {
        let mut state = [0_u32; STATE_WORDS_LEN];

        for (i, word) in digest.chunks_exact(WORD_BYTES_LEN).enumerate() {
            // unwrap safe here, since word is guaranteed to be exactly four bytes long
            state[i] = u32::from_le_bytes(word.try_into().unwrap());
        }

        Self {
            state: state,
            block: [0_u8; BLOCK_BYTES_LEN],
            index: 0,
            total_len: 0,
        }
    }

    /// Input message bytes into the MD4 transform
    pub fn update(&mut self, msg: &[u8]) -> Result<(), Error> {
        let msg_len = (msg.len() * 8) as u64;

        if msg_len + self.total_len > core::u64::MAX {
            return Err(Error::InvalidLength);
        }

        self.total_len += msg_len;

        for byte in msg.iter() {
            self.block[self.index] = *byte;
            self.index += 1;

            if self.index == BLOCK_BYTES_LEN {
                self.transform();
            }
        }

        Ok(())
    }

    /// Perform final padding and encoding of the MD4 digest
    pub fn finalize(&mut self) -> Result<[u8; DIGEST_LEN], Error> {
        if self.index < BLOCK_BYTES_LEN {
            let old_len = self.index;

            self.pad()?;
            self.transform();

            if old_len > BLOCK_BYTES_LEN - PAD_AND_LENGTH_LEN {
                self.full_pad();
                self.transform();
            }
        }

        let mut res = [0_u8; DIGEST_LEN];

        for (i, word) in self.state.iter().enumerate() {
            res[i * WORD_BYTES_LEN..(i + 1) * WORD_BYTES_LEN]
                .copy_from_slice(word.to_le_bytes().as_ref());
        }

        Ok(res)
    }

    /// Perform *insecure* final padding and encoding of the MD4 digest
    ///
    /// This is an intentionally insecure interface for Cryptopals challenge #30
    ///
    /// NEVER actually do this in practice
    ///
    /// Encode the forged total message length, and compute the digest
    pub fn finalize_insecure(&mut self, forged_total_len: u64) -> Result<[u8; DIGEST_LEN], Error> {
        if self.index < BLOCK_BYTES_LEN {
            let old_len = self.index;

            // forge the total message length
            self.total_len = forged_total_len;

            self.pad()?;
            self.transform();

            if old_len > BLOCK_BYTES_LEN - PAD_AND_LENGTH_LEN {
                self.full_pad();
                self.transform();
            }
        }

        let mut res = [0_u8; DIGEST_LEN];

        for (i, word) in self.state.iter().enumerate() {
            res[i * WORD_BYTES_LEN..(i + 1) * WORD_BYTES_LEN]
                .copy_from_slice(word.to_le_bytes().as_ref());
        }

        Ok(res)
    }

    // Implementation of the MD4 transform over a message block
    fn transform(&mut self) {
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        let mut x = [0_u32; TRANSFORM_WORDS_LEN];
        for (t, word) in self.block.chunks_exact(WORD_BYTES_LEN).enumerate() {
            // unwrap safe here, since word is guaranteed to be 4 bytes long
            x[t] = u32::from_le_bytes(word.try_into().unwrap());
        }

        /* Round 1 */
        a = Self::ff(a, b, c, d, x[0], S11); /* 1 */
        d = Self::ff(d, a, b, c, x[1], S12); /* 2 */
        c = Self::ff(c, d, a, b, x[2], S13); /* 3 */
        b = Self::ff(b, c, d, a, x[3], S14); /* 4 */
        a = Self::ff(a, b, c, d, x[4], S11); /* 5 */
        d = Self::ff(d, a, b, c, x[5], S12); /* 6 */
        c = Self::ff(c, d, a, b, x[6], S13); /* 7 */
        b = Self::ff(b, c, d, a, x[7], S14); /* 8 */
        a = Self::ff(a, b, c, d, x[8], S11); /* 9 */
        d = Self::ff(d, a, b, c, x[9], S12); /* 10 */
        c = Self::ff(c, d, a, b, x[10], S13); /* 11 */
        b = Self::ff(b, c, d, a, x[11], S14); /* 12 */
        a = Self::ff(a, b, c, d, x[12], S11); /* 13 */
        d = Self::ff(d, a, b, c, x[13], S12); /* 14 */
        c = Self::ff(c, d, a, b, x[14], S13); /* 15 */
        b = Self::ff(b, c, d, a, x[15], S14); /* 16 */

        /* Round 2 */
        a = Self::gg(a, b, c, d, x[0], S21); /* 17 */
        d = Self::gg(d, a, b, c, x[4], S22); /* 18 */
        c = Self::gg(c, d, a, b, x[8], S23); /* 19 */
        b = Self::gg(b, c, d, a, x[12], S24); /* 20 */
        a = Self::gg(a, b, c, d, x[1], S21); /* 21 */
        d = Self::gg(d, a, b, c, x[5], S22); /* 22 */
        c = Self::gg(c, d, a, b, x[9], S23); /* 23 */
        b = Self::gg(b, c, d, a, x[13], S24); /* 24 */
        a = Self::gg(a, b, c, d, x[2], S21); /* 25 */
        d = Self::gg(d, a, b, c, x[6], S22); /* 26 */
        c = Self::gg(c, d, a, b, x[10], S23); /* 27 */
        b = Self::gg(b, c, d, a, x[14], S24); /* 28 */
        a = Self::gg(a, b, c, d, x[3], S21); /* 29 */
        d = Self::gg(d, a, b, c, x[7], S22); /* 30 */
        c = Self::gg(c, d, a, b, x[11], S23); /* 31 */
        b = Self::gg(b, c, d, a, x[15], S24); /* 32 */

        /* Round 3 */
        a = Self::hh(a, b, c, d, x[0], S31); /* 33 */
        d = Self::hh(d, a, b, c, x[8], S32); /* 34 */
        c = Self::hh(c, d, a, b, x[4], S33); /* 35 */
        b = Self::hh(b, c, d, a, x[12], S34); /* 36 */
        a = Self::hh(a, b, c, d, x[2], S31); /* 37 */
        d = Self::hh(d, a, b, c, x[10], S32); /* 38 */
        c = Self::hh(c, d, a, b, x[6], S33); /* 39 */
        b = Self::hh(b, c, d, a, x[14], S34); /* 40 */
        a = Self::hh(a, b, c, d, x[1], S31); /* 41 */
        d = Self::hh(d, a, b, c, x[9], S32); /* 42 */
        c = Self::hh(c, d, a, b, x[5], S33); /* 43 */
        b = Self::hh(b, c, d, a, x[13], S34); /* 44 */
        a = Self::hh(a, b, c, d, x[3], S31); /* 45 */
        d = Self::hh(d, a, b, c, x[11], S32); /* 46 */
        c = Self::hh(c, d, a, b, x[7], S33); /* 47 */
        b = Self::hh(b, c, d, a, x[15], S34); /* 48 */

        for (i, word) in self.state.iter_mut().enumerate() {
            let temp = match i {
                0 => a as u64,
                1 => b as u64,
                2 => c as u64,
                3 => d as u64,
                _ => unreachable!("invalid state index"),
            };

            *word = ((*word as u64 + temp) & 0xffff_ffff) as u32;
        }

        self.index = 0;

        Self::zero_block(&mut self.block);
        Self::zero_transform(&mut x);
    }

    // Pad a message to next block-length bytes
    fn pad(&mut self) -> Result<(), Error> {
        Self::inner_pad(&mut self.block, self.index, self.total_len)
    }

    fn inner_pad(
        block: &mut [u8; BLOCK_BYTES_LEN],
        index: usize,
        total_len: u64,
    ) -> Result<(), Error> {
        let pad_len = BLOCK_BYTES_LEN - index;

        // check that we are not padding a full block
        // total_len is a u64, so can't be more than u64::MAX
        if pad_len == 0 {
            return Err(Error::InvalidLength);
        }

        block[index] = PAD_START;

        // the end position of zero-byte padding
        let zero_pad_end = if pad_len > PAD_AND_LENGTH_LEN {
            // enough room for message bit length to follow
            BLOCK_BYTES_LEN - MSG_BITS_LENGTH_LEN
        } else {
            // only enough room for zeros
            BLOCK_BYTES_LEN
        };

        if pad_len > 1 {
            // will pad with zeroes, or a no-op if index + 1 == zero_pad_end
            Self::zero_bytes(&mut block[index + 1..zero_pad_end]);
        }

        if pad_len >= PAD_AND_LENGTH_LEN {
            // add the message bits length
            block[BLOCK_BYTES_LEN - MSG_BITS_LENGTH_LEN..]
                .copy_from_slice(total_len.to_le_bytes().as_ref());
        }

        Ok(())
    }

    /// Pad a message using MD4 formatting
    ///
    /// Only return the padding
    pub fn pad_message(msg: &[u8]) -> Result<Vec<u8>, Error> {
        let msg_len = msg.len();

        if msg_len == 0 || msg_len * 8 > core::u64::MAX as usize {
            return Err(Error::InvalidLength);
        }

        let total_len = (msg_len * 8) as u64;
        let mut pad_block = [0_u8; BLOCK_BYTES_LEN];

        let end_len = if msg_len % BLOCK_BYTES_LEN == 0 {
            // add full block of padding
            Self::inner_pad(&mut pad_block, 0, total_len)?;
            0
        } else if msg_len < BLOCK_BYTES_LEN {
            // copy message to padding block
            Self::inner_pad(&mut pad_block, msg_len, total_len)?;
            msg_len
        } else {
            // message is larger than a full block
            // non-modulo the block length
            let last_len = msg_len % BLOCK_BYTES_LEN;
            Self::inner_pad(&mut pad_block, last_len, total_len)?;
            last_len
        };

        let mut res: Vec<u8> = Vec::with_capacity(BLOCK_BYTES_LEN * 2);

        // add the padding block to the result
        res.extend_from_slice(&pad_block[end_len..]);

        if end_len > BLOCK_BYTES_LEN - PAD_AND_LENGTH_LEN {
            // not enough space to write the total bit length
            // add a block full of zeroes + total bit length
            Self::inner_full_pad(&mut pad_block, total_len);
            res.extend_from_slice(&pad_block);
        }

        Ok(res)
    }

    // Add a full block of padding
    fn full_pad(&mut self) {
        Self::inner_full_pad(&mut self.block, self.total_len);
    }

    fn inner_full_pad(block: &mut [u8; BLOCK_BYTES_LEN], total_len: u64) {
        Self::zero_bytes(&mut block[..BLOCK_BYTES_LEN - MSG_BITS_LENGTH_LEN]);
        block[BLOCK_BYTES_LEN - MSG_BITS_LENGTH_LEN..]
            .copy_from_slice(total_len.to_le_bytes().as_ref());
    }

    // F transform
    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | ((!x) & z)
    }

    // G transform
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | ((x & z) | (y & z))
    }

    // H transform
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    // FF transform for "Round 1"
    fn ff(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
        let t = ((a as u64 + Self::f(b, c, d) as u64 + x as u64) & 0xffff_ffff) as u32;
        t.rotate_left(s)
    }

    // GG transform for "Round 2"
    fn gg(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
        let t =
            ((a as u64 + Self::g(b, c, d) as u64 + x as u64 + ROOT_2 as u64) & 0xffff_ffff) as u32;
        t.rotate_left(s)
    }

    // HH transform for "Round 3"
    fn hh(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
        let t =
            ((a as u64 + Self::h(b, c, d) as u64 + x as u64 + ROOT_3 as u64) & 0xffff_ffff) as u32;
        t.rotate_left(s)
    }

    // Zero a block to clear sensitive data
    fn zero_block(block: &mut [u8; BLOCK_BYTES_LEN]) {
        block.copy_from_slice(&ZERO_BLOCK);
    }

    // Zero a transform word buffer to clear sensitive data
    fn zero_transform(x: &mut [u32; TRANSFORM_WORDS_LEN]) {
        x.copy_from_slice(&ZERO_TRANSFORM);
    }

    // Zero a byte buffer to clear sensitive data
    //
    // Buffer guaranteed to be smaller than a block at compile time
    fn zero_bytes(buf: &mut [u8]) {
        buf.copy_from_slice(&ZERO_BLOCK[..buf.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_vector_one() {
        let input = b"";
        let expected = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0,
            0x89, 0xc0,
        ];

        let mut md4 = Md4::new();

        md4.update(input.as_ref()).unwrap();

        let digest = md4.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn check_vector_two() {
        let input = b"a";

        let expected = [
            0xbd, 0xe5, 0x2c, 0xb3, 0x1d, 0xe3, 0x3e, 0x46, 0x24, 0x5e, 0x05, 0xfb, 0xdb, 0xd6,
            0xfb, 0x24,
        ];

        let mut md4 = Md4::new();

        md4.update(input.as_ref()).unwrap();

        let digest = md4.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn check_vector_three() {
        let input = b"abc";

        let expected = [
            0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6,
            0x72, 0x9d,
        ];

        let mut md4 = Md4::new();

        md4.update(input.as_ref()).unwrap();

        let digest = md4.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn check_vector_four() {
        let input = b"message digest";

        let expected = [
            0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8, 0x18, 0x87, 0x48, 0x06, 0xe1, 0xc7,
            0x01, 0x4b,
        ];

        let mut md4 = Md4::new();

        md4.update(input.as_ref()).unwrap();

        let digest = md4.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn check_vector_five() {
        let input = b"abcdefghijklmnopqrstuvwxyz";

        let expected = [
            0xd7, 0x9e, 0x1c, 0x30, 0x8a, 0xa5, 0xbb, 0xcd, 0xee, 0xa8, 0xed, 0x63, 0xdf, 0x41,
            0x2d, 0xa9,
        ];

        let mut md4 = Md4::new();

        md4.update(input.as_ref()).unwrap();

        let digest = md4.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn check_vector_six() {
        let input = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        let expected = [
            0x04, 0x3f, 0x85, 0x82, 0xf2, 0x41, 0xdb, 0x35, 0x1c, 0xe6, 0x27, 0xe1, 0x53, 0xe7,
            0xf0, 0xe4,
        ];

        let mut md4 = Md4::new();

        md4.update(input.as_ref()).unwrap();

        let digest = md4.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn check_vector_seven() {
        let input =
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890";

        let expected = [
            0xe3, 0x3b, 0x4d, 0xdc, 0x9c, 0x38, 0xf2, 0x19, 0x9c, 0x3e, 0x7b, 0x16, 0x4f, 0xcc,
            0x05, 0x36,
        ];

        let mut md4 = Md4::new();

        md4.update(input.as_ref()).unwrap();

        let digest = md4.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn check_pad() {
        let msg = [0x69; 93];

        let mut md4 = Md4::new();

        md4.block[..29].copy_from_slice(&msg[64..]);
        md4.index = 29;
        md4.total_len = 93 * 8;
        md4.pad().unwrap();

        let exp_padding = &md4.block[29..];
        let padding = Md4::pad_message(msg.as_ref()).unwrap();

        assert_eq!(padding[..], exp_padding[..]);
    }
}
