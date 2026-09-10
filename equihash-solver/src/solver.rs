use std::alloc::{alloc as alloc_raw, dealloc as dealloc_raw, Layout};
use std::cmp::Ordering;

const ERR_INVALID_INPUT: i32 = -1;
const ERR_RESOURCE: i32 = -2;
const SEED_BYTES: u32 = 32;
const NONCE_BYTES: u32 = 24;

#[derive(Clone)]
struct BitField {
    bytes: Vec<u8>,
    bit_len: usize,
}

impl BitField {
    fn try_new(bit_len: usize) -> Result<Self, ()> {
        let byte_len = bit_len.checked_add(7).ok_or(())? / 8;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(byte_len).map_err(|_| ())?;
        bytes.resize(byte_len, 0);
        Ok(Self { bytes, bit_len })
    }

    fn from_prefix(input: &[u8], bit_len: usize) -> Result<Self, ()> {
        if input.len() < bit_len.checked_add(7).ok_or(())? / 8 {
            return Err(());
        }
        let mut out = Self::try_new(bit_len)?;
        for idx in 0..bit_len {
            write_bit(&mut out.bytes, idx, read_bit(input, idx));
        }
        Ok(out)
    }

    fn xor_tail(left: &Self, right: &Self, start: usize, bit_len: usize) -> Result<Self, ()> {
        if start.checked_add(bit_len).ok_or(())? > left.bit_len
            || start.checked_add(bit_len).ok_or(())? > right.bit_len
        {
            return Err(());
        }
        let mut out = Self::try_new(bit_len)?;
        for idx in 0..bit_len {
            let bit = read_bit(&left.bytes, start + idx) ^ read_bit(&right.bytes, start + idx);
            write_bit(&mut out.bytes, idx, bit);
        }
        Ok(out)
    }

    fn prefix_cmp(&self, other: &Self, bit_len: usize) -> Ordering {
        let full_bytes = bit_len / 8;
        for idx in 0..full_bytes {
            match self.bytes[idx].cmp(&other.bytes[idx]) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        let remaining = bit_len % 8;
        if remaining == 0 {
            return Ordering::Equal;
        }
        let mask = 0xff << (8 - remaining);
        (self.bytes[full_bytes] & mask).cmp(&(other.bytes[full_bytes] & mask))
    }

    fn is_zero(&self) -> bool {
        self.bytes.iter().all(|byte| *byte == 0)
    }
}

#[derive(Clone)]
struct Entry {
    bits: BitField,
    first: u32,
    indices: Vec<u32>,
}

fn read_bit(bytes: &[u8], idx: usize) -> u8 {
    let byte = bytes[idx / 8];
    (byte >> (7 - (idx % 8))) & 1
}

fn write_bit(bytes: &mut [u8], idx: usize, bit: u8) {
    let byte_idx = idx / 8;
    let shift = 7 - (idx % 8);
    let mask = 1u8 << shift;
    if bit == 0 {
        bytes[byte_idx] &= !mask;
    } else {
        bytes[byte_idx] |= mask;
    }
}

fn make_personalization(n: u32, k: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(b"ZcashPoW");
    out[8..12].copy_from_slice(&n.to_le_bytes());
    out[12..16].copy_from_slice(&k.to_le_bytes());
    out
}

fn hash_index_bits(
    seed: &[u8],
    nonce: &[u8],
    index: u32,
    n: u32,
    personalization: &[u8; 16],
) -> Result<BitField, ()> {
    let input_len = seed
        .len()
        .checked_add(nonce.len())
        .and_then(|len| len.checked_add(4))
        .ok_or(())?;
    let mut input = Vec::new();
    input.try_reserve_exact(input_len).map_err(|_| ())?;
    input.extend_from_slice(seed);
    input.extend_from_slice(nonce);
    input.extend_from_slice(&index.to_be_bytes());

    let out_bytes = (n as usize).checked_add(7).ok_or(())? / 8;
    let digest = blake2b_simd::Params::new()
        .hash_length(out_bytes)
        .personal(personalization)
        .hash(&input);
    BitField::from_prefix(digest.as_bytes(), n as usize)
}

fn entries_disjoint(left: &[u32], right: &[u32]) -> bool {
    left.iter().all(|value| !right.contains(value))
}

fn solve_one(seed: &[u8], nonce: &[u8], n: u32, k: u32, rows: u32) -> Result<Option<Vec<u8>>, i32> {
    let collision_bits = (n / (k + 1)) as usize;
    let personalization = make_personalization(n, k);

    let mut layer = Vec::new();
    layer
        .try_reserve_exact(rows as usize)
        .map_err(|_| ERR_RESOURCE)?;
    for idx in 0..rows {
        let mut indices = Vec::new();
        indices.try_reserve_exact(1).map_err(|_| ERR_RESOURCE)?;
        indices.push(idx);
        layer.push(Entry {
            bits: hash_index_bits(seed, nonce, idx, n, &personalization)
                .map_err(|_| ERR_RESOURCE)?,
            first: idx,
            indices,
        });
    }

    let mut bit_len = n as usize;
    for _round in 0..k {
        if layer.is_empty() {
            return Ok(None);
        }
        let rem_bits = bit_len.checked_sub(collision_bits).ok_or(ERR_RESOURCE)?;
        layer.sort_unstable_by(|left, right| {
            left.bits
                .prefix_cmp(&right.bits, collision_bits)
                .then_with(|| left.first.cmp(&right.first))
        });

        let mut next = Vec::new();
        let mut group_start = 0usize;
        while group_start < layer.len() {
            let mut group_end = group_start + 1;
            while group_end < layer.len()
                && layer[group_start]
                    .bits
                    .prefix_cmp(&layer[group_end].bits, collision_bits)
                    == Ordering::Equal
            {
                group_end += 1;
            }

            for left_index in group_start..group_end {
                for right_index in (left_index + 1)..group_end {
                    let left = &layer[left_index];
                    let right = &layer[right_index];
                    if left.first >= right.first || !entries_disjoint(&left.indices, &right.indices)
                    {
                        continue;
                    }

                    let index_len = left
                        .indices
                        .len()
                        .checked_add(right.indices.len())
                        .ok_or(ERR_RESOURCE)?;
                    if next.len() == next.capacity() {
                        if next.try_reserve(1).is_err() {
                            return Err(ERR_RESOURCE);
                        }
                    }
                    let bits =
                        BitField::xor_tail(&left.bits, &right.bits, collision_bits, rem_bits)
                            .map_err(|_| ERR_RESOURCE)?;
                    let mut indices = Vec::new();
                    indices
                        .try_reserve_exact(index_len)
                        .map_err(|_| ERR_RESOURCE)?;
                    indices.extend_from_slice(&left.indices);
                    indices.extend_from_slice(&right.indices);
                    next.push(Entry {
                        bits,
                        first: left.first,
                        indices,
                    });
                }
            }
            group_start = group_end;
        }

        if next.is_empty() {
            return Ok(None);
        }
        layer = next;
        bit_len = rem_bits;
    }

    let expected_count = 1usize << k;
    for entry in layer {
        if entry.bits.is_zero() && entry.indices.len() == expected_count {
            let out_len = entry.indices.len().checked_mul(4).ok_or(ERR_RESOURCE)?;
            let mut out = Vec::new();
            out.try_reserve_exact(out_len).map_err(|_| ERR_RESOURCE)?;
            out.resize(out_len, 0);
            for (idx, value) in entry.indices.iter().enumerate() {
                let start = idx.checked_mul(4).ok_or(ERR_RESOURCE)?;
                out[start..start + 4].copy_from_slice(&value.to_be_bytes());
            }
            return Ok(Some(out));
        }
    }
    Ok(None)
}

pub fn is_valid_params(n: u32, k: u32) -> bool {
    (8..=256).contains(&n) && n % 2 == 0 && (2..=8).contains(&k) && n % (k + 1) == 0
}

#[no_mangle]
pub extern "C" fn alloc(size: u32, alignment: u32) -> u32 {
    if size == 0 {
        return 0;
    }
    let layout = match Layout::from_size_align(size as usize, alignment as usize) {
        Ok(layout) => layout,
        Err(_) => return 0,
    };
    let ptr = unsafe { alloc_raw(layout) };
    if ptr.is_null() || (ptr as usize) > u32::MAX as usize {
        return 0;
    }
    ptr as u32
}

#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: u32, size: u32, alignment: u32) {
    if ptr == 0 || size == 0 {
        return;
    }
    if let Ok(layout) = Layout::from_size_align(size as usize, alignment as usize) {
        dealloc_raw(ptr as *mut u8, layout);
    }
}

#[no_mangle]
pub extern "C" fn is_valid_equihash_params(n: u32, k: u32) -> u32 {
    u32::from(is_valid_params(n, k))
}

#[no_mangle]
pub extern "C" fn required_proof_len(k: u32) -> u32 {
    if !(2..=8).contains(&k) {
        return 0;
    }
    4 * (1u32 << k)
}

#[no_mangle]
pub extern "C" fn solve_once(
    seed_ptr: *const u8,
    seed_len: u32,
    nonce_ptr: *const u8,
    nonce_len: u32,
    n: u32,
    k: u32,
    rows: u32,
    out_ptr: *mut u8,
    out_cap: u32,
) -> i32 {
    if seed_ptr.is_null() || nonce_ptr.is_null() || out_ptr.is_null() {
        return ERR_INVALID_INPUT;
    }
    if seed_len != SEED_BYTES || nonce_len != NONCE_BYTES || rows == 0 {
        return ERR_INVALID_INPUT;
    }
    if !is_valid_params(n, k) {
        return ERR_INVALID_INPUT;
    }

    let required = required_proof_len(k);
    if required == 0 || out_cap < required {
        return ERR_INVALID_INPUT;
    }

    let seed_len = seed_len as usize;
    let nonce_len = nonce_len as usize;
    let out_cap = out_cap as usize;

    // SAFETY: the ABI caller owns these non-null buffers and supplies their lengths.
    let seed = unsafe { std::slice::from_raw_parts(seed_ptr, seed_len) };
    // SAFETY: the ABI caller owns these non-null buffers and supplies their lengths.
    let nonce = unsafe { std::slice::from_raw_parts(nonce_ptr, nonce_len) };
    // SAFETY: the ABI caller owns this non-null output buffer and supplies its capacity.
    let out = unsafe { std::slice::from_raw_parts_mut(out_ptr, out_cap) };

    match solve_one(seed, nonce, n, k, rows) {
        Ok(Some(proof)) => {
            if proof.len() > out.len() {
                return ERR_INVALID_INPUT;
            }
            out[..proof.len()].copy_from_slice(&proof);
            proof.len() as i32
        }
        Ok(None) => 0,
        Err(code) => code,
    }
}
