//! Fast entry/attribute scanning helpers (filename-only focus).
//!
//! These utilities operate over raw entry byte slices (after fixups applied)
//! to extract FILE_NAME (0x30) attributes with minimal overhead.

use crate::fast_fixup::detect_entry_size;

pub const ATTR_TYPE_FILE_NAME: u32 = 0x30;
const ATTRIBUTE_TYPE_END: u32 = 0xFFFF_FFFF;

#[derive(Clone, Copy, Debug)]
pub struct FileNameRef<'a> {
    pub entry_id: u32,
    pub parent_ref: u64,   // raw 64-bit reference (contains sequence)
    pub namespace: u8,
    pub name_utf16: &'a [u16],
}

#[inline]
fn read_u16(bytes: &[u8], off: usize) -> Option<u16> {
    bytes.get(off..off+2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
#[inline]
fn read_u32(bytes: &[u8], off: usize) -> Option<u32> {
    bytes.get(off..off+4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
#[inline]
fn read_u64(bytes: &[u8], off: usize) -> Option<u64> {
    bytes.get(off..off+8).map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Parse the total entry size from the first entry slice (delegates to fast_fixup helper)
#[inline]
pub fn parse_first_entry_size(first_entry: &[u8]) -> Option<u32> { detect_entry_size(first_entry) }

/// Iterate all FILE_NAME attributes in an entry, invoking callback for each.
/// Returns number of filename attributes found.
pub fn for_each_filename<'a, F: FnMut(FileNameRef<'a>)>(entry_bytes: &'a [u8], entry_id: u32, mut f: F) -> usize {
    // Signature check
    if entry_bytes.len() < 0x18 || &entry_bytes[0..4] != b"FILE" { return 0; }
    let first_attr_off = match read_u16(entry_bytes, 0x14) { Some(v) => v as usize, None => return 0 };
    if first_attr_off == 0 || first_attr_off >= entry_bytes.len() { return 0; }

    let mut offset = first_attr_off;
    let mut count = 0;
    while offset + 16 <= entry_bytes.len() { // minimal attribute header length guard
        let attr_type = match read_u32(entry_bytes, offset) { Some(v) => v, None => break };
        if attr_type == ATTRIBUTE_TYPE_END { break; }
        let attr_len = match read_u32(entry_bytes, offset + 4) { Some(v) => v as usize, None => break };
        if attr_len == 0 || offset + attr_len > entry_bytes.len() { break; }
        let non_res_flag = entry_bytes.get(offset + 8).copied().unwrap_or(0);
        if attr_type == ATTR_TYPE_FILE_NAME && non_res_flag == 0 {
            // Resident attribute header layout (offsets relative to attribute start)
            if offset + 24 > entry_bytes.len() { break; }
            let value_len = match read_u32(entry_bytes, offset + 16) { Some(v) => v as usize, None => break };
            let value_off = match read_u16(entry_bytes, offset + 20) { Some(v) => v as usize, None => break };
            let value_abs = offset + value_off;
            if value_abs + value_len > entry_bytes.len() || value_len < 0x42 { /* need base struct */ } else {
                // FILE_NAME structure
                if let Some(parent_ref) = read_u64(entry_bytes, value_abs) {
                    let name_len = entry_bytes.get(value_abs + 0x40).copied().unwrap_or(0) as usize;
                    let namespace = entry_bytes.get(value_abs + 0x41).copied().unwrap_or(0);
                    let name_utf16_off = value_abs + 0x42;
                    let name_bytes_end = name_utf16_off + name_len * 2;
                    if name_bytes_end <= entry_bytes.len() {
                        // SAFETY: constructing &[u16] from properly aligned bytes – alignment of u16 may be 2; slice.as_ptr() is aligned to 1. Use from_raw_parts_unaligned (stable?) -> fallback to copy if misaligned risk. Here we accept potential unaligned read; on x86 it's fine.
                        let raw: &[u16] = unsafe { std::slice::from_raw_parts(entry_bytes[name_utf16_off..name_bytes_end].as_ptr() as *const u16, name_len) };
                        f(FileNameRef { entry_id, parent_ref, namespace, name_utf16: raw });
                        count += 1;
                    }
                }
            }
        }
        offset += attr_len;
    }
    count
}

#[cfg(feature = "parallel")]
pub fn par_collect_filenames<'a>(data: &'a [u8], entry_size: usize) -> (Vec<FileNameRef<'a>>, Vec<Vec<usize>>) {
    use rayon::prelude::*;
    let entries = data.par_chunks_exact(entry_size).enumerate();
    let per_thread: Vec<(Vec<FileNameRef<'a>>, Vec<(u32, usize)>)> = entries.map(|(idx, entry)| {
        let mut list = Vec::new();
        let mut pairs = Vec::new();
        for_each_filename(entry, idx as u32, |fref| {
            let global_index = list.len();
            list.push(fref);
            pairs.push((fref.entry_id, global_index));
        });
        (list, pairs)
    }).collect();

    let total = per_thread.iter().map(|(v, _)| v.len()).sum();
    let mut file_names = Vec::with_capacity(total);
    for (v, _) in &per_thread { file_names.extend_from_slice(v); }

    let entry_count = data.len() / entry_size;
    let mut per_entry: Vec<Vec<usize>> = vec![Vec::new(); entry_count];
    let mut base = 0usize;
    for (v, pairs) in per_thread {
        for (entry_id, local_idx) in pairs {
            let global_idx = base + local_idx;
            if let Some(vec) = per_entry.get_mut(entry_id as usize) { vec.push(global_idx); }
        }
        base += v.len();
    }
    (file_names, per_entry)
}
