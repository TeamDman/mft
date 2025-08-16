//! Basic sequential path resolution over collected FileNameRef entries.
//! This is a first-pass simple implementation (non-parallel) to be optimized later.

use std::borrow::Cow;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use eyre::bail;

use crate::fast_entry::{FileNameCollection, FileNameRef};

/// Namespace priority for canonical path selection (higher earlier).
/// Values correspond to NTFS FILE_NAME namespace codes.
/// 0 = POSIX, 1 = Win32, 2 = DOS, 3 = Win32+DOS (depending on defs). Adjust as needed.
const NAMESPACE_PRIORITY: &[u8] = &[1, 3, 0, 2];

#[inline]
fn choose_best<'a>(candidates: &[&'a FileNameRef<'a>]) -> Option<&'a FileNameRef<'a>> {
    for pref in NAMESPACE_PRIORITY {
        if let Some(chosen) = candidates.iter().copied().find(|c| c.namespace == *pref) {
            return Some(chosen);
        }
    }
    candidates.first().copied()
}

/// Decode UTF-16 little endian slice to String (lossy ASCII fast-path optional later).
fn decode_name(units: &[u16]) -> Cow<'_, str> {
    use std::char::decode_utf16;
    let iter = decode_utf16(units.iter().copied());
    let mut s = String::with_capacity(units.len());
    for r in iter {
        s.push(r.unwrap_or('\u{FFFD}'));
    }
    Cow::Owned(s)
}

/// Per-entry resolved paths (sparse). Index = entry id. None = unresolved.
#[derive(Debug, Default, Clone)]
pub struct ResolvedPaths(pub Vec<Option<PathBuf>>);

impl ResolvedPaths {
    pub fn unresolved_count(&self) -> usize {
        self.0.iter().filter(|p| p.is_none()).count()
    }
    pub fn resolved_count(&self) -> usize {
        self.0.len() - self.unresolved_count()
    }
    /// Iterate borrowing resolved entries (entry_id, &PathBuf)
    pub fn resolved(&self) -> impl Iterator<Item = (u32, &PathBuf)> {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, o)| o.as_ref().map(|p| (i as u32, p)))
    }
}

impl Deref for ResolvedPaths {
    type Target = [Option<PathBuf>];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for ResolvedPaths {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl IntoIterator for ResolvedPaths {
    type Item = (u32, PathBuf);
    type IntoIter = std::vec::IntoIter<(u32, PathBuf)>;
    fn into_iter(self) -> Self::IntoIter {
        self.0
            .into_iter()
            .enumerate()
            .filter_map(|(i, o)| o.map(|p| (i as u32, p)))
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// Resolve paths (simple, single parent path per entry, ignoring multiple hardlink parents for now).
pub fn resolve_paths_simple(file_names: &FileNameCollection<'_>) -> eyre::Result<ResolvedPaths> {
    let entry_count = file_names.entry_count();
    let mut results: Vec<Option<PathBuf>> = vec![None; entry_count];

    // Root (entry 5) special-case: gather name (usually '.') -> treat as empty path root
    if entry_count > 5 {
        results[5] = Some(PathBuf::new());
    }

    // Iterate sequentially; if parent unresolved we will revisit in second pass (inefficient but OK baseline)
    let mut changed = true;
    let mut passes = 0;
    while changed {
        if passes > 25 {
            bail!(
                "Warning: path resolution exceeded {} passes, stopping here.",
                passes
            );
        }
        changed = false;
        passes += 1;
        for entry_id in 0..entry_count {
            if results[entry_id].is_some() {
                continue;
            }
            let candidates: Vec<&FileNameRef> =
                file_names.filenames_for_entry(entry_id as u32).collect();
            if candidates.is_empty() {
                continue;
            }
            if let Some(best) = choose_best(&candidates) {
                let parent_record = (best.parent_ref & 0xFFFFFFFFFFFF) as usize; // mask to 48 bits
                let parent_ready = parent_record < entry_count && results[parent_record].is_some();
                if parent_ready {
                    let mut path = results[parent_record].as_ref().unwrap().clone();
                    let name = decode_name(best.name_utf16);
                    path.push(name.as_ref());
                    results[entry_id] = Some(path);
                    changed = true;
                }
            }
        }
    }

    Ok(ResolvedPaths(results))
}
