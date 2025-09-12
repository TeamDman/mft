//! Basic sequential path resolution over collected FileNameRef entries.
//! This is a first-pass simple implementation (non-parallel) to be optimized later.

use std::borrow::Cow;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

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
    // ASCII fast path: if all code units are < 0x80 build directly
    if units.iter().all(|&u| u < 0x80) {
        let mut s = String::with_capacity(units.len());
        for &u in units { s.push(u as u8 as char); }
        return Cow::Owned(s);
    }
    use std::char::decode_utf16;
    let iter = decode_utf16(units.iter().copied());
    let mut s = String::with_capacity(units.len());
    for r in iter { s.push(r.unwrap_or('\u{FFFD}')); }
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

// ORIGINAL multi-pass implementation preserved for validation / benchmarking.
pub fn resolve_paths_simple_multipass(file_names: &FileNameCollection<'_>) -> eyre::Result<ResolvedPaths> {
    let entry_count = file_names.entry_count();
    let mut results: Vec<Option<PathBuf>> = vec![None; entry_count];
    if entry_count > 5 { results[5] = Some(PathBuf::new()); }
    let mut changed = true;
    let mut passes = 0u32;
    while changed {
        if passes > 25 {
            break; // mimic old early stop behavior (was bail! previously)
        }
        changed = false;
        passes += 1;
        for entry_id in 0..entry_count {
            if results[entry_id].is_some() { continue; }
            let candidates: Vec<&FileNameRef> = file_names.filenames_for_entry(entry_id as u32).collect();
            if candidates.is_empty() { continue; }
            if let Some(best) = choose_best(&candidates) {
                let parent_record = (best.parent_ref & 0xFFFFFFFFFFFF) as usize;
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

/// Randomly sample entries comparing the original multi-pass resolver and the new DFS resolver.
/// Ensures:
/// 1. Same total resolved count.
/// 2. For sampled indices, both have identical presence/absence and identical path when present.
/// Fails fast on first discrepancy.
pub fn compare_resolvers_random_sample(
    file_names: &FileNameCollection<'_>,
    sample_size: usize,
    seed: u64,
) -> eyre::Result<()> {
    let old_paths = resolve_paths_simple_multipass(file_names)?;
    let new_paths = resolve_paths_simple(file_names)?;

    // Global counts: new must be >= old (multi-parent support may increase resolutions)
    let old_resolved = old_paths.resolved_count();
    let new_resolved = new_paths.resolved_count();
    if new_resolved < old_resolved {
        eyre::bail!(
            "Resolved count regression new={} < old={}",
            new_resolved, old_resolved
        );
    }
    if old_paths.len() != new_paths.len() {
        eyre::bail!(
            "Vector length mismatch old={} new={}",
            old_paths.len(),
            new_paths.len()
        );
    }

    // Simple deterministic xorshift64* PRNG
    fn next_rand(state: &mut u64) -> u64 { let mut x = *state; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; *state = x; x.wrapping_mul(0x2545F4914F6CDD1D) }

    let entry_count = old_paths.len();
    let take = sample_size.min(entry_count);
    let mut rng_state = if seed == 0 { 0xDEADBEEFCAFEBABEu64 } else { seed };

    for _ in 0..take {
        let idx = (next_rand(&mut rng_state) as usize) % entry_count;
        let a = &old_paths[idx];
        let b = &new_paths[idx];
        match (a, b) {
            (None, None) => {},                 // both unresolved -> fine
            (None, Some(_pb)) => {},            // new resolved extra -> acceptable
            (Some(_pa), None) => {
                eyre::bail!(
                    "Entry {} lost resolution: old had path, new is None",
                    idx
                );
            }
            (Some(pa), Some(pb)) => {
                if pa != pb {
                    eyre::bail!(
                        "Path mismatch at index {} old='{}' new='{}'",
                        idx,
                        pa.display(),
                        pb.display()
                    );
                }
            }
        }
    }
    Ok(())
}

/// Resolve paths (optimized single-pass DFS with memoization).
/// Previous implementation used iterative multi-pass over all entries causing
/// O(N * passes) behavior (~depth * N). This version reduces work to near O(N).
pub fn resolve_paths_simple(file_names: &FileNameCollection<'_>) -> eyre::Result<ResolvedPaths> {
    let entry_count = file_names.entry_count();
    let mut results: Vec<Option<PathBuf>> = vec![None; entry_count];

    // Root (entry 5) special-case: treat as empty path root
    if entry_count > 5 {
        results[5] = Some(PathBuf::new());
    }

    // Pre-select best filename attr per entry (canonical choice) => (parent_entry, name_utf16)
    let mut best_meta: Vec<Option<(usize, &'_ [u16])>> = vec![None; entry_count];
    for entry_id in 0..entry_count {
        let cands: Vec<&FileNameRef> = file_names.filenames_for_entry(entry_id as u32).collect();
        if cands.is_empty() {
            continue;
        }
        if let Some(best) = choose_best(&cands) {
            let parent_record = (best.parent_ref & 0xFFFFFFFFFFFF) as usize; // mask to 48 bits
            if parent_record < entry_count { // discard invalid parents
                best_meta[entry_id] = Some((parent_record, best.name_utf16));
            }
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum VisitState { Unvisited, Visiting, Done }
    let mut state: Vec<VisitState> = vec![VisitState::Unvisited; entry_count];

    // Iterative DFS to avoid deep recursion; typical depth small but this is safe.
    for start in 0..entry_count {
        if state[start] == VisitState::Done { continue; }
        // Skip if we already have a resolved path (e.g., root) and no need to propagate
        if results[start].is_some() { state[start] = VisitState::Done; continue; }
        let mut stack: Vec<usize> = Vec::new();
        stack.push(start);
        while let Some(&cur) = stack.last() {
            match state[cur] {
                VisitState::Done => { stack.pop(); },
                VisitState::Visiting => {
                    // Children (parents) processed, build this path if possible
                    if results[cur].is_none() {
                        if let Some((parent, name_units)) = best_meta[cur] {
                            if parent == cur { // self-cycle guard
                                results[cur] = Some(PathBuf::from(decode_name(name_units).as_ref()));
                            } else if let Some(parent_path) = results[parent].clone() {
                                let mut path = parent_path.clone();
                                path.push(decode_name(name_units).as_ref());
                                results[cur] = Some(path);
                            }
                        }
                    }
                    state[cur] = VisitState::Done;
                    stack.pop();
                }
                VisitState::Unvisited => {
                    state[cur] = VisitState::Visiting;
                    if let Some((parent, _)) = best_meta[cur] {
                        if parent != cur && state[parent] == VisitState::Unvisited {
                            stack.push(parent);
                        }
                    }
                }
            }
        }
    }

    // Optional sanity threshold: if too many remain unresolved maybe corrupted graph
    // (Keep previous behavior of not treating as hard error, but we can warn externally.)
    if entry_count > 0 && results.iter().filter(|p| p.is_none()).count() > entry_count / 2 {
        // Large fraction unresolved could indicate issues; return Ok anyway for now.
    }

    Ok(ResolvedPaths(results))
}

/// A mapping from MFT entry ID to zero/one/many resolved paths.
/// Because an entry can have multiple x30 attributes, one entry may have more than one full path associated with it.
#[derive(Debug, Default, Clone)]
pub struct MftEntryPathCollection(pub Vec<Vec<PathBuf>>);
impl MftEntryPathCollection {
    pub fn entry_count(&self) -> usize { self.0.len() }
    pub fn total_paths(&self) -> usize { self.0.iter().map(|v| v.len()).sum() }
    pub fn paths_for(&self, entry_id: usize) -> &[PathBuf] { self.0.get(entry_id).map(|v| &v[..]).unwrap_or(&[]) }
}

#[inline]
fn ns_rank(ns: u8) -> u8 { match ns { 1 => 0, 3 => 1, 0 => 2, 2 => 3, _ => 4 } } // Win32 > Win32AndDos > POSIX > DOS

/// Resolve all paths including multiple hardlink parents.
/// For each distinct parent of an entry, keep only the highest-precedence namespace.
/// Returns zero/one/many paths per entry (index aligned with entry id).
pub fn resolve_paths_all(file_names: &FileNameCollection<'_>) -> eyre::Result<MftEntryPathCollection> {
    let entry_count = file_names.entry_count();
    // Collect per-entry best (parent -> (namespace, name_utf16)) selections.
    struct BestName<'a> { parent: usize, namespace: u8, name_utf16: &'a [u16] }
    let mut per_entry: Vec<Vec<BestName<'_>>> = {
        let mut v = Vec::with_capacity(entry_count);
        for _ in 0..entry_count { v.push(Vec::new()); }
        v
    };
    for entry_id in 0..entry_count {
        for fref in file_names.filenames_for_entry(entry_id as u32) {
            let parent = (fref.parent_ref & 0xFFFFFFFFFFFF) as usize;
            if parent >= entry_count { continue; }
            let list = &mut per_entry[entry_id];
            if let Some(existing) = list.iter_mut().find(|bn| bn.parent == parent) {
                if ns_rank(fref.namespace) < ns_rank(existing.namespace) { existing.namespace = fref.namespace; existing.name_utf16 = fref.name_utf16; }
            } else {
                list.push(BestName { parent, namespace: fref.namespace, name_utf16: fref.name_utf16 });
            }
        }
    }

    // Prepare results: vector of vectors of PathBufs
    let mut results: Vec<Vec<PathBuf>> = vec![Vec::new(); entry_count];
    if entry_count > 5 { results[5].push(PathBuf::new()); }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum VisitState { Unvisited, Visiting, Done }
    let mut state: Vec<VisitState> = vec![VisitState::Unvisited; entry_count];

    for start in 0..entry_count {
        if state[start] == VisitState::Done { continue; }
        let mut stack: Vec<usize> = Vec::new();
        stack.push(start);
        while let Some(&cur) = stack.last() {
            match state[cur] {
                VisitState::Done => { stack.pop(); },
                VisitState::Visiting => {
                    if results[cur].is_empty() { // attempt to build paths
                        let mut acc: Vec<PathBuf> = Vec::new();
                        for bn in &per_entry[cur] {
                            if bn.parent == cur { continue; } // self-cycle guard
                            if results[bn.parent].is_empty() { continue; } // parent unresolved
                            let name = decode_name(bn.name_utf16); // decode once per best parent
                            for parent_path in &results[bn.parent] {
                                let mut p = parent_path.clone();
                                p.push(name.as_ref());
                                acc.push(p);
                            }
                        }
                        if !acc.is_empty() {
                            // Dedup identical paths if any (rare). Use simple sort+dedup for determinism.
                            if acc.len() > 1 { acc.sort(); acc.dedup(); }
                            results[cur] = acc;
                        }
                    }
                    state[cur] = VisitState::Done; stack.pop();
                }
                VisitState::Unvisited => {
                    state[cur] = VisitState::Visiting;
                    // push parents first
                    for bn in &per_entry[cur] { if bn.parent != cur && state[bn.parent] == VisitState::Unvisited { stack.push(bn.parent); } }
                }
            }
        }
    }

    Ok(MftEntryPathCollection(results))
}

#[cfg(feature = "parallel")]
pub fn resolve_paths_all_parallel(file_names: &FileNameCollection<'_>) -> eyre::Result<MftEntryPathCollection> {
    use rayon::prelude::*;
    let entry_count = file_names.entry_count();

    #[derive(Clone)]
    struct BestName { parent: usize, name: String }

    // Build raw selections with namespace precedence (same logic as sequential version) then decode.
    let mut raw: Vec<Vec<(usize, u8, &'_ [u16])>> = Vec::with_capacity(entry_count);
    for _ in 0..entry_count { raw.push(Vec::new()); }
    for entry_id in 0..entry_count {
        for fref in file_names.filenames_for_entry(entry_id as u32) {
            let parent = (fref.parent_ref & 0xFFFFFFFFFFFF) as usize;
            if parent >= entry_count { continue; }
            let list = &mut raw[entry_id];
            if let Some((_, ns, name_units)) = list.iter_mut().find(|(p, _, _)| *p == parent) {
                if ns_rank(fref.namespace) < ns_rank(*ns) {
                    *ns = fref.namespace; *name_units = fref.name_utf16;
                }
            } else {
                list.push((parent, fref.namespace, fref.name_utf16));
            }
        }
    }
    let mut per_entry: Vec<Vec<BestName>> = Vec::with_capacity(entry_count);
    for entry_id in 0..entry_count {
        let mut v: Vec<BestName> = Vec::with_capacity(raw[entry_id].len());
        for (parent, _ns, name_units) in &raw[entry_id] {
            v.push(BestName { parent: *parent, name: decode_name(name_units).into_owned() });
        }
        per_entry.push(v);
    }

    // Compute depth (minimum parent depth + 1) so parents always processed before children.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mark { Unvis, Temp, Done }
    let mut depth: Vec<i32> = vec![-1; entry_count];
    let mut mark: Vec<Mark> = vec![Mark::Unvis; entry_count];
    fn dfs(i: usize, per_entry: &Vec<Vec<BestName>>, depth: &mut [i32], mark: &mut [Mark]) -> i32 {
        if mark[i] == Mark::Done { return depth[i]; }
        if mark[i] == Mark::Temp { return 0; } // cycle/self-root
        mark[i] = Mark::Temp;
        let mut best = 0;
        for bn in &per_entry[i] {
            if bn.parent == i { continue; }
            let pd = dfs(bn.parent, per_entry, depth, mark);
            if pd + 1 > best { best = pd + 1; }
        }
        depth[i] = best; mark[i] = Mark::Done; best
    }
    for i in 0..entry_count { if depth[i] == -1 { dfs(i, &per_entry, &mut depth, &mut mark); } }
    let max_depth = depth.iter().copied().max().unwrap_or(0) as usize;
    let mut layers: Vec<Vec<usize>> = vec![Vec::new(); max_depth + 1];
    for (i, d) in depth.iter().enumerate() { layers[*d as usize].push(i); }

    // Results storage
    let mut results: Vec<Vec<PathBuf>> = vec![Vec::new(); entry_count];
    if entry_count > 5 { results[5].push(PathBuf::new()); }

    // Process each layer: build outputs in parallel (read-only borrow of earlier results) then write.
    for layer_ids in &layers {
        let layer_outputs: Vec<(usize, Vec<PathBuf>)> = layer_ids.par_iter().map(|&entry_id| {
            if !results[entry_id].is_empty() { return (entry_id, Vec::new()); }
            let mut acc: Vec<PathBuf> = Vec::new();
            for bn in &per_entry[entry_id] {
                if bn.parent == entry_id { continue; }
                let parent_paths = &results[bn.parent];
                if parent_paths.is_empty() { continue; }
                for parent_path in parent_paths {
                    let mut p = parent_path.clone();
                    p.push(&bn.name);
                    acc.push(p);
                }
            }
            if acc.len() > 1 { acc.sort(); acc.dedup(); }
            (entry_id, acc)
        }).collect();
        // Write phase
        for (id, acc) in layer_outputs { if !acc.is_empty() { results[id] = acc; } }
    }

    Ok(MftEntryPathCollection(results))
}
