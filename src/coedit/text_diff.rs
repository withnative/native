//! Minimal text diff for routing whole-body writes into a live doc.
//!
//! A routed write must touch only what it changes, so that a peer's
//! in-flight edits elsewhere survive the CRDT merge. The diff trims the common
//! prefix and suffix, runs a line-level Myers diff over the middle, and trims
//! each changed hunk down to its differing bytes. All offsets are UTF-8 byte
//! offsets on `char` boundaries, matching the doc's `OffsetKind::Bytes`.

/// One splice against the OLD text: delete `delete` bytes at `at`, then
/// insert `insert` there. Splices are sorted by `at` and do not overlap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Splice {
    pub(crate) at: usize,
    pub(crate) delete: usize,
    pub(crate) insert: String,
}

/// Above this many line edits the Myers search stops and the middle is
/// replaced as one splice. Bounds work and memory on pathological inputs:
/// the search keeps one band of `2d + 3` frontier entries per round, so at
/// most about `D²` words (a few MiB at this cap) whatever the body size.
const MAX_EDIT_DISTANCE: usize = 512;

/// Splices turning `old` into `new`.
pub(crate) fn splices(old: &str, new: &str) -> Vec<Splice> {
    let prefix = common_prefix(old, new);
    let suffix = common_suffix(&old[prefix..], &new[prefix..]);
    let old_mid = &old[prefix..old.len() - suffix];
    let new_mid = &new[prefix..new.len() - suffix];
    if old_mid.is_empty() && new_mid.is_empty() {
        return Vec::new();
    }
    let old_lines = split_lines(old_mid);
    let new_lines = split_lines(new_mid);
    let Some(script) = myers(&old_lines, &new_lines) else {
        return vec![Splice {
            at: prefix,
            delete: old_mid.len(),
            insert: new_mid.to_owned(),
        }];
    };
    // Walk the script, coalescing adjacent deletes/inserts into hunks.
    let mut out = Vec::new();
    let (mut oi, mut ni) = (0usize, 0usize);
    let (mut old_at, mut new_at) = (0usize, 0usize);
    let mut hunk: Option<(usize, usize, usize, usize)> = None; // old start/end, new start/end
    let flush = |hunk: &mut Option<(usize, usize, usize, usize)>, out: &mut Vec<Splice>| {
        if let Some((os, oe, ns, ne)) = hunk.take() {
            let o = &old_mid[os..oe];
            let n = &new_mid[ns..ne];
            let p = common_prefix(o, n);
            let s = common_suffix(&o[p..], &n[p..]);
            out.push(Splice {
                at: prefix + os + p,
                delete: o.len() - p - s,
                insert: n[p..n.len() - s].to_owned(),
            });
        }
    };
    for op in script {
        match op {
            Op::Equal => {
                flush(&mut hunk, &mut out);
                old_at += old_lines[oi].len();
                new_at += new_lines[ni].len();
                oi += 1;
                ni += 1;
            }
            Op::Delete => {
                let len = old_lines[oi].len();
                let h = hunk.get_or_insert((old_at, old_at, new_at, new_at));
                h.1 += len;
                old_at += len;
                oi += 1;
            }
            Op::Insert => {
                let len = new_lines[ni].len();
                let h = hunk.get_or_insert((old_at, old_at, new_at, new_at));
                h.3 += len;
                new_at += len;
                ni += 1;
            }
        }
    }
    flush(&mut hunk, &mut out);
    out.retain(|s| s.delete > 0 || !s.insert.is_empty());
    out
}

/// Apply splices to `old`.
pub(crate) fn apply(old: &str, splices: &[Splice]) -> String {
    let mut out = String::with_capacity(old.len());
    let mut cursor = 0;
    for s in splices {
        out.push_str(&old[cursor..s.at]);
        out.push_str(&s.insert);
        cursor = s.at + s.delete;
    }
    out.push_str(&old[cursor..]);
    out
}

fn common_prefix(a: &str, b: &str) -> usize {
    let mut n = a
        .as_bytes()
        .iter()
        .zip(b.as_bytes())
        .take_while(|(x, y)| x == y)
        .count();
    while !a.is_char_boundary(n) || !b.is_char_boundary(n) {
        n -= 1;
    }
    n
}

fn common_suffix(a: &str, b: &str) -> usize {
    let mut n = a
        .as_bytes()
        .iter()
        .rev()
        .zip(b.as_bytes().iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    while !a.is_char_boundary(a.len() - n) || !b.is_char_boundary(b.len() - n) {
        n -= 1;
    }
    n
}

/// Lines including their trailing `\n` (the last may lack one).
fn split_lines(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Equal,
    Delete,
    Insert,
}

/// Myers' O(ND) shortest edit script, or `None` past [`MAX_EDIT_DISTANCE`].
fn myers(a: &[&str], b: &[&str]) -> Option<Vec<Op>> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    let max = ((n + m) as usize).min(MAX_EDIT_DISTANCE) as isize;
    let offset = max + 1;
    let mut v = vec![0isize; (2 * max + 3) as usize];
    // `bands[d]` holds the frontier for diagonals `-d-1 ..= d+1` as it stood
    // when round `d` began: the only entries round `d` (and its backtrack
    // step) read. Storing the band rather than the whole frontier keeps
    // memory quadratic in the edit distance, not in the input size.
    let mut bands: Vec<Vec<isize>> = Vec::new();
    for d in 0..=max {
        bands.push(v[(offset - d - 1) as usize..=(offset + d + 1) as usize].to_vec());
        let mut k = -d;
        while k <= d {
            let idx = (k + offset) as usize;
            let mut x = if k == -d || (k != d && v[idx - 1] < v[idx + 1]) {
                v[idx + 1]
            } else {
                v[idx - 1] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[idx] = x;
            if x >= n && y >= m {
                return Some(backtrack(&bands, a.len(), b.len()));
            }
            k += 2;
        }
    }
    None
}

fn backtrack(bands: &[Vec<isize>], n: usize, m: usize) -> Vec<Op> {
    let mut ops = Vec::new();
    let (mut x, mut y) = (n as isize, m as isize);
    for (d, v) in bands.iter().enumerate().rev() {
        let d = d as isize;
        // Band index of diagonal `k` in round `d`.
        let idx = |k: isize| (k + d + 1) as usize;
        let k = x - y;
        let prev_k = if k == -d || (k != d && v[idx(k - 1)] < v[idx(k + 1)]) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = v[idx(prev_k)];
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            ops.push(Op::Equal);
            x -= 1;
            y -= 1;
        }
        if d > 0 {
            ops.push(if x == prev_x { Op::Insert } else { Op::Delete });
        }
        x = prev_x;
        y = prev_y;
    }
    ops.reverse();
    ops
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(old: &str, new: &str) -> Vec<Splice> {
        let s = splices(old, new);
        assert_eq!(apply(old, &s), new, "old={old:?} new={new:?} splices={s:?}");
        for w in s.windows(2) {
            assert!(w[0].at + w[0].delete <= w[1].at, "overlap {s:?}");
        }
        s
    }

    #[test]
    fn identical_text_needs_no_splice() {
        assert!(roundtrip("same\ntext\n", "same\ntext\n").is_empty());
        assert!(roundtrip("", "").is_empty());
    }

    #[test]
    fn distant_edits_stay_separate_hunks() {
        let old = "alpha\nbeta\ngamma\ndelta\nepsilon\n";
        let new = "ALPHA\nbeta\ngamma\ndelta\nepsilon!\n";
        let s = roundtrip(old, new);
        assert_eq!(s.len(), 2, "{s:?}");
        assert_eq!(
            s[0],
            Splice {
                at: 0,
                delete: 5,
                insert: "ALPHA".into()
            }
        );
        assert_eq!(s[1].insert, "!");
    }

    #[test]
    fn multibyte_text_splits_on_char_boundaries() {
        roundtrip("héllo 🌍 wörld", "héllo 🌎 wörld");
        roundtrip(
            "日本語のテキスト\n二行目\n",
            "日本語のテキスト\n三行目\n追加\n",
        );
        roundtrip("a\r\nb\r\n", "a\r\nc\r\nb\r\n");
        roundtrip("e\u{301}", "e\u{300}");
    }

    #[test]
    fn insertions_deletions_and_rewrites_roundtrip() {
        roundtrip("", "new body\n");
        roundtrip("old body\n", "");
        roundtrip("a\nb\nc\n", "c\nb\na\n");
        roundtrip("one\ntwo\nthree", "zero\none\nthree\nfour");
        roundtrip("x\n".repeat(50).as_str(), &"y\n".repeat(50));
    }

    #[test]
    fn past_the_edit_cap_falls_back_to_one_splice() {
        // Every line differs: far more than MAX_EDIT_DISTANCE line edits.
        let old: String = (0..2000).map(|i| format!("old {i}\n")).collect();
        let new: String = (0..2000).map(|i| format!("new {i}\n")).collect();
        let s = roundtrip(&old, &new);
        assert_eq!(s.len(), 1, "one splice past the cap");
    }

    #[test]
    fn large_bodies_with_few_edits_stay_minimal() {
        let old: String = (0..20_000).map(|i| format!("line {i}\n")).collect();
        let new = old.replacen("line 10\n", "line ten\n", 1).replacen(
            "line 19990\n",
            "line 19990 edited\n",
            1,
        );
        let s = roundtrip(&old, &new);
        assert_eq!(s.len(), 2, "{s:?}");
        assert!(s
            .iter()
            .all(|splice| splice.delete + splice.insert.len() < 40));
    }
}
