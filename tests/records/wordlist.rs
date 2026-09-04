//! The run-key wordlists satisfy their distance floor (task `cb6c9da`).
//!
//! `src/wordlist.rs` is static data with a property, and the property is the
//! entire reason the three-word run key of `508dd9e` / `62a6a09` §3 is viable
//! at all: without it a typo turns one valid key into a *different valid key*,
//! and the design's silent-failure mode returns. So the floor is recomputed
//! here on every run rather than asserted in a comment.
//!
//! The distance implementation has MOVED into the crate, exactly as this file
//! anticipated: the write-path break (`ddee1f0` / spec `fbfaf25` §3.2) made the
//! engine repair keys, so `MIN_DISTANCE` stopped being a property to verify and
//! became a property the engine relies on — at a floor of 3 a single-character
//! garble has exactly one nearest valid word, which is what lets `crate::runkey`
//! hand a mistyped key back with the word it meant. The checker now lives beside
//! the data it makes usable, and this file keeps checking it.

use native_ce::wordlist::{damerau_levenshtein, DISAMBIGUATORS, HANDLES, MIN_DISTANCE};
use std::collections::HashSet;

#[test]
fn damerau_levenshtein_is_correct_on_known_pairs() {
    // Pin the checker before trusting it against 200k pairs of real data.
    assert_eq!(damerau_levenshtein("chair", "chair"), 0);
    assert_eq!(damerau_levenshtein("chair", "chain"), 1); // substitution
    assert_eq!(damerau_levenshtein("chair", "chai"), 1); // deletion
    assert_eq!(damerau_levenshtein("chair", "chairs"), 1); // insertion
    assert_eq!(damerau_levenshtein("chair", "chiar"), 1); // transposition
    assert_eq!(damerau_levenshtein("", "abc"), 3);
    assert_eq!(damerau_levenshtein("scout", "jam"), 5);

    // The case that separates unrestricted DL from OSA: OSA scores this 3
    // because it forbids editing a substring twice, true DL scores it 2.
    assert_eq!(damerau_levenshtein("ca", "abc"), 2);
}

/// The property the whole design rests on, for both lists.
#[test]
fn every_pair_within_a_list_is_at_least_min_distance_apart() {
    for (name, list) in [
        ("HANDLES", &HANDLES[..]),
        ("DISAMBIGUATORS", &DISAMBIGUATORS[..]),
    ] {
        let mut worst: Option<(&str, &str, usize)> = None;
        for i in 0..list.len() {
            for j in (i + 1)..list.len() {
                let d = damerau_levenshtein(list[i], list[j]);
                assert!(
                    d >= MIN_DISTANCE,
                    "{name}: {:?} and {:?} are {d} apart, floor is {MIN_DISTANCE}. \
                     A single typo can turn one valid key into another.",
                    list[i],
                    list[j],
                );
                if worst.is_none_or(|(_, _, w)| d < w) {
                    worst = Some((list[i], list[j], d));
                }
            }
        }
        let (a, b, d) = worst.expect("list is non-empty");
        assert!(d >= MIN_DISTANCE, "{name}: closest pair {a}/{b} at {d}");
    }
}

/// There is deliberately NO cross-list constraint — position is structural, so
/// the parser splits on the first hyphen and a word may serve both roles. This
/// test pins that as an intended property rather than leaving it to be
/// "fixed" later by someone who reads the overlap as a bug.
#[test]
fn the_lists_may_overlap_and_that_is_intended() {
    let labels: HashSet<&str> = HANDLES.iter().copied().collect();
    let overlap = DISAMBIGUATORS
        .iter()
        .filter(|w| labels.contains(*w))
        .count();
    assert!(
        overlap > 0,
        "expected some shared words; if this ever hits zero the lists were \
         forced disjoint, which costs useful disambiguators to buy a cosmetic property"
    );
}

#[test]
fn lists_are_the_documented_sizes() {
    assert_eq!(HANDLES.len(), 256);
    assert_eq!(DISAMBIGUATORS.len(), 512);
}

#[test]
fn every_word_is_unique_within_its_list() {
    for (name, list) in [
        ("HANDLES", &HANDLES[..]),
        ("DISAMBIGUATORS", &DISAMBIGUATORS[..]),
    ] {
        let unique: HashSet<&str> = list.iter().copied().collect();
        assert_eq!(unique.len(), list.len(), "{name} contains a duplicate");
    }
}

/// Shape constraints. A key is typed, hyphen-separated and sometimes dictated,
/// so anything outside `[a-z]` in the 4-7 band would break the split or the
/// retyping.
#[test]
fn every_word_is_lowercase_ascii_in_the_length_band() {
    for (name, list) in [
        ("HANDLES", &HANDLES[..]),
        ("DISAMBIGUATORS", &DISAMBIGUATORS[..]),
    ] {
        for w in list {
            assert!(
                (4..=7).contains(&w.len()),
                "{name}: {w:?} is {} characters, band is 4-7",
                w.len()
            );
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "{name}: {w:?} is not lowercase ASCII"
            );
        }
    }
}

/// A hyphen in a word would make the key ambiguous to split, since the label
/// is defined as everything before the first hyphen.
#[test]
fn no_word_contains_a_hyphen() {
    for w in HANDLES.iter().chain(DISAMBIGUATORS.iter()) {
        assert!(!w.contains('-'), "{w:?} contains a hyphen");
    }
}
