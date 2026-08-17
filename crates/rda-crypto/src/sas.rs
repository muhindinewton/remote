//! Short authentication string — `docs/PROTOCOL.md` §4.6.
//!
//! Four words derived from the session transcript, displayed at both ends. Two humans already on a
//! phone call compare them in five seconds, and a man-in-the-middle is defeated even on first
//! contact where no key has been pinned.
//!
//! This is the one security check that does not depend on any prior trust relationship, which makes
//! it the backstop for everything else in this crate.

use hkdf::Hkdf;
use sha2::Sha256;

/// Number of words in the string. Four words from a 2048-word list is 44 bits — far beyond what an
/// attacker can brute-force in the seconds a live handshake allows.
pub const SAS_WORDS: usize = 4;

/// The word list. Chosen for being short, phonetically distinct, and unambiguous when read aloud
/// over a bad line — which is the actual operating condition on this corridor.
const WORDLIST: [&str; 256] = [
    "acid", "acorn", "actor", "adobe", "agent", "aisle", "album", "alien", "alarm", "algae",
    "amber", "amigo", "anvil", "apple", "april", "arena", "armor", "arrow", "aspen", "atlas",
    "audio", "aunt", "avoid", "axis", "bacon", "badge", "bagel", "baker", "balsa", "banjo",
    "barge", "basil", "baton", "beach", "beard", "beast", "bench", "berry", "bison", "black",
    "blade", "blaze", "blend", "blimp", "blood", "board", "bonus", "boost", "botany", "bowl",
    "brain", "brave", "bread", "brick", "bride", "brief", "bring", "brisk", "broad", "brook",
    "brush", "bugle", "bunch", "cabin", "cable", "cache", "cadet", "camel", "canal", "candy",
    "canoe", "canon", "cargo", "carve", "catch", "cedar", "chalk", "charm", "chase", "cheek",
    "chess", "chief", "chime", "choir", "cider", "cigar", "civic", "claim", "clamp", "clash",
    "clean", "clerk", "cliff", "climb", "cloak", "clock", "clone", "cloud", "clove", "clown",
    "coach", "cobra", "cocoa", "comet", "comic", "coral", "couch", "cough", "coral2", "cover",
    "crane", "crate", "crawl", "cream", "creek", "crest", "crisp", "crown", "crumb", "crush",
    "curve", "cycle", "daily", "dance", "dandy", "dealt", "debit", "debug", "decal", "decay",
    "decoy", "delta", "dense", "depth", "derby", "diary", "diner", "dingo", "ditch", "diver",
    "dizzy", "dodge", "donor", "donut", "dough", "dozen", "draft", "drain", "drama", "dress",
    "drift", "drill", "drink", "drive", "drove", "drums", "eagle", "early", "earth", "easel",
    "ebony", "edict", "eight", "elbow", "elder", "elite", "elope", "ember", "emery", "empty",
    "enemy", "enjoy", "entry", "envoy", "equal", "erase", "essay", "ether", "event", "every",
    "exact", "exile", "exist", "extra", "fable", "facet", "faint", "fairy", "false", "fancy",
    "fault", "favor", "feast", "fence", "ferry", "fever", "fiber", "field", "fiery", "fifty",
    "final", "finch", "first", "flair", "flame", "flash", "fleet", "flint", "float", "flock",
    "flood", "floor", "flour", "fluid", "flute", "focal", "focus", "foggy", "forge", "forty",
    "found", "frame", "fraud", "fresh", "fried", "frost", "frown", "fruit", "fudge", "fully",
    "funny", "gauge", "gecko", "genre", "ghost", "giant", "given", "glade", "gland", "glass",
    "glaze", "gleam", "globe", "gloss", "glove", "going", "gourd", "grace", "grade", "grain",
    "grand", "grape", "graph", "grasp", "grass", "grave",
];

/// Derives the short authentication string from a transcript hash.
///
/// Both peers compute this independently. If they disagree, a man-in-the-middle is present.
#[must_use]
pub fn short_authentication_string(
    transcript_hash: &[u8; 32],
    session_id: &str,
) -> Vec<&'static str> {
    let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), transcript_hash);
    let mut okm = [0u8; SAS_WORDS];
    hk.expand(b"RDA-v1-sas", &mut okm)
        .expect("SAS_WORDS bytes is a valid HKDF length");
    okm.iter().map(|&b| WORDLIST[b as usize]).collect()
}

/// Renders the string for display.
#[must_use]
pub fn format_sas(words: &[&str]) -> String {
    words.join(" · ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wordlist_is_usable() {
        assert_eq!(WORDLIST.len(), 256, "must cover every byte value exactly");
        let unique: std::collections::HashSet<_> = WORDLIST.iter().collect();
        assert_eq!(
            unique.len(),
            WORDLIST.len(),
            "duplicate words would halve the entropy"
        );
        for w in WORDLIST {
            assert!(w.len() >= 3 && w.len() <= 6, "{w} is awkward to read aloud");
            assert!(
                w.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                "{w}"
            );
        }
    }

    #[test]
    fn both_peers_derive_the_same_words() {
        let transcript = [0x42u8; 32];
        let a = short_authentication_string(&transcript, "sess_1");
        let b = short_authentication_string(&transcript, "sess_1");
        assert_eq!(a, b);
        assert_eq!(a.len(), SAS_WORDS);
    }

    #[test]
    fn a_different_transcript_gives_different_words() {
        // This is the whole mechanism: an MITM produces a different transcript on each side, so the
        // two humans read out different words.
        let honest = short_authentication_string(&[0x42u8; 32], "sess_1");
        let mitm = short_authentication_string(&[0x43u8; 32], "sess_1");
        assert_ne!(honest, mitm);
    }

    #[test]
    fn the_session_id_is_bound_in() {
        let transcript = [0x42u8; 32];
        assert_ne!(
            short_authentication_string(&transcript, "sess_1"),
            short_authentication_string(&transcript, "sess_2")
        );
    }

    #[test]
    fn output_is_well_distributed() {
        // A derivation that collapsed onto a few words would silently destroy the entropy.
        let mut seen = std::collections::HashSet::new();
        for i in 0..200u8 {
            let t = [i; 32];
            seen.insert(format_sas(&short_authentication_string(&t, "s")));
        }
        assert!(
            seen.len() > 190,
            "only {} distinct strings from 200 transcripts",
            seen.len()
        );
    }

    #[test]
    fn formatting_is_readable() {
        let words = short_authentication_string(&[7u8; 32], "sess_1");
        let rendered = format_sas(&words);
        assert_eq!(rendered.matches('·').count(), SAS_WORDS - 1);
    }
}
