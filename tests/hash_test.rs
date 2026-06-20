use nexoia::hash::canonical_hash;

#[test]
fn hash_returns_64_char_hex() {
    let h = canonical_hash("test");
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hash_is_deterministic() {
    let a = canonical_hash("deterministic");
    let b = canonical_hash("deterministic");
    assert_eq!(a, b);
}

#[test]
fn empty_input_hashes() {
    let h = canonical_hash("");
    assert_eq!(h.len(), 64);
}
