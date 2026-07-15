pub fn canonical_hash(input: &str) -> String {
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::canonical_hash;

    #[test]
    fn canonical_hash_is_stable_for_same_input() {
        let a = canonical_hash("nexoia");
        let b = canonical_hash("nexoia");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn canonical_hash_changes_for_different_input() {
        let a = canonical_hash("alpha");
        let b = canonical_hash("beta");
        assert_ne!(a, b);
    }
}
