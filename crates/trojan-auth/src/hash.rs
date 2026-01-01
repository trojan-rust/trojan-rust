//! Password hashing utilities.

use sha2::{Digest, Sha224};

/// Compute SHA224 hash and return as lowercase hex string.
///
/// This is the standard hash function used by the Trojan protocol.
///
/// # Example
/// ```
/// use trojan_auth::sha224_hex;
///
/// let hash = sha224_hex("password123");
/// assert_eq!(hash.len(), 56); // SHA224 = 224 bits = 28 bytes = 56 hex chars
/// ```
#[inline]
pub fn sha224_hex(input: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Verify if a hash matches a plaintext password.
#[inline]
pub fn verify_password(password: &str, hash: &str) -> bool {
    sha224_hex(password) == hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha224_hex() {
        // Known test vector
        let hash = sha224_hex("password");
        assert_eq!(hash.len(), 56);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_verify_password() {
        let hash = sha224_hex("test123");
        assert!(verify_password("test123", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn test_consistency() {
        let password = "my_secret_password";
        let hash1 = sha224_hex(password);
        let hash2 = sha224_hex(password);
        assert_eq!(hash1, hash2);
    }
}
