//! In-memory authentication backend.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::AuthError;
use crate::hash::sha224_hex;
use crate::result::AuthResult;
use crate::traits::AuthBackend;

/// Simple in-memory authentication backend using a hash set.
///
/// This is suitable for small deployments with a fixed set of users.
/// For dynamic user management or large user bases, consider using
/// a database-backed backend.
#[derive(Debug, Clone)]
pub struct MemoryAuth {
    /// Map from hash to optional user ID
    users: HashMap<String, Option<String>>,
}

impl MemoryAuth {
    /// Create a new empty auth backend.
    #[inline]
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    /// Create from pre-computed SHA224 hashes.
    ///
    /// # Example
    /// ```
    /// use trojan_auth::MemoryAuth;
    ///
    /// let auth = MemoryAuth::from_hashes(["abc123...", "def456..."]);
    /// ```
    pub fn from_hashes<I, S>(hashes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let users = hashes.into_iter().map(|h| (h.into(), None)).collect();
        Self { users }
    }

    /// Create from plaintext passwords (will be hashed).
    ///
    /// # Example
    /// ```
    /// use trojan_auth::MemoryAuth;
    ///
    /// let auth = MemoryAuth::from_passwords(["password1", "password2"]);
    /// ```
    pub fn from_passwords<I, S>(passwords: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let users = passwords
            .into_iter()
            .map(|p| (sha224_hex(p.as_ref()), None))
            .collect();
        Self { users }
    }

    /// Create from password-to-user-id pairs.
    ///
    /// # Example
    /// ```
    /// use trojan_auth::MemoryAuth;
    ///
    /// let auth = MemoryAuth::from_passwords_with_ids([
    ///     ("password1", "user1"),
    ///     ("password2", "user2"),
    /// ]);
    /// ```
    pub fn from_passwords_with_ids<I, P, U>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (P, U)>,
        P: AsRef<str>,
        U: Into<String>,
    {
        let users = pairs
            .into_iter()
            .map(|(p, u)| (sha224_hex(p.as_ref()), Some(u.into())))
            .collect();
        Self { users }
    }

    /// Add a user with a plaintext password.
    #[inline]
    pub fn add_password(&mut self, password: &str, user_id: Option<String>) {
        self.users.insert(sha224_hex(password), user_id);
    }

    /// Add a user with a pre-computed hash.
    #[inline]
    pub fn add_hash(&mut self, hash: String, user_id: Option<String>) {
        self.users.insert(hash, user_id);
    }

    /// Remove a user by hash.
    #[inline]
    pub fn remove_hash(&mut self, hash: &str) -> bool {
        self.users.remove(hash).is_some()
    }

    /// Get the number of registered users.
    #[inline]
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Check if no users are registered.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// Check if a hash is registered.
    #[inline]
    pub fn contains(&self, hash: &str) -> bool {
        self.users.contains_key(hash)
    }
}

impl Default for MemoryAuth {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthBackend for MemoryAuth {
    async fn verify(&self, hash: &str) -> Result<AuthResult, AuthError> {
        match self.users.get(hash) {
            Some(user_id) => Ok(AuthResult {
                user_id: user_id.clone(),
                metadata: None,
            }),
            None => Err(AuthError::Invalid),
        }
    }
}

// Backward compatibility alias
#[doc(hidden)]
pub type HashSetAuth = MemoryAuth;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_from_passwords() {
        let auth = MemoryAuth::from_passwords(["test123", "password"]);
        assert_eq!(auth.len(), 2);

        let hash = sha224_hex("test123");
        assert!(auth.verify(&hash).await.is_ok());

        let wrong_hash = sha224_hex("wrong");
        assert!(auth.verify(&wrong_hash).await.is_err());
    }

    #[tokio::test]
    async fn test_with_user_ids() {
        let auth = MemoryAuth::from_passwords_with_ids([("pass1", "user1"), ("pass2", "user2")]);

        let hash = sha224_hex("pass1");
        let result = auth.verify(&hash).await.unwrap();
        assert_eq!(result.user_id, Some("user1".to_string()));
    }

    #[test]
    fn test_add_remove() {
        let mut auth = MemoryAuth::new();
        assert!(auth.is_empty());

        auth.add_password("test", Some("user".to_string()));
        assert_eq!(auth.len(), 1);

        let hash = sha224_hex("test");
        assert!(auth.contains(&hash));

        auth.remove_hash(&hash);
        assert!(auth.is_empty());
    }
}
