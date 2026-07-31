//! User authentication lookup for NaiveProxy
//!
//! Provides O(1) user lookup with constant-time credential comparison
//! to prevent timing attacks.

use std::collections::HashMap;

use base64::engine::{Engine as _, general_purpose::STANDARD as BASE64};
use subtle::ConstantTimeEq;

use crate::tcp::tcp_handler::AuthenticatedUser;

/// Single user credential entry
struct UserEntry {
    /// Base64-encoded "user:pass" for comparison
    encoded: Vec<u8>,
    /// Display name (for logging)
    name: String,
    /// Optional authenticated runtime user for traffic accounting and policy enforcement.
    authenticated_user: Option<AuthenticatedUser>,
}

pub struct ValidatedUser<'a> {
    pub name: &'a str,
    pub authenticated_user: Option<&'a AuthenticatedUser>,
}

/// O(1) user lookup with constant-time credential comparison.
///
/// Uses BLAKE3 hash for fast lookup, then constant-time comparison
/// of actual credentials to prevent timing attacks.
pub struct UserLookup {
    /// Hash of encoded credentials -> index in users vec
    lookup: HashMap<[u8; 32], usize>,
    /// User entries
    users: Vec<UserEntry>,
}

impl std::fmt::Debug for UserLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserLookup")
            .field("num_users", &self.users.len())
            .finish()
    }
}

impl UserLookup {
    /// Create a new user lookup table from (name, username, password) tuples.
    ///
    /// # Panics
    /// Panics if credentials is empty (config validation should prevent this).
    pub fn new(credentials: Vec<(String, String, String)>) -> Self {
        Self::new_with_authenticated_users(
            credentials
                .into_iter()
                .map(|(name, username, password)| (name, username, password, None))
                .collect(),
        )
    }

    /// Create a new user lookup table from (name, username, password, authenticated user) tuples.
    ///
    /// # Panics
    /// Panics if credentials is empty (config validation should prevent this).
    pub fn new_with_authenticated_users(
        credentials: Vec<(String, String, String, Option<AuthenticatedUser>)>,
    ) -> Self {
        assert!(
            !credentials.is_empty(),
            "NaiveProxy requires at least one user"
        );
        let mut lookup = HashMap::with_capacity(credentials.len());
        let mut users = Vec::with_capacity(credentials.len());

        for (i, (name, username, password, authenticated_user)) in
            credentials.into_iter().enumerate()
        {
            let cred_string = format!("{}:{}", username, password);
            let encoded = BASE64.encode(&cred_string).into_bytes();
            let hash = blake3::hash(&encoded);
            lookup.insert(*hash.as_bytes(), i);
            users.push(UserEntry {
                encoded,
                name,
                authenticated_user,
            });
        }

        Self { lookup, users }
    }

    /// Validate credentials, returning the user's runtime identity if valid.
    ///
    /// O(1) lookup via hash, then constant-time comparison for security.
    pub fn validate(&self, auth_header: &str) -> Option<ValidatedUser<'_>> {
        let encoded = auth_header.strip_prefix("Basic ")?.as_bytes();
        let hash = blake3::hash(encoded);
        let idx = self.lookup.get(hash.as_bytes())?;
        let user = &self.users[*idx];

        // Constant-time comparison as defense in depth
        if user.encoded.ct_eq(encoded).unwrap_u8() == 1 {
            Some(ValidatedUser {
                name: &user.name,
                authenticated_user: user.authenticated_user.as_ref(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_lookup_basic() {
        let lookup = UserLookup::new(vec![(
            "alice".to_string(),
            "user".to_string(),
            "pass".to_string(),
        )]);
        // Base64 of "user:pass" is "dXNlcjpwYXNz"
        assert_eq!(lookup.validate("Basic dXNlcjpwYXNz").unwrap().name, "alice");
        assert_eq!(lookup.users.len(), 1);
    }

    #[test]
    fn test_user_lookup_special_chars() {
        // Test with special characters in password
        let lookup = UserLookup::new(vec![(
            "bob".to_string(),
            "user".to_string(),
            "p@ss:w0rd!".to_string(),
        )]);
        // Encode "user:p@ss:w0rd!" to base64
        let encoded = BASE64.encode("user:p@ss:w0rd!");
        let header = format!("Basic {}", encoded);
        assert_eq!(lookup.validate(&header).unwrap().name, "bob");
    }

    #[test]
    fn test_user_lookup_empty_password() {
        let lookup = UserLookup::new(vec![(
            "test".to_string(),
            "user".to_string(),
            "".to_string(),
        )]);
        let encoded = BASE64.encode("user:");
        let header = format!("Basic {}", encoded);
        assert_eq!(lookup.validate(&header).unwrap().name, "test");
    }

    #[test]
    fn test_user_lookup_invalid_credentials() {
        let lookup = UserLookup::new(vec![(
            "alice".to_string(),
            "user".to_string(),
            "pass".to_string(),
        )]);
        assert!(lookup.validate("Basic invalid").is_none());
        assert!(lookup.validate("Basic d3Jvbmc6cGFzcw==").is_none()); // wrong:pass
        assert!(lookup.validate("Bearer token").is_none());
        assert!(lookup.validate("").is_none());
    }

    #[test]
    fn test_user_lookup_multiple_users() {
        let lookup = UserLookup::new(vec![
            (
                "alice".to_string(),
                "alice".to_string(),
                "alice123".to_string(),
            ),
            ("bob".to_string(), "bob".to_string(), "bob456".to_string()),
            (
                "charlie".to_string(),
                "charlie".to_string(),
                "charlie789".to_string(),
            ),
        ]);
        assert_eq!(lookup.users.len(), 3);

        let alice_header = format!("Basic {}", BASE64.encode("alice:alice123"));
        let bob_header = format!("Basic {}", BASE64.encode("bob:bob456"));
        let charlie_header = format!("Basic {}", BASE64.encode("charlie:charlie789"));

        assert_eq!(lookup.validate(&alice_header).unwrap().name, "alice");
        assert_eq!(lookup.validate(&bob_header).unwrap().name, "bob");
        assert_eq!(lookup.validate(&charlie_header).unwrap().name, "charlie");
    }

    #[test]
    fn test_user_lookup_returns_authenticated_user() {
        let authenticated_user = AuthenticatedUser {
            node_tag: "node-a".to_string(),
            uid: 42,
            user_key: "user-42".to_string(),
            speed_limit: Some(10),
            device_limit: Some(2),
            recorder: None,
        };
        let lookup = UserLookup::new_with_authenticated_users(vec![(
            "alice".to_string(),
            "user-42".to_string(),
            "secret".to_string(),
            Some(authenticated_user),
        )]);

        let header = format!("Basic {}", BASE64.encode("user-42:secret"));
        let user = lookup.validate(&header).unwrap();

        assert_eq!(user.name, "alice");
        assert_eq!(user.authenticated_user.unwrap().uid, 42);
    }
}
