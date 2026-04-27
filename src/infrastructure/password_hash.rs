use bcrypt::{hash, verify, BcryptError, DEFAULT_COST};

pub fn hash_secret(secret: &str) -> Result<String, BcryptError> {
    hash(secret, DEFAULT_COST)
}

pub fn verify_secret(secret: &str, hashed: &str) -> bool {
    verify(secret, hashed).unwrap_or(false)
}
