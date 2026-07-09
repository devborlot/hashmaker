use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use bcrypt::{hash as bcrypt_hash, DEFAULT_COST};
use pbkdf2::pbkdf2_hmac;
use rand_core::{OsRng, RngCore};
use scrypt::{scrypt, Params as ScryptParams};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
    Blake2b,
    Blake2s,
    Bcrypt,
    Argon2id,
    Pbkdf2Sha256,
    Scrypt,
    Wordpress,
}

impl Algorithm {
    pub fn all() -> &'static [Algorithm] {
        &[
            Algorithm::Md5,
            Algorithm::Sha1,
            Algorithm::Sha256,
            Algorithm::Sha512,
            Algorithm::Sha3_256,
            Algorithm::Sha3_512,
            Algorithm::Blake2b,
            Algorithm::Blake2s,
            Algorithm::Bcrypt,
            Algorithm::Argon2id,
            Algorithm::Pbkdf2Sha256,
            Algorithm::Scrypt,
            Algorithm::Wordpress,
        ]
    }

    pub fn from_str(name: &str) -> Option<Algorithm> {
        match name.to_lowercase().as_str() {
            "md5" => Some(Algorithm::Md5),
            "sha1" => Some(Algorithm::Sha1),
            "sha256" => Some(Algorithm::Sha256),
            "sha512" => Some(Algorithm::Sha512),
            "sha3_256" => Some(Algorithm::Sha3_256),
            "sha3_512" => Some(Algorithm::Sha3_512),
            "blake2b" => Some(Algorithm::Blake2b),
            "blake2s" => Some(Algorithm::Blake2s),
            "bcrypt" => Some(Algorithm::Bcrypt),
            "argon2id" => Some(Algorithm::Argon2id),
            "pbkdf2_sha256" => Some(Algorithm::Pbkdf2Sha256),
            "scrypt" => Some(Algorithm::Scrypt),
            "wordpress" => Some(Algorithm::Wordpress),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Algorithm::Md5 => "MD5",
            Algorithm::Sha1 => "SHA-1",
            Algorithm::Sha256 => "SHA-256",
            Algorithm::Sha512 => "SHA-512",
            Algorithm::Sha3_256 => "SHA3-256",
            Algorithm::Sha3_512 => "SHA3-512",
            Algorithm::Blake2b => "BLAKE2b",
            Algorithm::Blake2s => "BLAKE2s",
            Algorithm::Bcrypt => "bcrypt",
            Algorithm::Argon2id => "Argon2id",
            Algorithm::Pbkdf2Sha256 => "PBKDF2-SHA256",
            Algorithm::Scrypt => "scrypt",
            Algorithm::Wordpress => "WordPress",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            Algorithm::Md5 | Algorithm::Sha1 | Algorithm::Sha256 | Algorithm::Sha512
            | Algorithm::Sha3_256 | Algorithm::Sha3_512 | Algorithm::Blake2b
            | Algorithm::Blake2s => "digest",
            Algorithm::Bcrypt | Algorithm::Argon2id | Algorithm::Pbkdf2Sha256
            | Algorithm::Scrypt | Algorithm::Wordpress => "password",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Algorithm::Md5 => "Legacy 128-bit digest — not secure for passwords",
            Algorithm::Sha1 => "160-bit digest — deprecated for security use",
            Algorithm::Sha256 => "256-bit SHA-2 digest",
            Algorithm::Sha512 => "512-bit SHA-2 digest",
            Algorithm::Sha3_256 => "256-bit SHA-3 digest",
            Algorithm::Sha3_512 => "512-bit SHA-3 digest",
            Algorithm::Blake2b => "Fast cryptographic hash (512-bit output)",
            Algorithm::Blake2s => "Fast cryptographic hash (256-bit output)",
            Algorithm::Bcrypt => "Adaptive password hash with salt",
            Algorithm::Argon2id => "Modern memory-hard password hash (recommended)",
            Algorithm::Pbkdf2Sha256 => "Key derivation with configurable iterations",
            Algorithm::Scrypt => "Memory-hard password-based KDF",
            Algorithm::Wordpress => "phpass portable hash ($P$) used by WordPress",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap().trim_matches('"'))
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct HashOptions {
    #[serde(default = "default_bcrypt_cost")]
    pub bcrypt_cost: u32,
    #[serde(default = "default_pbkdf2_iterations")]
    pub pbkdf2_iterations: u32,
    #[serde(default = "default_wordpress_log2")]
    pub wordpress_log2: u32,
}

fn default_bcrypt_cost() -> u32 {
    DEFAULT_COST
}

fn default_pbkdf2_iterations() -> u32 {
    100_000
}

fn default_wordpress_log2() -> u32 {
    8
}

pub struct HashError {
    pub message: String,
}

impl HashError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub fn hash_password(
    password: &str,
    algorithm: Algorithm,
    options: &HashOptions,
) -> Result<String, HashError> {
    if password.is_empty() {
        return Err(HashError::new("Password cannot be empty"));
    }

    match algorithm {
        Algorithm::Md5 => {
            use md5::{Digest as _, Md5};
            Ok(hex::encode(Md5::digest(password.as_bytes())))
        }
        Algorithm::Sha1 => Ok(hex::encode(Sha1::digest(password.as_bytes()))),
        Algorithm::Sha256 => Ok(hex::encode(Sha256::digest(password.as_bytes()))),
        Algorithm::Sha512 => Ok(hex::encode(Sha512::digest(password.as_bytes()))),
        Algorithm::Sha3_256 => Ok(hex::encode(Sha3_256::digest(password.as_bytes()))),
        Algorithm::Sha3_512 => Ok(hex::encode(Sha3_512::digest(password.as_bytes()))),
        Algorithm::Blake2b => {
            use blake2::Blake2b512;
            Ok(hex::encode(Blake2b512::digest(password.as_bytes())))
        }
        Algorithm::Blake2s => {
            use blake2::Blake2s256;
            Ok(hex::encode(Blake2s256::digest(password.as_bytes())))
        }
        Algorithm::Bcrypt => {
            // Uses the `bcrypt` crate → OpenBSD format `$2b$<cost>$<22-char salt><31-char hash>`
            // Compatible with Elixir `Bcrypt.hash_pwd_salt/2` / `Bcrypt.verify_pass/2` ($2b$).
            let cost = options.bcrypt_cost.clamp(4, 31);
            bcrypt_hash(password, cost).map_err(|e| HashError::new(e.to_string()))
        }
        Algorithm::Argon2id => {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            argon2
                .hash_password(password.as_bytes(), &salt)
                .map(|h| h.to_string())
                .map_err(|e| HashError::new(e.to_string()))
        }
        Algorithm::Pbkdf2Sha256 => {
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let mut derived = [0u8; 32];
            pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                &salt,
                options.pbkdf2_iterations,
                &mut derived,
            );
            Ok(format!(
                "{}:{}",
                hex::encode(salt),
                hex::encode(derived)
            ))
        }
        Algorithm::Scrypt => {
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let params = ScryptParams::new(14, 8, 1, 32)
                .map_err(|e| HashError::new(e.to_string()))?;
            let mut derived = [0u8; 32];
            scrypt(password.as_bytes(), &salt, &params, &mut derived)
                .map_err(|e| HashError::new(e.to_string()))?;
            Ok(format!(
                "{}:{}",
                hex::encode(salt),
                hex::encode(derived)
            ))
        }
        Algorithm::Wordpress => {
            crate::wordpress::hash_wordpress_phpass(password, options.wordpress_log2)
                .map_err(HashError::new)
        }
    }
}
