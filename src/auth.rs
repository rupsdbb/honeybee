//! Password login with stateless, HMAC-signed session cookies.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use miniscript::bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256};

pub const COOKIE_NAME: &str = "honeybee_session";
pub const SESSION_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

const MAX_FAILURES: u32 = 10;
const FAILURE_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Hash a password as `scrypt$log_n$r$p$salt$hash` (hex).
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt: [u8; 16] = rand::random();
    let hash = scrypt_hash(password, &salt, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)?;
    Ok(format!("scrypt${SCRYPT_LOG_N}${SCRYPT_R}${SCRYPT_P}${}${}", hex::encode(salt), hex::encode(hash)))
}

fn scrypt_hash(password: &str, salt: &[u8], log_n: u8, r: u32, p: u32) -> anyhow::Result<[u8; 32]> {
    let params = scrypt::Params::new(log_n, r, p).map_err(|e| anyhow!("scrypt params: {e}"))?;
    let mut out = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut out).map_err(|e| anyhow!("scrypt: {e}"))?;
    Ok(out)
}

struct ParsedHash {
    log_n: u8,
    r: u32,
    p: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

fn parse_hash(encoded: &str) -> anyhow::Result<ParsedHash> {
    let parts: Vec<&str> = encoded.trim().split('$').collect();
    let [alg, log_n, r, p, salt, hash] = parts.as_slice() else {
        bail!("malformed password hash");
    };
    if *alg != "scrypt" {
        bail!("unsupported password hash algorithm '{alg}'");
    }
    let parsed = ParsedHash {
        log_n: log_n.parse().context("log_n")?,
        r: r.parse().context("r")?,
        p: p.parse().context("p")?,
        salt: hex::decode(salt).context("salt")?,
        hash: hex::decode(hash).context("hash")?,
    };
    if parsed.log_n > 22 || parsed.hash.len() != 32 || parsed.salt.is_empty() {
        bail!("unsupported scrypt parameters");
    }
    scrypt::Params::new(parsed.log_n, parsed.r, parsed.p).map_err(|e| anyhow!("scrypt params: {e}"))?;
    Ok(parsed)
}

/// Check that a stored hash is well formed, without the cost of verifying.
pub fn validate_hash(encoded: &str) -> anyhow::Result<()> {
    parse_hash(encoded).map(|_| ())
}

pub fn verify_password(password: &str, encoded: &str) -> anyhow::Result<bool> {
    let h = parse_hash(encoded)?;
    let actual = scrypt_hash(password, &h.salt, h.log_n, h.r, h.p)?;
    Ok(constant_time_eq(&h.hash, &actual))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub struct Auth {
    /// `None` when authentication is disabled.
    password_hash: Option<String>,
    secret: [u8; 32],
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Auth {
    pub fn new(password_hash: Option<String>, secret: [u8; 32]) -> Auth {
        Auth { password_hash, secret, failures: Mutex::new(HashMap::new()) }
    }

    pub fn required(&self) -> bool {
        self.password_hash.is_some()
    }

    fn mac(&self, expiry: u64) -> String {
        let mut engine = HmacEngine::<sha256::Hash>::new(&self.secret);
        engine.input(b"honeybee-session-v1:");
        // Changing the password invalidates existing sessions.
        engine.input(self.password_hash.as_deref().unwrap_or("").as_bytes());
        engine.input(b":");
        engine.input(expiry.to_string().as_bytes());
        hex::encode(Hmac::<sha256::Hash>::from_engine(engine).to_byte_array())
    }

    pub fn issue_token(&self) -> String {
        let expiry = now_secs() + SESSION_TTL.as_secs();
        format!("{expiry}.{}", self.mac(expiry))
    }

    pub fn check_token(&self, token: &str) -> bool {
        let Some((expiry, mac)) = token.split_once('.') else { return false };
        let Ok(expiry) = expiry.parse::<u64>() else { return false };
        expiry > now_secs() && constant_time_eq(mac.as_bytes(), self.mac(expiry).as_bytes())
    }

    /// Returns Err with a message if this client is temporarily locked out.
    pub fn check_rate_limit(&self, ip: IpAddr) -> Result<(), String> {
        let mut failures = self.failures.lock().unwrap();
        failures.retain(|_, (_, since)| since.elapsed() < FAILURE_WINDOW);
        match failures.get(&ip) {
            Some((count, _)) if *count >= MAX_FAILURES => {
                Err("Too many failed attempts. Try again in a few minutes.".into())
            }
            _ => Ok(()),
        }
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let mut failures = self.failures.lock().unwrap();
        let entry = failures.entry(ip).or_insert((0, Instant::now()));
        entry.0 += 1;
    }

    /// Slow (scrypt); call from a blocking context.
    pub fn verify(&self, password: &str) -> bool {
        match &self.password_hash {
            None => true,
            Some(hash) => verify_password(password, hash).unwrap_or(false),
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let h = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &h).unwrap());
        assert!(!verify_password("wrong horse", &h).unwrap());
    }

    #[test]
    fn tokens() {
        let auth = Auth::new(Some(hash_password("pw").unwrap()), [7; 32]);
        let t = auth.issue_token();
        assert!(auth.check_token(&t));
        assert!(!auth.check_token(&t.replace('.', ".0")));
        assert!(!auth.check_token("1.abc"));
        let other = Auth::new(Some(hash_password("pw2").unwrap()), [7; 32]);
        assert!(!other.check_token(&t), "a password change must invalidate sessions");
    }
}
