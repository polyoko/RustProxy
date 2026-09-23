//! Dashboard login sessions: random token -> expiry, held in memory.
//! ponytail: in-memory store, sessions die on server restart (re-login once); signed cookies if that ever matters.

use dashmap::DashMap;
use std::io::Read;
use std::time::{Duration, Instant};

pub const COOKIE_NAME: &str = "rp_session";
pub const TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const MAX_SESSIONS: usize = 100;

lazy_static::lazy_static! {
    static ref SESSIONS: DashMap<String, Instant> = DashMap::new();
}

/// Creates a session and returns its token. Fails if the OS RNG is unavailable (never falls back to a guessable token).
pub fn create() -> std::io::Result<String> {
    let token = random_token()?;
    insert(token.clone(), Instant::now() + TTL);
    Ok(token)
}

/// Returns a random 256-bit token without storing it as a dashboard session.
pub fn random_token() -> std::io::Result<String> {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

fn insert(token: String, expires_at: Instant) {
    if SESSIONS.len() >= MAX_SESSIONS {
        let now = Instant::now();
        SESSIONS.retain(|_, exp| *exp > now);
    }
    while SESSIONS.len() >= MAX_SESSIONS {
        let oldest = SESSIONS.iter().min_by_key(|e| *e.value()).map(|e| e.key().clone());
        match oldest {
            Some(k) => { SESSIONS.remove(&k); }
            None => break,
        }
    }
    SESSIONS.insert(token, expires_at);
}

pub fn is_valid(token: &str) -> bool {
    let expired = match SESSIONS.get(token) {
        Some(exp) => *exp <= Instant::now(),
        None => return false,
    };
    if expired {
        SESSIONS.remove(token);
    }
    !expired
}

pub fn revoke(token: &str) {
    SESSIONS.remove(token);
}

/// Extracts our session token from a raw `Cookie:` header value.
pub fn token_from_cookie_header(header: &str) -> Option<&str> {
    header.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        (k == COOKIE_NAME && !v.is_empty()).then_some(v)
    })
}

/// `secure` only when the request came over HTTPS: browsers drop `Secure` cookies on plain-HTTP origins (README's `http://<VPS_IP>:8081`).
pub fn set_cookie_header(token: &str, secure: bool) -> String {
    format!("Set-Cookie: {}={}; HttpOnly;{} SameSite=Strict; Path=/; Max-Age={}", COOKIE_NAME, token, if secure { " Secure;" } else { "" }, TTL.as_secs())
}

pub fn clear_cookie_header(secure: bool) -> String {
    format!("Set-Cookie: {}=; HttpOnly;{} SameSite=Strict; Path=/; Max-Age=0", COOKIE_NAME, if secure { " Secure;" } else { "" })
}

/// Constant-time comparison so password checks don't leak how many leading bytes matched.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_lifecycle() {
        let t = create().unwrap();
        assert_eq!(t.len(), 64);
        assert!(is_valid(&t));
        revoke(&t);
        assert!(!is_valid(&t));
        assert!(!is_valid("forged"));

        // cap: checked in the same test because SESSIONS is global and tests run in parallel
        for _ in 0..MAX_SESSIONS + 5 {
            create().unwrap();
        }
        assert!(SESSIONS.len() <= MAX_SESSIONS);
    }

    #[test]
    fn expired_session_is_rejected() {
        insert("expired-token".into(), Instant::now());
        assert!(!is_valid("expired-token"));
    }

    #[test]
    fn parses_cookie_header() {
        assert_eq!(token_from_cookie_header("a=1; rp_session=abc; b=2"), Some("abc"));
        assert_eq!(token_from_cookie_header("rp_session="), None);
        assert_eq!(token_from_cookie_header("x_rp_session=abc"), None);
    }

    #[test]
    fn secure_flag_follows_scheme() {
        assert!(set_cookie_header("t", true).contains("Secure;"));
        assert!(!set_cookie_header("t", false).contains("Secure"));
    }

    #[test]
    fn compares_passwords() {
        assert!(constant_time_eq("secret", "secret"));
        assert!(!constant_time_eq("secret", "secreT"));
        assert!(!constant_time_eq("secret", "secret1"));
    }
}
