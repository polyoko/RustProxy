use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::fs::{File, read_to_string};
use std::io::Write;
use log::{info, warn, error};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_FAILED_ATTEMPTS: u32 = 10;
const BLACKLIST_FILE: &str = "blacklist.json";
const BAN_TTL_SECS: u64 = 15 * 60;

lazy_static! {
    static ref SECURITY_MANAGER: Mutex<SecurityManager> = Mutex::new(SecurityManager::new());
}

struct SecurityManager {
    blacklist: HashSet<String>,
    blacklist_expires_at: HashMap<String, u64>,
    failed_attempts: HashMap<String, u32>,
}

#[derive(Serialize, Deserialize)]
struct BlacklistRecord {
    ip: String,
    expires_at: u64,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

impl SecurityManager {
    fn new() -> Self {
        let mut sm = SecurityManager {
            blacklist: HashSet::new(),
            blacklist_expires_at: HashMap::new(),
            failed_attempts: HashMap::new(),
        };
        sm.load_blacklist();
        sm
    }

    fn load_blacklist(&mut self) {
        if let Ok(content) = read_to_string(BLACKLIST_FILE) {
            if let Ok(records) = serde_json::from_str::<Vec<BlacklistRecord>>(&content) {
                for record in records {
                    if record.expires_at > now_secs() {
                        self.blacklist.insert(record.ip.clone());
                        self.blacklist_expires_at.insert(record.ip, record.expires_at);
                    }
                }
            } else if let Ok(ips) = serde_json::from_str::<Vec<String>>(&content) {
                for ip in ips {
                    self.add_ban(ip);
                }
                self.save_blacklist();
            } else {
                warn!("Failed to parse {}", BLACKLIST_FILE);
            }
            info!("Loaded {} active blacklisted IPs from {}", self.blacklist.len(), BLACKLIST_FILE);
        } else {
            // Re-attempt loading from old txt if json is missing
            if let Ok(content) = read_to_string("blacklisted.txt") {
                for line in content.lines() {
                    let ip = line.trim().to_string();
                    if !ip.is_empty() {
                        self.add_ban(ip);
                    }
                }
                self.save_blacklist();
            }
        }
    }

    fn save_blacklist(&self) {
        let records: Vec<_> = self.blacklist.iter().filter_map(|ip| {
            self.blacklist_expires_at.get(ip).map(|expires_at| BlacklistRecord {
                ip: ip.clone(),
                expires_at: *expires_at,
            })
        }).collect();
        match serde_json::to_string_pretty(&records) {
            Ok(json_str) => {
                if let Ok(mut file) = File::create(BLACKLIST_FILE) {
                    let _ = file.write_all(json_str.as_bytes());
                } else {
                    error!("Could not open {} for writing.", BLACKLIST_FILE);
                }
            }
            Err(e) => error!("Failed to serialize blacklist: {}", e),
        }
    }

    fn add_ban(&mut self, ip: String) {
        self.blacklist.insert(ip.clone());
        self.blacklist_expires_at.insert(ip, now_secs() + BAN_TTL_SECS);
    }

    fn remove_expired(&mut self) -> bool {
        let now = now_secs();
        let expired: Vec<_> = self.blacklist.iter()
            .filter(|ip| self.blacklist_expires_at.get(*ip).map_or(true, |expires_at| *expires_at <= now))
            .cloned()
            .collect();
        for ip in &expired {
            self.blacklist.remove(ip);
            self.blacklist_expires_at.remove(ip);
            self.failed_attempts.remove(ip);
        }
        !expired.is_empty()
    }
}

pub fn is_blacklisted(ip: &str) -> bool {
    let mut sm = SECURITY_MANAGER.lock().unwrap();
    if sm.remove_expired() {
        sm.save_blacklist();
    }
    sm.blacklist.contains(ip)
}
pub fn report_failure(ip: &str) {
    let mut sm = SECURITY_MANAGER.lock().unwrap();
    if sm.remove_expired() {
        sm.save_blacklist();
    }
    if sm.blacklist.contains(ip) {
        return;
    }

    let ip_str = ip.to_string();
    let count = sm.failed_attempts.entry(ip_str.clone()).or_insert(0);
    *count += 1;

    warn!("Failed attempt from {}. Total attempts: {}/{}", ip_str, *count, MAX_FAILED_ATTEMPTS);

    if *count >= MAX_FAILED_ATTEMPTS {
        warn!("IP {} reached max failed attempts. Temporary blacklist applied for {} seconds.", ip_str, BAN_TTL_SECS);
        sm.add_ban(ip_str);
        sm.save_blacklist();
    }
}

pub fn report_success(ip: &str) {
    let mut sm = SECURITY_MANAGER.lock().unwrap();
    sm.failed_attempts.remove(ip);
}

pub fn get_blacklist() -> Vec<String> {
    let mut sm = SECURITY_MANAGER.lock().unwrap();
    if sm.remove_expired() {
        sm.save_blacklist();
    }
    let mut ips: Vec<_> = sm.blacklist.iter().cloned().collect();
    ips.sort();
    ips
}

pub fn add_to_blacklist(ip: String) -> bool {
    let mut sm = SECURITY_MANAGER.lock().unwrap();
    if sm.remove_expired() {
        sm.save_blacklist();
    }
    if !sm.blacklist.contains(&ip) {
        sm.add_ban(ip);
        sm.save_blacklist();
        true
    } else {
        false
    }
}

pub fn remove_from_blacklist(ip: &str) -> bool {
    let mut sm = SECURITY_MANAGER.lock().unwrap();
    if sm.blacklist.remove(ip) {
        sm.blacklist_expires_at.remove(ip);
        sm.failed_attempts.remove(ip);
        sm.save_blacklist();
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_bans_are_removed() {
        let mut sm = SecurityManager {
            blacklist: HashSet::from(["expired".to_string(), "active".to_string()]),
            blacklist_expires_at: HashMap::from([
                ("expired".to_string(), now_secs().saturating_sub(1)),
                ("active".to_string(), now_secs() + 60),
            ]),
            failed_attempts: HashMap::new(),
        };
        assert!(sm.remove_expired());
        assert!(!sm.blacklist.contains("expired"));
        assert!(sm.blacklist.contains("active"));
    }
}
