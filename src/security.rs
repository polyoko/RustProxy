use std::collections::HashMap;
use std::sync::Mutex;
use std::fs::{File, read_to_string};
use std::io::Write;
use log::{info, warn, error};
use lazy_static::lazy_static;

const MAX_FAILED_ATTEMPTS: u32 = 10;
const BLACKLIST_FILE: &str = "blacklist.json";

lazy_static! {
    static ref SECURITY_MANAGER: Mutex<SecurityManager> = Mutex::new(SecurityManager::new());
}

struct SecurityManager {
    blacklist: Vec<String>,
    failed_attempts: HashMap<String, u32>,
}

impl SecurityManager {
    fn new() -> Self {
        let mut sm = SecurityManager {
            blacklist: Vec::new(),
            failed_attempts: HashMap::new(),
        };
        sm.load_blacklist();
        sm
    }

    fn load_blacklist(&mut self) {
        if let Ok(content) = read_to_string(BLACKLIST_FILE) {
            match serde_json::from_str::<Vec<String>>(&content) {
                Ok(ips) => {
                    self.blacklist = ips;
                    info!("Loaded {} blacklisted IPs from {}", self.blacklist.len(), BLACKLIST_FILE);
                }
                Err(e) => warn!("Failed to parse {}: {}", BLACKLIST_FILE, e),
            }
        } else {
            // Re-attempt loading from old txt if json is missing
            if let Ok(content) = read_to_string("blacklisted.txt") {
                for line in content.lines() {
                    let ip = line.trim().to_string();
                    if !ip.is_empty() {
                        self.blacklist.push(ip);
                    }
                }
                self.save_blacklist();
            }
        }
    }

    fn save_blacklist(&self) {
        match serde_json::to_string_pretty(&self.blacklist) {
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
}

pub fn is_blacklisted(ip: &str) -> bool {
    let sm = SECURITY_MANAGER.lock().unwrap();
    sm.blacklist.contains(&ip.to_string())
}
pub fn report_failure(ip: &str) {
    let mut sm = SECURITY_MANAGER.lock().unwrap();
    if sm.blacklist.contains(&ip.to_string()) {
        return;
    }

    let ip_str = ip.to_string();
    let count = sm.failed_attempts.entry(ip_str.clone()).or_insert(0);
    *count += 1;

    warn!("Failed attempt from {}. Total attempts: {}/{}", ip_str, *count, MAX_FAILED_ATTEMPTS);

    if *count >= MAX_FAILED_ATTEMPTS {
        warn!("IP {} reached max failed attempts. Permanent blacklist applied.", ip_str);
        if !sm.blacklist.contains(&ip_str) {
            sm.blacklist.push(ip_str);
            sm.save_blacklist();
        }
    }
}

pub fn report_success(ip: &str) {
    let mut sm = SECURITY_MANAGER.lock().unwrap();
    sm.failed_attempts.remove(ip);
}

pub fn get_blacklist() -> Vec<String> {
    let sm = SECURITY_MANAGER.lock().unwrap();
    sm.blacklist.clone()
}

pub fn add_to_blacklist(ip: String) -> bool {
    let mut sm = SECURITY_MANAGER.lock().unwrap();
    if !sm.blacklist.contains(&ip) {
        sm.blacklist.push(ip);
        sm.save_blacklist();
        true
    } else {
        false
    }
}

pub fn remove_from_blacklist(ip: &str) -> bool {
    let mut sm = SECURITY_MANAGER.lock().unwrap();
    if let Some(pos) = sm.blacklist.iter().position(|x| x == ip) {
        sm.blacklist.remove(pos);
        sm.save_blacklist();
        true
    } else {
        false
    }
}
