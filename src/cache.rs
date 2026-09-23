use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Serialize, Deserialize, Default)]
pub struct ServerCache {
    #[serde(default)]
    pub binds: Vec<BindConfig>,
    #[serde(default)]
    pub agent_usage: Vec<AgentCache>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BindConfig {
    pub port: u16,
    pub agent_id: String,
    pub user: Option<String>,
    pub pass: Option<String>,
    #[serde(default)]
    pub usage: u64,
    #[serde(default = "default_max_conns")]
    pub max_conns: usize,
}

fn default_max_conns() -> usize {
    crate::tunnel::DEFAULT_MAX_CONNS
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AgentCache {
    pub agent_id: String,
    pub cumulative_usage: u64,
}

pub struct CacheManager {
    path: String,
}

impl CacheManager {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    pub fn load(&self) -> Result<ServerCache> {
        if !Path::new(&self.path).exists() {
            return Ok(ServerCache::default());
        }
        let mut file = File::open(&self.path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let cache = serde_json::from_str(&content)?;
        Ok(cache)
    }

    pub fn save(&self, cache: &ServerCache) -> Result<()> {
        let content = serde_json::to_string_pretty(cache)?;
        let mut file = File::create(&self.path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    pub fn load_agent(&self) -> Result<AgentCache> {
        if !Path::new(&self.path).exists() {
            return Ok(AgentCache::default());
        }
        let mut file = File::open(&self.path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let cache = serde_json::from_str(&content)?;
        Ok(cache)
    }

    pub fn save_agent(&self, cache: &AgentCache) -> Result<()> {
        let content = serde_json::to_string_pretty(cache)?;
        let mut file = File::create(&self.path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ServerCache;

    #[test]
    fn legacy_server_cache_defaults_agent_usage() {
        let cache: ServerCache = serde_json::from_str(r#"{"binds":[]}"#).unwrap();
        assert!(cache.agent_usage.is_empty());
    }

    #[test]
    fn legacy_bind_defaults_connection_limit() {
        let cache: ServerCache = serde_json::from_str(
            r#"{"binds":[{"port":51300,"agent_id":"phone","user":"u","pass":"p"}]}"#,
        )
        .unwrap();
        assert_eq!(cache.binds[0].max_conns, crate::tunnel::DEFAULT_MAX_CONNS);
    }

    #[test]
    fn bind_connection_limit_round_trips() {
        let cache: ServerCache = serde_json::from_str(
            r#"{"binds":[{"port":51300,"agent_id":"phone","user":"u","pass":"p","max_conns":42}]}"#,
        )
        .unwrap();
        let restored: ServerCache =
            serde_json::from_str(&serde_json::to_string(&cache).unwrap()).unwrap();
        assert_eq!(restored.binds[0].max_conns, 42);
    }
}
