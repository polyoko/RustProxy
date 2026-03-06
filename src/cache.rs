use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use anyhow::Result;

#[derive(Serialize, Deserialize, Default)]
pub struct ServerCache {
    pub binds: Vec<BindConfig>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BindConfig {
    pub port: u16,
    pub agent_id: String,
    pub user: Option<String>,
    pub pass: Option<String>,
    #[serde(default)]
    pub usage: u64,
}

#[derive(Serialize, Deserialize, Default)]
pub struct AgentCache {
    pub agent_id: String,
    pub cumulative_usage: u64,
}

pub struct CacheManager {
    path: String,
}

impl CacheManager {
    pub fn new(path: &str) -> Self {
        Self { path: path.to_string() }
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
