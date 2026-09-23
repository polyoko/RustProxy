use rust_proxy::{tunnel, cache};
use log::{info, error, warn};

use anyhow::Result;
use clap::{Parser, Subcommand};
use inquire::{Select, Text, CustomType};
use colored::*;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Server {
        #[arg(short, long, default_value_t = 8080)]
        control: u16,

        #[arg(short, long, default_value_t = 8081)]
        api_port: u16,

        #[arg(short, long)]
        password: Option<String>,

        #[arg(long)]
        admin_password: String,
    },
    Agent {
        #[arg(short, long)]
        connect: String,

        #[arg(short, long)]
        id: String,

        #[arg(short, long)]
        password: Option<String>,
    }
}

fn print_banner() {
    let banner = r#"
  ____            _   ____                                
 |  _ \ _   _ ___| |_|  _ \ _ __ _____  ___   _ 
 | |_) | | | / __| __| |_) | '__/ _ \ \/ / | | |
 |  _ <| |_| \__ \ |_|  __/| | | (_) >  <| |_| |
 |_| \_\\__,_|___/\__|_|   |_|  \___/_/\_\\__, |
                                          |___/ 
    "#;
    println!("{}", banner.bright_blue().bold());
    println!("{}", " --- High Performance Reverse SOCKS5 Tunnel --- ".bright_black().italic());
    println!();
}

async fn run_interactive() -> Result<()> {
    print_banner();

    let options = vec!["Server (Public VPS)", "Agent (Home/Mobile/CGNAT)"];
    let choice = Select::new("Select Mode:", options).prompt()?;

    if choice == "Server (Public VPS)" {
        let control_port = CustomType::<u16>::new("Control Port:")
            .with_default(8080)
            .prompt()?;
        
        let agent_pw = Text::new("Agent Password (Optional, Enter for none):").prompt()?;
        let agent_pw = if agent_pw.is_empty() { None } else { Some(agent_pw) };
        let admin_pw = Text::new("Admin Password:").prompt()?;
        if admin_pw.is_empty() {
            anyhow::bail!("Admin password is required");
        }

        let registry = std::sync::Arc::new(dashmap::DashMap::new());
        let bind_registry = std::sync::Arc::new(dashmap::DashMap::new());
        run_server_with_cli(control_port, 8081, agent_pw, admin_pw, registry, bind_registry).await
    } else {
        let agent_id = Text::new("Agent ID (e.g., Phone-1):").prompt()?;
        let server_ip = Text::new("Server IP/Host:").prompt()?;
        let control_port = CustomType::<u16>::new("Server Control Port:")
            .with_default(8080)
            .prompt()?;
        
        let server_pw = Text::new("Server Password (if required):").prompt()?;
        let s_pw = if server_pw.is_empty() { None } else { Some(server_pw) };
        
        let connect_addr = format!("{}:{}", server_ip, control_port);
        tunnel::run_agent(connect_addr, agent_id, s_pw, None).await
    }
}

async fn run_server_with_cli(
    control_port: u16,
    api_port: u16,
    agent_password: Option<String>,
    admin_password: String,
    registry: tunnel::AgentRegistry,
    bind_registry: tunnel::BindRegistry,
) -> Result<()> {
    let cache_mgr = Arc::new(cache::CacheManager::new("server_cache.json"));
    let initial_cache = cache_mgr.load().unwrap_or_default();
    
    let cumulative_usage = Arc::new(dashmap::DashMap::new());

    for b in initial_cache.binds {
        let (Some(user), Some(pass)) = (b.user.clone(), b.pass.clone()) else {
            error!(
                "Skipping cached SOCKS bind on port {}: missing user or password; refusing to restore an open proxy",
                b.port
            );
            continue;
        };
        let port = b.port;
        if !tunnel::is_socks_port(port) {
            warn!(
                "Skipping cached SOCKS bind on port {}: allowed range is {}-{}",
                port,
                tunnel::SOCKS_PORT_MIN,
                tunnel::SOCKS_PORT_MAX
            );
            continue;
        }
        let socks_listener = match tunnel::bind_socks_listener(port).await {
            Ok(listener) => listener,
            Err(e) => {
                warn!("Skipping cached SOCKS bind on port {}: {}", port, e);
                continue;
            }
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let id = b.agent_id.clone();
        
        let bind_usage = Arc::new(std::sync::atomic::AtomicU64::new(b.usage));
        bind_registry.insert(port, tunnel::BindEntry {
            agent_id: id.clone(),
            port,
            usage: bind_usage,
            user: Some(user.clone()),
            pass: Some(pass.clone()),
            shutdown_tx: Some(shutdown_tx),
        });

        let reg = Arc::clone(&registry);
        let b_reg = Arc::clone(&bind_registry);
        tokio::spawn(async move {
            if let Err(e) = tunnel::run_socks_listener(socks_listener, id, reg, b_reg, Some(user), Some(pass), shutdown_rx).await {
                log::error!("Restored SOCKS Listener failed on {}: {}", port, e);
            }
        });
    }

    let registry_for_server = Arc::clone(&registry);
    let bind_registry_for_server = Arc::clone(&bind_registry);
    let usage_for_server = Arc::clone(&cumulative_usage);
    tokio::spawn(async move {
        if let Err(e) = tunnel::run_server(control_port, api_port, agent_password, admin_password, registry_for_server, bind_registry_for_server, usage_for_server).await {
            log::error!("Background Server Failed: {}", e);
        }
    });

    let bind_registry_for_save = Arc::clone(&bind_registry);
    let cache_mgr_for_save = Arc::clone(&cache_mgr);

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            
            let mut cache_data = cache::ServerCache::default();
            for entry in bind_registry_for_save.iter() {
                let b = entry.value();
                cache_data.binds.push(cache::BindConfig {
                    port: entry.key().clone(),
                    agent_id: b.agent_id.clone(),
                    user: b.user.clone(),
                    pass: b.pass.clone(), 
                    usage: b.usage.load(Ordering::Relaxed),
                });
            }

            if let Err(e) = cache_mgr_for_save.save(&cache_data) {
                log::error!("Failed to save cache: {}", e);
            }
        }
    });

    info!("Web GUI Dashboard active on http://127.0.0.1:{}", api_port);
    info!("Server running in background. Press Ctrl+C to exit.");
    if let Err(e) = tokio::signal::ctrl_c().await {
        error!("Failed to listen for ctrl+c: {}", e);
    }
    info!("Shutting down...");
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    let cli = Cli::parse();
    
    match cli.command {
        Some(Commands::Server { control, api_port, password, admin_password }) => {
            print_banner();
            info!("Running in SERVER mode");
            let registry = std::sync::Arc::new(dashmap::DashMap::new());
            let bind_registry = std::sync::Arc::new(dashmap::DashMap::new());
            run_server_with_cli(control, api_port, password, admin_password, registry, bind_registry).await?;
        }
        Some(Commands::Agent { connect, id, password }) => {
            print_banner();
            info!("Running in AGENT mode ('{}')", id);
            loop {
                let res = tunnel::run_agent(connect.clone(), id.clone(), password.clone(), None).await;
                if let Err(e) = res {
                    error!("Agent error: {}. Retrying in 5 seconds...", e);
                } else {
                    warn!("Agent connection closed. Retrying in 5 seconds...");
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
        None => {
            run_interactive().await?;
        }
    }
    Ok(())
}
